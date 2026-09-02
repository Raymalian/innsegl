// SPDX-License-Identifier: Apache-2.0

package load

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/segment"
)

// OPS-002 (doc 07, layer F): "Sustained append load across ≥3 segment
// rollovers → No gaps, all segments seal and anchor, dashboard heartbeat
// accurate throughout." Proves IP §6.4, Phase 5.
//
// And, per doc 05 §4, it is the measurement that supersedes the estimate:
//
//	"Sizing posture (initial, revisit with data) ... The first real load test
//	 (OPS-002) replaces these estimates with measurements; per the verification
//	 methodology, measured numbers supersede this section and get recorded in
//	 an ADR appendix."
//
// The numbers, with the hardware and the images they were taken on, are in
// ADR-0039. This file is what produces them, and it is written so that a
// number it prints cannot be read without the conditions it was taken under:
// see reportOf and runtimeConditions.
//
// # A number that only measures the harness is worse than no number
//
// The easiest wrong result here is a throughput figure that describes the Go
// program doing the appending rather than the ledger being appended to. Two
// measurements are taken to tell those apart, and both are printed beside the
// throughput:
//
//   - a single-writer calibration, which is the serialized cost of one append
//     with nothing else running. doc 02 §2 assigns chain_position "under
//     serialized append" and the store takes an advisory lock to do it, so
//     1/calibration is the ceiling the whole system has, whatever the
//     concurrency;
//   - the fraction of wall time the concurrent workers spent *inside*
//     store.Append. If the workers are inside the ledger essentially all the
//     time, the generator is not what is being measured.
//
// The run asserts the second, because a run whose generator was the
// bottleneck must not be allowed to report a ledger throughput.

// loadConfig is the shape of one run. The defaults are the CI sizing.
//
// # What runs in CI, and what is opt-in
//
// The whole case runs in CI, at the default sizing: four rollovers of 200
// events each, driven by eight concurrent writers against a real Postgres, a
// real MinIO with object lock on, and a real Rekor over a real Trillian.
// Nothing here skips and nothing here is behind a flag — a load test that only
// runs when somebody remembers to run it is a load test that has stopped
// running, and #101 is this repository's evidence for how quietly that
// happens.
//
// The soak is the same case with bigger numbers. It is opt-in only in the
// sense that a longer run costs more wall clock:
//
//	INNSEGL_LOAD_SEGMENT_EVENTS=5000 INNSEGL_LOAD_SEGMENTS=10 \
//	INNSEGL_LOAD_WORKERS=16 INNSEGL_LOAD_REPORT=/tmp/ops-002.json \
//	  go test ./test/load/ -run OPS002 -count=1 -v -timeout 90m
//
// The CI half is not the soak with its assertions turned down. It asserts
// exactly what the soak asserts — no gaps, every segment sealed and anchored,
// the heartbeat accurate on every reading. What more events buy is a tighter
// throughput measurement and a longer window for a gap to appear in.
type loadConfig struct {
	Workers       int
	SegmentEvents int64
	Segments      int
	ReportPath    string
}

const (
	defaultWorkers       = 8
	defaultSegmentEvents = 200
	// Four, where doc 07 asks for at least three. The third rollover is the
	// first whose predecessor was itself sealed under load; the fourth is the
	// first that is not also the last.
	defaultSegments = 4

	// minimumSegments is OPS-002's floor and is not configurable downwards.
	minimumSegments = 3

	// calibrationAppends is the single-writer sample. Its first fifth is
	// discarded as warm-up: the first append on a fresh pool pays for the
	// connection, and a ceiling computed from that would be a ceiling on
	// connecting.
	calibrationAppends = 200
	calibrationWarmup  = calibrationAppends / 5

	// floorSamples is how many trivial statements are timed to establish what
	// a round trip costs before any ledger work happens.
	floorSamples = 200

	// generatorBudget is the largest share of worker wall time that may be
	// spent outside store.Append for the throughput figure to be a
	// measurement of the ledger. Above it the run refuses to call the number
	// a ledger throughput.
	generatorBudget = 0.10

	// heartbeatTick is the sampling interval of the concurrent heartbeat
	// reader. Every sample is retained and checked; at this rate a soak of an
	// hour retains a few hundred thousand of them, which is affordable, and
	// dropping samples to save memory would mean the check no longer covers
	// the whole run.
	heartbeatTick = 5 * time.Millisecond
)

func envInt(t *testing.T, name string, fallback int64) int64 {
	t.Helper()
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		t.Fatalf("%s=%q is not an integer: %v", name, raw, err)
	}
	return v
}

func loadConfigFromEnv(t *testing.T) loadConfig {
	t.Helper()
	cfg := loadConfig{
		Workers:       int(envInt(t, "INNSEGL_LOAD_WORKERS", defaultWorkers)),
		SegmentEvents: envInt(t, "INNSEGL_LOAD_SEGMENT_EVENTS", defaultSegmentEvents),
		Segments:      int(envInt(t, "INNSEGL_LOAD_SEGMENTS", defaultSegments)),
		ReportPath:    os.Getenv("INNSEGL_LOAD_REPORT"),
	}
	switch {
	case cfg.Workers < 1:
		t.Fatalf("INNSEGL_LOAD_WORKERS=%d: a run with no writers appends nothing", cfg.Workers)
	case cfg.SegmentEvents < 1:
		t.Fatalf("INNSEGL_LOAD_SEGMENT_EVENTS=%d is not a segment", cfg.SegmentEvents)
	case cfg.Segments < minimumSegments:
		t.Fatalf("INNSEGL_LOAD_SEGMENTS=%d: doc 07 OPS-002 is \"sustained append load "+
			"across ≥%d segment rollovers\". A run with fewer is not OPS-002, and "+
			"turning the requirement down until a run passes is the one thing this "+
			"case must never permit.", cfg.Segments, minimumSegments)
	}
	return cfg
}

// sealedSegment is one rollover: what was sealed, what it cost, and the anchor
// that came back.
type sealedSegment struct {
	ID          string
	MerkleRoot  string
	First       int64
	Last        int64
	Events      int
	ObjectBytes int
	SealFor     time.Duration
	AnchorFor   time.Duration
	Anchor      segment.Anchor

	// SealedRecord is the segment_sealed event as the ledger holds it;
	// AnchoredRecord is the superseding one that carries the anchor (doc 02
	// §3: the first is never rewritten, I4).
	SealedRecord   event.Fields
	AnchoredRecord event.Fields
}

// runResult is everything one OPS-002 run observed.
type runResult struct {
	WorkerAppends int64
	Wall          time.Duration
	WorkerBusy    time.Duration
	Latencies     []time.Duration

	Segments     []sealedSegment
	Samples      []heartbeatSample
	AnchoredWall []anchoredWall

	// PendingObserved is the deterministic under-report guard: one whole
	// anchor was watched at microsecond resolution, and this says whether the
	// heartbeat ever showed the segment pending while it was in flight.
	PendingObserved bool
	// PendingWatchFor is how long that anchor took, so the margin behind the
	// guard is visible rather than assumed.
	PendingWatchFor time.Duration
	PendingPolls    int
}

// harness is the live wiring one run drives.
type harness struct {
	store    *ledger.Store
	dsn      string
	worm     *segment.WORM
	sealer   *segment.Sealer
	anchorer *segment.Anchorer
	rekor    *segment.RekorClient
	bound    time.Duration
}

// anchorBound is the lag past which FD §3.1 turns the header amber. It is set
// short here relative to the shipped 15-minute default so that "the heartbeat
// stayed inside its bound" is a claim about this run rather than a claim that
// is true of any run shorter than a quarter of an hour.
const anchorBound = 30 * time.Second

// newLedger opens a migrated chain of its own. ADR-0005 scopes a chain to a
// database, so a database per chain is what the design already implies.
func newLedger(t *testing.T, s *stack) (*ledger.Store, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dsn := freshDatabase(t, s)
	store, err := ledger.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(store.Close)
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("ledger.Migrate: %v", err)
	}
	return store, dsn
}

func newHarness(t *testing.T, s *stack) *harness {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	store, dsn := newLedger(t, s)

	bucket := freshLockedBucket(t, s)
	worm, err := segment.NewWORM(ctx, segment.WORMConfig{
		Endpoint:  s.minioAddr,
		AccessKey: minioRootUser,
		SecretKey: minioRootPassword,
		Bucket:    bucket,
		Mode:      segment.RetentionCompliance,
		// Long enough to outlast the run. Compliance mode refuses a deletion
		// the same way for an hour as for a decade; what is measured here is
		// the cost of writing under a lock, not the length of one.
		Retention: time.Hour,
	})
	if err != nil {
		t.Fatalf("segment.NewWORM against %s/%s: %v", s.minioAddr, bucket, err)
	}

	signer, err := segment.GenerateAnchorSigner()
	if err != nil {
		t.Fatalf("GenerateAnchorSigner: %v", err)
	}
	rekor := &segment.RekorClient{BaseURL: s.rekorBaseURL, Signer: signer}

	return &harness{
		store:  store,
		dsn:    dsn,
		worm:   worm,
		sealer: &segment.Sealer{Store: worm},
		anchorer: &segment.Anchorer{
			Log:    rekor,
			Policy: segment.RetryPolicy{Attempts: 4, Base: 250 * time.Millisecond, Max: 4 * time.Second},
			Bound:  anchorBound,
		},
		rekor: rekor,
		bound: anchorBound,
	}
}

// toolCallBody is one unit of load: an agent tool invocation, the event type
// doc 02 §3 records with "body only as payload_digest".
//
// Every worker appends the same *shape* of event with a distinct
// idempotency_key, because the shape is what the bytes-per-event measurement
// is a measurement of. A run whose event sizes varied would produce a mean
// describing no event the system will ever hold, and ADR-0039 says so where it
// quotes the number.
func toolCallBody(worker int, n int64) event.Fields {
	runID := fmt.Sprintf("run-load-%02d", worker)
	return event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeToolCall,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       "spiffe://innsegl.dev/agent/load-test/ops-002/" + runID,
		event.FieldSource:         event.SourceMCP,
		event.FieldIdempotencyKey: fmt.Sprintf("ops002-%02d-%012d", worker, n),
		event.FieldToolName:       "record_event",
		event.FieldPayloadDigest: "sha256:" +
			"0000000000000000000000000000000000000000000000000000000000000000",
	}
}

func newEventID(t *testing.T) string {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7: %v", err)
	}
	return id.String()
}

// driveSustainedLoad runs the workload: writers appending continuously while a
// sealer rolls the chain over behind them, and a sampler reading the anchoring
// heartbeat throughout.
//
// The writers are not paused for a rollover, and that is the point of the
// case. IP §6.4 requires that "appends to the next segment continue" while a
// segment is being sealed and anchored, so a driver that quiesced the load to
// seal cleanly would be testing a system nobody runs.
func driveSustainedLoad(ctx context.Context, t *testing.T, h *harness, cfg loadConfig) runResult {
	t.Helper()

	var (
		appends   atomic.Int64
		busyNanos atomic.Int64
		submitted atomic.Int64
		completed atomic.Int64
		broken    atomic.Bool
		alive     atomic.Int64
	)
	stopWorkers := make(chan struct{})
	stopSampler := make(chan struct{})

	latencies := make([][]time.Duration, cfg.Workers)
	var writers sync.WaitGroup
	start := time.Now()

	for w := range cfg.Workers {
		writers.Add(1)
		alive.Add(1)
		go func() {
			defer writers.Done()
			defer alive.Add(-1)
			var n int64
			local := make([]time.Duration, 0, 1024)
			for {
				select {
				case <-stopWorkers:
					latencies[w] = local
					return
				default:
				}
				n++
				at := time.Now()
				_, err := h.store.Append(ctx, toolCallBody(w, n))
				took := time.Since(at)
				if err != nil {
					// An append that fails under load is not a slow append: it
					// is the ledger declining to record an action (I3), and
					// there is nothing left worth measuring after it.
					broken.Store(true)
					t.Errorf("writer %d: append %d failed after %s: %v", w, n, took, err)
					latencies[w] = local
					return
				}
				local = append(local, took)
				busyNanos.Add(int64(took))
				appends.Add(1)
			}
		}()
	}

	var sampler sync.WaitGroup
	var samples []heartbeatSample
	sampler.Add(1)
	go func() {
		defer sampler.Done()
		ticker := time.NewTicker(heartbeatTick)
		defer ticker.Stop()
		for {
			select {
			case <-stopSampler:
				// One last synchronous reading, so the final segment's anchor
				// is in the trace rather than lost to the tick that never came.
				samples = append(samples, readHeartbeat(h, &submitted, &completed))
				return
			case <-ticker.C:
			}
			samples = append(samples, readHeartbeat(h, &submitted, &completed))
		}
	}()

	segments, walls, watch := driveRollovers(ctx, t, h, cfg, driveState{
		submitted: &submitted, completed: &completed, broken: &broken, alive: &alive,
	})

	close(stopWorkers)
	writers.Wait()
	wall := time.Since(start)
	close(stopSampler)
	sampler.Wait()

	var merged []time.Duration
	for _, l := range latencies {
		merged = append(merged, l...)
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i] < merged[j] })

	return runResult{
		WorkerAppends:   appends.Load(),
		Wall:            wall,
		WorkerBusy:      time.Duration(busyNanos.Load()),
		Latencies:       merged,
		Segments:        segments,
		Samples:         samples,
		AnchoredWall:    walls,
		PendingObserved: watch.observed,
		PendingWatchFor: watch.took,
		PendingPolls:    watch.polls,
	}
}

// readHeartbeat takes one bracketed reading. The counters are read on both
// sides of Lag() so that the reading can be checked against a window the
// driver can vouch for rather than against a truth nothing can observe.
func readHeartbeat(h *harness, submitted, completed *atomic.Int64) heartbeatSample {
	s := heartbeatSample{
		At:              time.Now(),
		SubmittedBefore: int(submitted.Load()),
		CompletedBefore: int(completed.Load()),
	}
	s.Snap = h.anchorer.Lag()
	s.AtEnd = time.Now()
	s.SubmittedAfter = int(submitted.Load())
	s.CompletedAfter = int(completed.Load())
	return s
}

// driveState is the bookkeeping the rollover driver shares with the sampler.
type driveState struct {
	submitted *atomic.Int64
	completed *atomic.Int64
	broken    *atomic.Bool
	alive     *atomic.Int64
}

// pendingWatch is what watching one anchor at microsecond resolution saw.
type pendingWatch struct {
	observed bool
	took     time.Duration
	polls    int
}

// driveRollovers seals and anchors each segment as the chain crosses its
// boundary, while the writers keep appending into the next one.
func driveRollovers(
	ctx context.Context, t *testing.T, h *harness, cfg loadConfig, st driveState,
) ([]sealedSegment, []anchoredWall, pendingWatch) {
	t.Helper()

	segments := make([]sealedSegment, 0, cfg.Segments)
	walls := make([]anchoredWall, 0, cfg.Segments)
	var watch pendingWatch

	from := int64(1)
	for i := range cfg.Segments {
		to := from + cfg.SegmentEvents - 1
		waitForPosition(ctx, t, h, st, to)

		records, err := h.store.Events(ctx, from, to)
		if err != nil {
			t.Fatalf("segment %d: Events(%d..%d): %v", i, from, to, err)
		}
		if int64(len(records)) != to-from+1 {
			t.Fatalf("segment %d: the ledger returned %d records for positions %d..%d; "+
				"a short read here is a gap in the chain, not a slow reader",
				i, len(records), from, to)
		}

		sealAt := time.Now()
		sealed, err := h.sealer.Seal(segment.Request{Records: records})
		sealFor := time.Since(sealAt)
		if err != nil {
			t.Fatalf("segment %d: Seal(%d..%d): %v", i, from, to, err)
		}

		sealedRecord := appendSealed(ctx, t, h, i, sealed)

		// The first rollover's anchor is watched at microsecond resolution.
		// The 5 ms sampler establishes the trace; this establishes, without
		// depending on a tick landing in the right place, that the heartbeat
		// really does report a segment as pending while it is in flight.
		st.submitted.Add(1)
		anchorAt := time.Now()
		var anchor segment.Anchor
		if i == 0 {
			anchor, watch = anchorAndWatch(ctx, t, h, sealedRecord)
		} else {
			anchor, err = h.anchorer.Anchor(ctx, sealedRecord)
			if err != nil {
				t.Fatalf("segment %d (%s): Anchor: %v", i, sealed.SegmentID, err)
			}
		}
		anchorFor := time.Since(anchorAt)
		st.completed.Add(1)
		anchoredAt := time.Now()

		anchoredRecord := appendAnchored(ctx, t, h, i, sealedRecord, anchor)

		segments = append(segments, sealedSegment{
			ID:             sealed.SegmentID,
			MerkleRoot:     sealed.MerkleRoot,
			First:          sealed.FirstPosition,
			Last:           sealed.LastPosition,
			Events:         len(records),
			ObjectBytes:    len(sealed.Object),
			SealFor:        sealFor,
			AnchorFor:      anchorFor,
			Anchor:         anchor,
			SealedRecord:   sealedRecord,
			AnchoredRecord: anchoredRecord,
		})
		walls = append(walls, anchoredWall{
			SegmentID: sealed.SegmentID, At: anchoredAt, Last: sealed.LastPosition,
		})
		from = to + 1
	}
	return segments, walls, watch
}

// appendSealed writes the segment_sealed event the seal produced.
//
// The body comes from segment.Sealed.Event rather than being assembled here,
// because that is the production builder and a second assembly in a test is a
// second thing that can disagree with doc 02 §3. The two members it fills in
// that the ledger owns are then removed: event_id is assigned by the store,
// and ts is the server clock at append ("Client-supplied values are ignored",
// doc 02 §2).
func appendSealed(ctx context.Context, t *testing.T, h *harness, i int, sealed *segment.Sealed) event.Fields {
	t.Helper()
	body, err := sealed.Event(segment.EventMeta{
		EventID: newEventID(t),
		TS:      event.NewTimestamp(time.Now()),
	})
	if err != nil {
		t.Fatalf("segment %d: building the segment_sealed body: %v", i, err)
	}
	delete(body, event.FieldEventID)
	delete(body, event.FieldTS)

	record, err := h.store.Append(ctx, body)
	if err != nil {
		t.Fatalf("segment %d: appending segment_sealed: %v", i, err)
	}
	return record
}

// appendAnchored writes the superseding segment_sealed event that carries the
// anchor. doc 02 §3 and I4: the first event is not rewritten, a second one
// supersedes it.
func appendAnchored(
	ctx context.Context, t *testing.T, h *harness, i int,
	sealedRecord event.Fields, anchor segment.Anchor,
) event.Fields {
	t.Helper()
	body, err := segment.AnchorEvent(segment.EventMeta{
		EventID: newEventID(t),
		TS:      event.NewTimestamp(time.Now()),
	}, sealedRecord, anchor)
	if err != nil {
		t.Fatalf("segment %d: building the anchored segment_sealed body: %v", i, err)
	}
	delete(body, event.FieldEventID)
	delete(body, event.FieldTS)
	// ledger.Correct owns this member when the chain is walked in memory; the
	// Postgres store has no Correct, so the link is set here from the record
	// being superseded and from nowhere else.
	body[event.FieldSupersedes] = sealedRecord[event.FieldEventID]

	record, err := h.store.Append(ctx, body)
	if err != nil {
		t.Fatalf("segment %d: appending the superseding anchored event: %v", i, err)
	}
	return record
}

// anchorAndWatch anchors one segment while polling the heartbeat as fast as it
// can be read. Proposed doc 07 ID: OPS-002d, layer F.
//
// This is the deterministic half of "the heartbeat stays accurate": a
// heartbeat pinned at zero pending would satisfy every per-sample rule, and
// only watching an anchor that is genuinely in flight can convict it. The poll
// interval is two orders of magnitude below any round trip to a containerised
// Rekor, and the run reports both the anchor's duration and the number of
// polls so the margin is visible rather than asserted.
func anchorAndWatch(
	ctx context.Context, t *testing.T, h *harness, sealedRecord event.Fields,
) (segment.Anchor, pendingWatch) {
	t.Helper()

	type outcome struct {
		anchor segment.Anchor
		err    error
	}
	done := make(chan outcome, 1)
	at := time.Now()
	go func() {
		anchor, err := h.anchorer.Anchor(ctx, sealedRecord)
		done <- outcome{anchor, err}
	}()

	watch := pendingWatch{}
	for {
		select {
		case got := <-done:
			watch.took = time.Since(at)
			if got.err != nil {
				t.Fatalf("segment 0: Anchor: %v", got.err)
			}
			return got.anchor, watch
		default:
		}
		watch.polls++
		if h.anchorer.Lag().PendingSegments > 0 {
			watch.observed = true
		}
		time.Sleep(200 * time.Microsecond)
	}
}

// waitForPosition blocks until the chain has reached a position, or until it
// is clear it never will.
func waitForPosition(ctx context.Context, t *testing.T, h *harness, st driveState, want int64) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Minute)
	for {
		head, err := h.store.Head(ctx)
		if err != nil {
			t.Fatalf("Head while waiting for position %d: %v", want, err)
		}
		if head.Position >= want {
			return
		}
		if st.broken.Load() || st.alive.Load() == 0 {
			t.Fatalf("the writers stopped at position %d with %d still wanted; "+
				"there is no sustained load left to roll a segment over",
				head.Position, want)
		}
		if time.Now().After(deadline) {
			t.Fatalf("the chain reached position %d and stalled short of %d",
				head.Position, want)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestOPS002SustainedAppendLoadAcrossSegmentRollovers(t *testing.T) {
	s := requireStack(t)
	cfg := loadConfigFromEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()

	t.Logf("conditions: %s", runtimeConditions(s))
	t.Logf("run: %d writers, %d rollovers of %d events",
		cfg.Workers, cfg.Segments, cfg.SegmentEvents)

	// The ceiling first, on a chain of its own so that the sustained run's
	// positions and its stored bytes are the load and nothing else.
	calibration := calibrate(ctx, t, s)
	floor := roundTripFloor(ctx, t, calibration.dsn)

	h := newHarness(t, s)
	run := driveSustainedLoad(ctx, t, h, cfg)
	storage := measureStorage(ctx, t, h.dsn)

	t.Run("no gaps in chain positions under sustained load", func(t *testing.T) {
		head, err := h.store.Head(ctx)
		if err != nil {
			t.Fatalf("Head: %v", err)
		}
		if head.Position == 0 {
			t.Fatal("the chain is empty after a sustained-load run; there is nothing " +
				"to check for gaps, which is not the same as having none")
		}
		records, err := h.store.Events(ctx, 1, head.Position)
		if err != nil {
			t.Fatalf("Events(1..%d): %v", head.Position, err)
		}
		scan, err := scanPositions(records)
		if err != nil {
			t.Fatalf("scanPositions: %v", err)
		}
		if !scan.OK() {
			t.Fatalf("THE CHAIN HAS GAPS. This is an I1/I2 violation and not a flake:\n"+
				"  positions %d..%d over %d records\n  gaps: %v\n  duplicates: %v\n"+
				"  out of order: %v",
				scan.First, scan.Last, scan.Count, scan.Gaps, scan.Duplicates, scan.Unordered)
		}
		// The positions being contiguous is one property; the hashes linking
		// is another, and a run that produced a contiguous chain of records
		// that do not hash together has still lost the ledger.
		if _, err := ledger.Verify(records); err != nil {
			t.Fatalf("the chain does not verify end to end after sustained load: %v", err)
		}
		t.Logf("chain: %d events, positions %d..%d, no gaps, verifies end to end",
			scan.Count, scan.First, scan.Last)
	})

	t.Run("at least three segments rolled over", func(t *testing.T) {
		if len(run.Segments) < minimumSegments {
			t.Fatalf("the run produced %d segment rollovers; OPS-002 is \"sustained "+
				"append load across ≥%d segment rollovers\"",
				len(run.Segments), minimumSegments)
		}
		t.Logf("rollovers: %d", len(run.Segments))
	})

	t.Run("all segments seal and anchor", func(t *testing.T) {
		if len(run.Segments) == 0 {
			t.Fatal("no segment was sealed, so \"all segments sealed\" is vacuously " +
				"true and proves nothing")
		}
		var covered int64
		for i, seg := range run.Segments {
			assertSealedAndAnchored(ctx, t, h, i, seg)
			covered += seg.Last - seg.First + 1
			t.Logf("segment %d: %s positions %d..%d, %d events, %d object bytes, "+
				"sealed in %s, anchored in %s at log index %d",
				i, seg.ID, seg.First, seg.Last, seg.Events, seg.ObjectBytes,
				seg.SealFor.Round(time.Millisecond), seg.AnchorFor.Round(time.Millisecond),
				seg.Anchor.LogIndex)
		}
		if want := int64(cfg.Segments) * cfg.SegmentEvents; covered != want {
			t.Fatalf("the sealed segments cover %d positions, the run rolled over %d",
				covered, want)
		}
	})

	t.Run("the dashboard heartbeat stays accurate throughout", func(t *testing.T) {
		if len(run.Samples) == 0 {
			t.Fatal("the heartbeat was never read; an unread heartbeat cannot be " +
				"inaccurate, and cannot be accurate either")
		}
		if bad := checkHeartbeat(run.Samples, h.bound, run.AnchoredWall); len(bad) != 0 {
			t.Fatalf("the anchoring heartbeat was not accurate over %d readings:\n  %v",
				len(run.Samples), bad)
		}

		// Every segment the run anchored has to have been named by the
		// heartbeat at some point. A heartbeat frozen on the first segment
		// would satisfy every per-reading rule while reporting public
		// tamper-evidence as current after it had stopped advancing.
		named := segmentsNamed(run.Samples)
		for _, seg := range run.Segments {
			if _, ok := named[seg.ID]; !ok {
				t.Errorf("the heartbeat never named segment %s (%d..%d), which it "+
					"anchored; it named %d segment(s) over %d readings",
					seg.ID, seg.First, seg.Last, len(named), len(run.Samples))
			}
		}

		if !run.PendingObserved {
			t.Fatalf("the heartbeat never showed a segment pending while one was in "+
				"flight: %d polls over the %s the first anchor took. A heartbeat "+
				"pinned at zero pending satisfies every per-reading rule and reports "+
				"a lag that is never behind.",
				run.PendingPolls, run.PendingWatchFor)
		}

		// Finally, the reading the dashboard actually serves: FD §3.1's
		// heartbeat is read out of the chain (internal/api's anchorSQL takes
		// the newest segment_sealed), and it has to agree with the anchorer.
		assertChainHeartbeatAgrees(ctx, t, h, run)

		t.Logf("heartbeat: %d readings, all accurate; %d segment(s) named; "+
			"pending seen within %s over %d polls",
			len(run.Samples), len(named),
			run.PendingWatchFor.Round(time.Millisecond), run.PendingPolls)
	})

	t.Run("the measurement is of the ledger and not of the generator", func(t *testing.T) {
		if run.WorkerAppends == 0 {
			t.Fatal("no append completed; there is no throughput to report")
		}
		outside := generatorShare(run, cfg.Workers)
		if outside > generatorBudget {
			t.Fatalf("the writers spent %.1f%% of their wall time outside "+
				"store.Append (budget %.1f%%). The throughput this run measured is "+
				"a property of the generator, not of the ledger, and reporting it "+
				"as a ledger throughput in ADR-0039 would be a wrong number stated "+
				"confidently.", outside*100, generatorBudget*100)
		}
		t.Logf("writers were inside store.Append %.2f%% of their wall time",
			(1-outside)*100)
	})

	report := reportOf(s, cfg, run, calibration, floor, storage)
	t.Log("\n" + report.String())
	if cfg.ReportPath != "" {
		writeReport(t, cfg.ReportPath, report)
	}
}

// generatorShare is the fraction of writer wall time spent outside
// store.Append: building a body, scheduling, and the test's own bookkeeping.
func generatorShare(run runResult, workers int) float64 {
	total := float64(run.Wall) * float64(workers)
	if total <= 0 {
		return 1
	}
	outside := total - float64(run.WorkerBusy)
	if outside < 0 {
		return 0
	}
	return outside / total
}

// assertSealedAndAnchored re-reads one segment out of the object store and
// asks Rekor, independently, whether the anchor is really in the log.
func assertSealedAndAnchored(ctx context.Context, t *testing.T, h *harness, i int, seg sealedSegment) {
	t.Helper()

	stored, openErr := segment.Open(h.worm, seg.ID)
	if openErr != nil {
		t.Fatalf("segment %d (%s) is not readable back out of the object store: %v",
			i, seg.ID, openErr)
	}
	if stored.Object.MerkleRoot != seg.MerkleRoot {
		t.Fatalf("segment %d: the stored object's root is %s, the seal reported %s",
			i, stored.Object.MerkleRoot, seg.MerkleRoot)
	}
	// The object and the ledger's claim about it, checked against each other:
	// a segment that sealed is one whose stored bytes substantiate the event
	// that announced it, and anything less is drift (doc 02 §3).
	if err := stored.VerifyAgainst(seg.SealedRecord); err != nil {
		t.Fatalf("segment %d: the stored object does not substantiate the ledger's "+
			"segment_sealed event: %v", i, err)
	}
	if err := stored.VerifyAgainst(seg.AnchoredRecord); err != nil {
		t.Fatalf("segment %d: the stored object does not substantiate the superseding "+
			"anchored event: %v", i, err)
	}

	if seg.Anchor.EntryUUID == "" {
		t.Fatalf("segment %d (%s) sealed and was never anchored", i, seg.ID)
	}

	// Read back by a client with no signing key: a third party asking the log,
	// which is the only reason an anchor is worth anything (I5).
	reader := &segment.RekorClient{BaseURL: h.rekor.BaseURL}
	proof, proofErr := reader.InclusionProof(ctx, seg.Anchor.EntryUUID)
	if proofErr != nil {
		t.Fatalf("segment %d: no inclusion proof for entry %s: %v",
			i, seg.Anchor.EntryUUID, proofErr)
	}
	logKey, keyErr := reader.PublicKey(ctx)
	if keyErr != nil {
		t.Fatalf("fetch the log's public key: %v", keyErr)
	}
	if err := proof.Verify(logKey); err != nil {
		t.Fatalf("segment %d: the log's inclusion proof does not verify: %v", i, err)
	}
	root, rootErr := proof.MerkleRoot()
	if rootErr != nil {
		t.Fatalf("segment %d: the proof carries no root: %v", i, rootErr)
	}
	if root == "" {
		t.Fatalf("segment %d: the proof's root is empty", i)
	}
}

// assertChainHeartbeatAgrees checks the heartbeat the dashboard is actually
// served against the one the anchorer reports.
//
// internal/api reads FD §3.1's heartbeat out of the ledger — the newest
// segment_sealed event, and its anchor members. That is a second place the
// same fact is held, and OPS-002 is the run long enough for the two to drift
// apart if anything is going to make them.
func assertChainHeartbeatAgrees(ctx context.Context, t *testing.T, h *harness, run runResult) {
	t.Helper()
	if len(run.Segments) == 0 {
		return
	}
	last := run.Segments[len(run.Segments)-1]

	head, err := h.store.Head(ctx)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	records, err := h.store.Events(ctx, 1, head.Position)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	var newest event.Fields
	for _, record := range records {
		if record[event.FieldEventType] == event.EventTypeSegmentSealed {
			newest = record
		}
	}
	if newest == nil {
		t.Fatal("the chain holds no segment_sealed event; the dashboard's heartbeat " +
			"reads that event and would render nothing")
	}
	if got := newest[event.FieldSegmentID]; got != last.ID {
		t.Errorf("the newest segment_sealed in the chain names segment %v; the run "+
			"last anchored %s", got, last.ID)
	}
	if _, ok := newest[event.FieldAnchorRekorEntryUUID]; !ok {
		t.Error("the newest segment_sealed in the chain carries no anchor; the " +
			"dashboard would render the heartbeat as sealed-but-unanchored while " +
			"the anchorer reports it anchored")
	}
	if got, want := newest[event.FieldAnchorRekorLogIndex], last.Anchor.LogIndex; got != want {
		t.Errorf("the chain records log index %v for the newest segment, the anchor "+
			"returned %d", got, want)
	}

	final := h.anchorer.Lag()
	if !final.Anchored || final.PendingSegments != 0 {
		t.Errorf("the run ended with the heartbeat reporting %d pending and "+
			"anchored=%v", final.PendingSegments, final.Anchored)
	}
	if final.SegmentID != last.ID || final.LastPosition != last.Last {
		t.Errorf("the heartbeat ends on segment %s (…%d); the run ended on %s (…%d)",
			final.SegmentID, final.LastPosition, last.ID, last.Last)
	}
	if final.OverBound {
		t.Errorf("the heartbeat ended over its %s bound with %.3fs of lag; sealing "+
			"and anchoring did not keep up with the load",
			h.bound, final.LagSeconds)
	}
}

// calibrationResult is the single-writer ceiling.
type calibrationResult struct {
	dsn       string
	latencies []time.Duration
}

// calibrate measures one append at a time on a chain of its own.
//
// This is the number that says what the ledger can do at all. doc 02 §2
// assigns chain_position "under serialized append", and the store takes a
// Postgres advisory lock to serialize it, so no amount of concurrency can
// exceed 1/(serialized append). Reporting a concurrent throughput without it
// would leave a reader unable to tell a saturated ledger from a lazy
// generator.
func calibrate(ctx context.Context, t *testing.T, s *stack) calibrationResult {
	t.Helper()
	store, dsn := newLedger(t, s)

	out := make([]time.Duration, 0, calibrationAppends)
	for i := range calibrationAppends {
		at := time.Now()
		if _, err := store.Append(ctx, toolCallBody(99, int64(i))); err != nil {
			t.Fatalf("calibration append %d: %v", i, err)
		}
		if i >= calibrationWarmup {
			out = append(out, time.Since(at))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return calibrationResult{dsn: dsn, latencies: out}
}

// roundTripFloor is the cost of the cheapest possible statement through the
// same driver and socket the appends use.
//
// Without it an append latency is uninterpretable: 3 ms could be a database
// doing real work, or a client library and a loopback socket costing 3 ms
// before anything happens. On Docker Desktop, where the daemon is a VM and a
// published port is a proxied one, this is not a small number and pretending
// otherwise would inflate what the ledger appears to cost.
func roundTripFloor(ctx context.Context, t *testing.T, dsn string) []time.Duration {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect for the round-trip floor: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	out := make([]time.Duration, 0, floorSamples)
	for range floorSamples {
		at := time.Now()
		var one int
		if err := conn.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
			t.Fatalf("SELECT 1: %v", err)
		}
		out = append(out, time.Since(at))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// storageFacts is what one event costs where it is kept.
type storageFacts struct {
	Events       int64   `json:"events"`
	CanonicalMin int64   `json:"canonical_min_bytes"`
	CanonicalAvg float64 `json:"canonical_avg_bytes"`
	CanonicalMax int64   `json:"canonical_max_bytes"`
	// EventsRelationBytes is pg_total_relation_size of innsegl.events: the
	// heap, its indexes and its toast. SchemaBytes is the same over every
	// table in the innsegl schema, which is what a deployment actually holds.
	EventsRelationBytes int64   `json:"events_relation_bytes"`
	SchemaBytes         int64   `json:"schema_bytes"`
	BytesPerEvent       float64 `json:"bytes_per_event"`
	// Relations is every table in the schema with its total size, so that a
	// bytes-per-event figure can be read as the sum of things somebody can go
	// and look at rather than as one opaque number. innsegl.idempotency is
	// the one most likely to surprise a reader sizing from doc 05 §4, which
	// mentions only events.
	Relations map[string]int64 `json:"relations"`
	// Indexes is every index on innsegl.events with its size. The
	// bytes-per-event figure this ADR-facing report exists to produce is
	// mostly index, and "mostly index" is a claim that has to be checkable
	// rather than inferred from reading the migration.
	Indexes map[string]int64 `json:"indexes"`
}

// relationLines renders the breakdown, largest first.
func (f storageFacts) relationLines() string {
	return sizeLines(f.Relations, f.Events) + sizeLines(f.Indexes, f.Events)
}

func sizeLines(sizes map[string]int64, events int64) string {
	names := make([]string, 0, len(sizes))
	for name := range sizes {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return sizes[names[i]] > sizes[names[j]] })
	var b strings.Builder
	for _, name := range names {
		per := 0.0
		if events > 0 {
			per = float64(sizes[name]) / float64(events)
		}
		fmt.Fprintf(&b, "\n    %-28s %9d B  (%6.1f B/event)", name, sizes[name], per)
	}
	return b.String()
}

// measureStorage reads what the run cost on disk.
//
// VACUUM ANALYZE first: a table read immediately after a burst of inserts
// reports whatever the last extension left it at, and the question doc 05 §4
// asks is what a year of events costs, not what one burst left unreclaimed.
func measureStorage(ctx context.Context, t *testing.T, dsn string) storageFacts {
	t.Helper()
	conn, connErr := pgx.Connect(ctx, dsn)
	if connErr != nil {
		t.Fatalf("connect to measure storage: %v", connErr)
	}
	defer func() { _ = conn.Close(ctx) }()

	if _, err := conn.Exec(ctx, "VACUUM (ANALYZE) innsegl.events"); err != nil {
		t.Fatalf("VACUUM ANALYZE innsegl.events: %v", err)
	}

	var f storageFacts
	if err := conn.QueryRow(ctx, `
		SELECT count(*),
		       coalesce(min(octet_length(canonical)), 0),
		       coalesce(avg(octet_length(canonical)), 0),
		       coalesce(max(octet_length(canonical)), 0)
		  FROM innsegl.events`).
		Scan(&f.Events, &f.CanonicalMin, &f.CanonicalAvg, &f.CanonicalMax); err != nil {
		t.Fatalf("measure canonical sizes: %v", err)
	}
	if err := conn.QueryRow(ctx,
		`SELECT pg_total_relation_size('innsegl.events')`).
		Scan(&f.EventsRelationBytes); err != nil {
		t.Fatalf("measure the events relation: %v", err)
	}
	rows, queryErr := conn.Query(ctx, `
		SELECT c.relname, pg_total_relation_size(c.oid)
		  FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = 'innsegl' AND c.relkind = 'r'`)
	if queryErr != nil {
		t.Fatalf("measure the innsegl schema: %v", queryErr)
	}
	f.Relations = map[string]int64{}
	for rows.Next() {
		var name string
		var size int64
		if err := rows.Scan(&name, &size); err != nil {
			rows.Close()
			t.Fatalf("measure the innsegl schema: %v", err)
		}
		f.Relations["innsegl."+name] = size
		f.SchemaBytes += size
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("measure the innsegl schema: %v", err)
	}
	idx, idxErr := conn.Query(ctx, `
		SELECT indexrelname, pg_relation_size(indexrelid)
		  FROM pg_stat_all_indexes
		 WHERE schemaname = 'innsegl' AND relname = 'events'`)
	if idxErr != nil {
		t.Fatalf("measure the indexes on innsegl.events: %v", idxErr)
	}
	f.Indexes = map[string]int64{}
	for idx.Next() {
		var name string
		var size int64
		if err := idx.Scan(&name, &size); err != nil {
			idx.Close()
			t.Fatalf("measure the indexes on innsegl.events: %v", err)
		}
		f.Indexes["index "+name] = size
	}
	idx.Close()
	if err := idx.Err(); err != nil {
		t.Fatalf("measure the indexes on innsegl.events: %v", err)
	}

	if f.Events > 0 {
		f.BytesPerEvent = float64(f.SchemaBytes) / float64(f.Events)
	}
	return f
}

// runtimeConditions is the half of every measurement that is not a number.
func runtimeConditions(s *stack) string {
	return fmt.Sprintf(
		"go %s %s/%s, GOMAXPROCS=%d, NumCPU=%d, race detector %s; "+
			"docker %s on %s (%s cpus, %s bytes of RAM); images %s, %s, %s",
		runtime.Version(), runtime.GOOS, runtime.GOARCH,
		runtime.GOMAXPROCS(0), runtime.NumCPU(), raceDetectorState,
		s.dockerVersion, s.dockerOS, s.dockerCPUs, s.dockerMemory,
		postgresImage(), minioImage(), rekorImage())
}

// percentile returns the p-th percentile of a sorted slice.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(p / 100 * float64(len(sorted)-1))
	return sorted[i]
}

// yearlyEvents is doc 05 §4's own workload assumption, restated here so that
// the extrapolation below is visibly the document's arithmetic with a measured
// bytes-per-event substituted in, and not a new claim.
//
//	"at 10⁶ runs/year with ~20 events/run"
const yearlyEvents = 1_000_000 * 20

// measurement is one OPS-002 run, reduced to the numbers ADR-0039 quotes.
type measurement struct {
	Conditions string `json:"conditions"`
	TakenAt    string `json:"taken_at"`

	Workers       int   `json:"writers"`
	Segments      int   `json:"rollovers"`
	SegmentEvents int64 `json:"events_per_segment"`

	// Measured.
	Appends            int64   `json:"appends"`
	WallSeconds        float64 `json:"wall_seconds"`
	AppendsPerSecond   float64 `json:"appends_per_second"`
	InsideAppendShare  float64 `json:"inside_append_share"`
	AppendP50Millis    float64 `json:"append_p50_ms"`
	AppendP95Millis    float64 `json:"append_p95_ms"`
	AppendP99Millis    float64 `json:"append_p99_ms"`
	AppendMaxMillis    float64 `json:"append_max_ms"`
	SerialP50Millis    float64 `json:"serial_append_p50_ms"`
	SerialCeilingPerS  float64 `json:"serial_ceiling_appends_per_second"`
	RoundTripP50Millis float64 `json:"round_trip_floor_p50_ms"`

	Storage storageFacts `json:"storage"`

	SegmentObjectBytes  int     `json:"segment_object_bytes_max"`
	SegmentBytesPerLeaf float64 `json:"segment_object_bytes_per_event"`
	SealP50Millis       float64 `json:"seal_p50_ms"`
	AnchorP50Millis     float64 `json:"anchor_p50_ms"`

	HeartbeatReadings int     `json:"heartbeat_readings"`
	MaxLagSeconds     float64 `json:"heartbeat_max_lag_seconds"`
	BoundSeconds      float64 `json:"heartbeat_bound_seconds"`

	// Extrapolated, and labelled as such everywhere it appears.
	HotTierGiBPerYear float64 `json:"extrapolated_hot_tier_gib_per_year"`
	ObjectGiBPerYear  float64 `json:"extrapolated_segment_objects_gib_per_year"`
}

func reportOf(
	s *stack, cfg loadConfig, run runResult,
	calibration calibrationResult, floor []time.Duration, storage storageFacts,
) measurement {
	m := measurement{
		Conditions:    runtimeConditions(s),
		TakenAt:       time.Now().UTC().Format(time.RFC3339),
		Workers:       cfg.Workers,
		Segments:      len(run.Segments),
		SegmentEvents: cfg.SegmentEvents,

		Appends:           run.WorkerAppends,
		WallSeconds:       run.Wall.Seconds(),
		InsideAppendShare: 1 - generatorShare(run, cfg.Workers),
		Storage:           storage,
		HeartbeatReadings: len(run.Samples),
		BoundSeconds:      anchorBound.Seconds(),
	}
	if run.Wall > 0 {
		m.AppendsPerSecond = float64(run.WorkerAppends) / run.Wall.Seconds()
	}
	m.AppendP50Millis = millis(percentile(run.Latencies, 50))
	m.AppendP95Millis = millis(percentile(run.Latencies, 95))
	m.AppendP99Millis = millis(percentile(run.Latencies, 99))
	if n := len(run.Latencies); n > 0 {
		m.AppendMaxMillis = millis(run.Latencies[n-1])
	}
	serial := percentile(calibration.latencies, 50)
	m.SerialP50Millis = millis(serial)
	if serial > 0 {
		m.SerialCeilingPerS = float64(time.Second) / float64(serial)
	}
	m.RoundTripP50Millis = millis(percentile(floor, 50))

	seals := make([]time.Duration, 0, len(run.Segments))
	anchors := make([]time.Duration, 0, len(run.Segments))
	for _, seg := range run.Segments {
		seals = append(seals, seg.SealFor)
		anchors = append(anchors, seg.AnchorFor)
		if seg.ObjectBytes > m.SegmentObjectBytes {
			m.SegmentObjectBytes = seg.ObjectBytes
			if seg.Events > 0 {
				m.SegmentBytesPerLeaf = float64(seg.ObjectBytes) / float64(seg.Events)
			}
		}
	}
	sort.Slice(seals, func(i, j int) bool { return seals[i] < seals[j] })
	sort.Slice(anchors, func(i, j int) bool { return anchors[i] < anchors[j] })
	m.SealP50Millis = millis(percentile(seals, 50))
	m.AnchorP50Millis = millis(percentile(anchors, 50))

	for _, sample := range run.Samples {
		if sample.Snap.LagSeconds > m.MaxLagSeconds {
			m.MaxLagSeconds = sample.Snap.LagSeconds
		}
	}

	const gib = 1024 * 1024 * 1024
	m.HotTierGiBPerYear = storage.BytesPerEvent * yearlyEvents / gib
	m.ObjectGiBPerYear = m.SegmentBytesPerLeaf * yearlyEvents / gib
	return m
}

func millis(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// String renders the run the way ADR-0039 quotes it: measured facts and
// extrapolations in separate blocks, and the conditions above both.
func (m measurement) String() string {
	return fmt.Sprintf(`OPS-002 measurement
  taken at   %s
  conditions %s
  run        %d writers, %d rollovers of %d events

MEASURED
  appends                     %d in %.2fs
  throughput                  %.0f appends/s at %d writers
  writers inside store.Append %.2f%% of wall time
  append latency              p50 %.2f ms, p95 %.2f ms, p99 %.2f ms, max %.2f ms
  serialized append (1 writer) p50 %.2f ms  -> ceiling %.0f appends/s
  round-trip floor (SELECT 1) p50 %.2f ms
  canonical event             min %d B, mean %.1f B, max %d B
  hot tier per event          %.1f B (whole innsegl schema incl. indexes, after VACUUM)%s
  segment object              %d B for %d events -> %.1f B/event
  seal                        p50 %.1f ms
  anchor (real Rekor)         p50 %.1f ms
  heartbeat                   %d readings, max lag %.3fs against a %.0fs bound

EXTRAPOLATED (arithmetic, not measurement)
  doc 05 §4's own workload of 10^6 runs/year x 20 events/run = %d events/year
  hot tier                    %.1f GiB/year at the measured bytes/event
  segment objects             %.1f GiB/year at the measured bytes/event
  Neither figure was run for a year. They are the measured per-event costs
  multiplied by the document's assumed event count, and they inherit every
  assumption in it.`,
		m.TakenAt, m.Conditions,
		m.Workers, m.Segments, m.SegmentEvents,
		m.Appends, m.WallSeconds,
		m.AppendsPerSecond, m.Workers,
		m.InsideAppendShare*100,
		m.AppendP50Millis, m.AppendP95Millis, m.AppendP99Millis, m.AppendMaxMillis,
		m.SerialP50Millis, m.SerialCeilingPerS,
		m.RoundTripP50Millis,
		m.Storage.CanonicalMin, m.Storage.CanonicalAvg, m.Storage.CanonicalMax,
		m.Storage.BytesPerEvent, m.Storage.relationLines(),
		m.SegmentObjectBytes, m.SegmentEvents, m.SegmentBytesPerLeaf,
		m.SealP50Millis, m.AnchorP50Millis,
		m.HeartbeatReadings, m.MaxLagSeconds, m.BoundSeconds,
		int64(yearlyEvents),
		m.HotTierGiBPerYear, m.ObjectGiBPerYear)
}

func writeReport(t *testing.T, path string, m measurement) {
	t.Helper()
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("marshal the measurement: %v", err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	t.Logf("measurement written to %s", path)
}
