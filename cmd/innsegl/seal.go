// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/segment"
)

// `innsegl seal` — the sealer, wired.
//
// doc 05 §1 lists `innsegl-sealer` as one of the reference stack's twelve
// services, "built (same binary, subcommand)", and doc 05 §2 runs it
// leader-elected beside the reconciler. Until now nothing the shipped binary
// could run ever produced a segment, so a deployment accumulated no cold tier
// at all and doc 05 §2's premise — "losing Postgres loses *convenience* (the
// index), not *proof*" — had no artifact behind it (RM-078, #112).
//
// # It loops, like the reconciler, and it does not elect a leader
//
// doc 05 §1 lists a *component*, not a job, so the default is a loop and
// `-once` is the opt-out for a scheduled run — the same shape and the same
// flag as `innsegl reconcile`, which resolved this question first. Leader
// election is the deployment's job, not this binary's: doc 05 §2 says so, and
// providing it here would be a second implementation of something a Kubernetes
// Lease or a Job with a concurrency policy of Forbid already does.
//
// Nothing breaks if the deployment gets that wrong and two sealers overlap.
// Sealing is content-addressed and idempotent (SEG-002), every append carries a
// deterministic idempotency key, `idempotency_key` is UNIQUE across the chain
// (LED-008), and the ledger serializes appends — so two cycles over one range
// produce ONE segment_sealed event between them, and a cycle that would seal a
// *different* range from the same starting position is refused rather than
// appended. doc 05 §2 relies on exactly this, by name.
//
// # Three verdicts, and only one of them is a pass
//
// A cycle that sealed every full segment and got an entry for each exits 0. A
// cycle that sealed a segment the log would not take exits UNANCHORED: the
// record is durable and the object is stored, but nothing outside this system
// can yet be shown to agree with it, and doc 05 §4 lists anchoring lag among
// the monitoring minimums. A cycle that could not run at all exits
// INCONCLUSIVE: nothing was sealed, so the cold tier did not grow and the
// deployment is back where #112 found it.

// Exit statuses, continuing cli.go's contract. The canary owns 3 and 4, the
// reaper 5 and 6, the reconciler 7 and 8; these are the sealer's.
const (
	// exitSealUnanchored: a segment is sealed and stored but has no entry in
	// the transparency log.
	exitSealUnanchored = 9
	// exitSealInconclusive: the cycle could not run — bad configuration, an
	// unreachable ledger or object store. Nothing was sealed, so it fails
	// closed.
	exitSealInconclusive = 10
)

// Every flag falls back to an environment variable so a compose service or a
// scheduled job can be configured entirely by environment and never put the
// ledger DSN or the object store secret on a command line the process table
// can read.
//
// The object store names are the canary's own ($INNSEGL_OBJECT_STORE_*), the
// ledger and log names are `serve`'s and the reconciler's: the sealer writes
// the bucket the canary probes and anchors in the Rekor the reconciler reads,
// and a second spelling would be a second thing to get out of step in a
// deployment.
const (
	envSealSegmentEvents = "INNSEGL_SEAL_SEGMENT_EVENTS"
	envSealMaxAge        = "INNSEGL_SEAL_MAX_SEGMENT_AGE"
	envSealInterval      = "INNSEGL_SEAL_INTERVAL"
	envSealScanWindow    = "INNSEGL_SEAL_SCAN_WINDOW"
	envAnchorBound       = "INNSEGL_ANCHOR_BOUND"
	envAnchorAttempts    = "INNSEGL_ANCHOR_ATTEMPTS"
	envAnchorKey         = "INNSEGL_ANCHOR_KEY"
)

const (
	// defaultSegmentEvents is the size rollover. At doc 05 §4's sizing — 10⁶
	// runs a year at ~20 events each — this is roughly 20,000 segments and as
	// many log entries a year, and RM-052 measured a segment object at 74 B an
	// event (#60), so one is about 74 KB.
	defaultSegmentEvents = 1000

	// defaultMaxSegmentAge is the age rollover, and it is the reason a quiet
	// deployment still accumulates a cold tier. Without it a chain appending
	// fifty events a day would wait three weeks for its first segment, which
	// is #112's finding with a longer fuse. It sits under FD §3.1's
	// fifteen-minute heartbeat bound so that a deployment with any traffic at
	// all anchors inside the window the dashboard turns amber at.
	defaultMaxSegmentAge = 10 * time.Minute

	// defaultSealInterval is how often the loop looks. Sealing when there is
	// nothing to seal costs two indexed reads.
	defaultSealInterval = time.Minute

	// defaultScanWindow is how far back one page of the survey reads. It also
	// bounds how far back a sealed-but-unanchored segment is still retried
	// automatically; see the survey's note in sealengine.go.
	defaultScanWindow = 5000

	// defaultAnchorBound is FD §3.1's amber threshold.
	defaultAnchorBound = 15 * time.Minute

	// defaultAnchorAttempts is the bounded retry one anchoring attempt runs
	// under before the alert. internal/segment's own default is the same.
	defaultAnchorAttempts = 5
)

// sealOptions is the resolved command line.
type sealOptions struct {
	dsn      string
	rekorURL string

	endpoint  string
	bucket    string
	accessKey string
	secretKey string
	region    string
	prefix    string
	useTLS    bool
	mode      string
	retention time.Duration
	opTimeout time.Duration

	segmentEvents  int64
	maxSegmentAge  time.Duration
	scanWindow     int64
	interval       time.Duration
	anchorBound    time.Duration
	anchorAttempts int
	anchorBase     time.Duration
	anchorKey      string
	once           bool
}

func defaultSealOptions() sealOptions {
	return sealOptions{
		useTLS:         true,
		mode:           string(segment.RetentionCompliance),
		opTimeout:      60 * time.Second,
		segmentEvents:  defaultSegmentEvents,
		maxSegmentAge:  defaultMaxSegmentAge,
		scanWindow:     defaultScanWindow,
		interval:       defaultSealInterval,
		anchorBound:    defaultAnchorBound,
		anchorAttempts: defaultAnchorAttempts,
	}
}

// sealCycler is the one thing this command needs of a sealer. *sealEngine is
// the production implementation and SEG-008..012 are what prove it.
type sealCycler interface {
	Cycle(ctx context.Context) (sealCycle, error)
}

// sealDeps are the seams this command's tests replace. Production wiring is
// the zero value.
type sealDeps struct {
	open func(context.Context, sealOptions) (sealCycler, func(), error)
}

func (d sealDeps) opener() func(context.Context, sealOptions) (sealCycler, func(), error) {
	if d.open != nil {
		return d.open
	}
	return openSealer
}

// sealCommand is the subcommand body wired into cli.go's dispatch table.
func sealCommand(args []string, stdout, stderr io.Writer) int {
	// SIGINT and SIGTERM end the loop cleanly. A sealer killed mid-cycle is
	// harmless — the object is content-addressed and every append is keyed, so
	// the next cycle re-derives the identical segment and adopts what is
	// already there (IP §6.4, SEG-002) — but an operator deserves the final
	// report.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runSealLoop(ctx, args, stdout, stderr, sealDeps{})
}

func runSealCommand(args []string, stdout, stderr io.Writer, deps sealDeps) int {
	return runSealLoop(context.Background(), args, stdout, stderr, deps)
}

// runSealLoop is the whole command: parse, refuse, open, cycle.
func runSealLoop(ctx context.Context, args []string, stdout, stderr io.Writer, deps sealDeps) int {
	opts, asJSON, quiet, code := parseSealFlags(args, stderr)
	if code != exitOK {
		return code
	}
	if opts == nil {
		return exitOK // -h
	}

	engine, closeAll, err := deps.opener()(ctx, *opts)
	if err != nil {
		fprintf(stderr, "innsegl seal: %v\n", err)
		fprintf(stderr, "innsegl seal: INCONCLUSIVE - nothing was sealed, so the cold "+
			"tier did not grow\n")
		return exitSealInconclusive
	}
	if closeAll != nil {
		defer closeAll()
	}
	if engine == nil {
		fprintf(stderr, "innsegl seal: %v\n", errNoCycler)
		return exitSealInconclusive
	}

	report := sealReporter{stdout: stdout, stderr: stderr, asJSON: asJSON, quiet: quiet}
	if opts.once {
		return report.cycle(ctx, engine)
	}

	ticker := time.NewTicker(opts.interval)
	defer ticker.Stop()
	worst := exitOK
	for {
		if code := report.cycle(ctx, engine); code != exitOK {
			worst = code
		}
		select {
		case <-ctx.Done():
			// A cancelled context is the operator stopping the component, not
			// a failure. The worst verdict seen is still the exit status: a
			// sealer that could not anchor for an hour because Rekor was down
			// must not exit 0 when it is finally stopped.
			return worst
		case <-ticker.C:
		}
	}
}

// parseSealFlags resolves the command line. It returns a nil options with
// exitOK for -h, and a non-OK code for anything it refuses.
//
//nolint:gocyclo // One refusal per flag, then the resolved options; splitting it would put the usage contract in a different function from the flags it is a function of.
func parseSealFlags(args []string, stderr io.Writer) (*sealOptions, bool, bool, int) {
	fs := flag.NewFlagSet("innsegl seal", flag.ContinueOnError)
	fs.SetOutput(stderr)
	d := defaultSealOptions()

	var (
		dsn = fs.String("dsn", os.Getenv(envLedgerDSN),
			"ledger connection string — prefer the environment variable ($"+envLedgerDSN+")")
		rekorURL = fs.String("rekor-url", os.Getenv(envRekorURL),
			"transparency log base URL, e.g. https://rekor.sigstore.dev ($"+envRekorURL+")")
		endpoint = fs.String("endpoint", os.Getenv(envEndpoint),
			"object store endpoint, host:port without a scheme ($"+envEndpoint+")")
		bucket = fs.String("bucket", os.Getenv(envBucket),
			"bucket sealed segments are written to ($"+envBucket+")")
		accessKey = fs.String("access-key", os.Getenv(envAccessKey),
			"object store access key ($"+envAccessKey+")")
		secretKey = fs.String("secret-key", os.Getenv(envSecretKey),
			"object store secret key — prefer the environment variable ($"+envSecretKey+")")
		region = fs.String("region", os.Getenv(envRegion),
			"object store region, if the store needs one ($"+envRegion+")")
		prefix = fs.String("prefix", os.Getenv(envPrefix),
			"key prefix for segment objects ($"+envPrefix+")")
		useTLS = fs.Bool("tls", envBool(envTLS, true), "use https ($"+envTLS+")")
		mode   = fs.String("mode", envOr(envMode, d.mode),
			"object lock retention mode, COMPLIANCE or GOVERNANCE ($"+envMode+")")
		retention = fs.Duration("retention", envDuration(envRetention, 0),
			"retention applied to each segment object; 0 relies on the bucket's default rule ($"+envRetention+")")
		timeout = fs.Duration("timeout", envDuration(envTimeoutVar, d.opTimeout),
			"bound on one object store request ($"+envTimeoutVar+")")
		segmentEvents = fs.Int64("segment-events",
			int64(envInt(envSealSegmentEvents, defaultSegmentEvents)),
			"events per segment; a full one is sealed as soon as it exists ($"+envSealSegmentEvents+")")
		maxSegmentAge = fs.Duration("max-segment-age", envDuration(envSealMaxAge, defaultMaxSegmentAge),
			"seal a partial segment once its oldest event has waited this long; "+
				"0 waits for a full segment however long that takes ($"+envSealMaxAge+")")
		scanWindow = fs.Int64("scan-window", int64(envInt(envSealScanWindow, defaultScanWindow)),
			"events per page of the backwards survey; also how far back a sealed "+
				"segment with no anchor is still retried ($"+envSealScanWindow+")")
		interval = fs.Duration("interval", envDuration(envSealInterval, defaultSealInterval),
			"time between cycles; ignored with -once ($"+envSealInterval+")")
		anchorBound = fs.Duration("anchor-bound", envDuration(envAnchorBound, defaultAnchorBound),
			"anchoring lag past which the dashboard heartbeat goes amber (FD §3.1) ($"+envAnchorBound+")")
		anchorAttempts = fs.Int("anchor-attempts", envInt(envAnchorAttempts, defaultAnchorAttempts),
			"submissions to the log per segment, including the first, before the alert ($"+envAnchorAttempts+")")
		anchorKey = fs.String("anchor-key", os.Getenv(envAnchorKey),
			"PEM file holding the EC private key that signs log submissions; "+
				"empty generates an ephemeral one per process ($"+envAnchorKey+")")
		once   = fs.Bool("once", false, "run one cycle and exit, for a scheduled job")
		asJSON = fs.Bool("json", false, "write each cycle's report as JSON")
		quiet  = fs.Bool("quiet", false,
			"print nothing for a cycle that sealed nothing; failures are always reported")
	)

	fs.Usage = func() {
		fprintf(stderr, "innsegl seal - seal ledger segments and anchor them in the transparency log (IP §6.4)\n\n")
		fprintf(stderr, "Usage:\n  innsegl seal [flags]\n\n")
		fprintf(stderr, "Runs continuously by default. Run it single-active; see doc 05 §2.\n\n")
		fprintf(stderr, "Exit status:\n")
		fprintf(stderr, "  %d  every full segment is sealed and anchored\n", exitOK)
		fprintf(stderr, "  %d  the command line was not understood\n", exitUsage)
		fprintf(stderr, "  %d  UNANCHORED - a segment is sealed and stored but has no transparency log entry\n",
			exitSealUnanchored)
		fprintf(stderr, "  %d  INCONCLUSIVE - the cycle could not run; nothing was sealed\n",
			exitSealInconclusive)
		fprintf(stderr, "\nFlags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, false, false, exitOK
		}
		return nil, false, false, exitUsage
	}
	if fs.NArg() > 0 {
		fprintf(stderr, "innsegl seal: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return nil, false, false, exitUsage
	}

	missing := ""
	switch {
	case *dsn == "":
		missing = "-dsn (or $" + envLedgerDSN + ")"
	case *rekorURL == "":
		missing = "-rekor-url (or $" + envRekorURL + ")"
	case *endpoint == "":
		missing = "-endpoint (or $" + envEndpoint + ")"
	case *bucket == "":
		missing = "-bucket (or $" + envBucket + ")"
	case *accessKey == "":
		missing = "-access-key (or $" + envAccessKey + ")"
	case *secretKey == "":
		missing = "-secret-key (or $" + envSecretKey + ")"
	}
	if missing != "" {
		fprintf(stderr, "innsegl seal: %s is required\n", missing)
		return nil, false, false, exitUsage
	}

	switch {
	case *segmentEvents < 1:
		fprintf(stderr, "innsegl seal: -segment-events %d is not a segment\n", *segmentEvents)
		return nil, false, false, exitUsage
	case *scanWindow < 1:
		fprintf(stderr, "innsegl seal: -scan-window %d reads nothing, so no segment is "+
			"ever found\n", *scanWindow)
		return nil, false, false, exitUsage
	case *anchorAttempts < 1:
		fprintf(stderr, "innsegl seal: -anchor-attempts %d never submits, so no segment "+
			"is ever anchored\n", *anchorAttempts)
		return nil, false, false, exitUsage
	case !*once && *interval <= 0:
		fprintf(stderr, "innsegl seal: -interval %s is not positive; use -once for a "+
			"single cycle\n", *interval)
		return nil, false, false, exitUsage
	}

	opts := d
	opts.dsn, opts.rekorURL = *dsn, *rekorURL
	opts.endpoint, opts.bucket = *endpoint, *bucket
	opts.accessKey, opts.secretKey = *accessKey, *secretKey
	opts.region, opts.prefix = *region, *prefix
	opts.useTLS, opts.mode = *useTLS, *mode
	opts.retention, opts.opTimeout = *retention, *timeout
	opts.segmentEvents, opts.maxSegmentAge = *segmentEvents, *maxSegmentAge
	opts.scanWindow, opts.interval = *scanWindow, *interval
	opts.anchorBound, opts.anchorAttempts = *anchorBound, *anchorAttempts
	opts.anchorKey = *anchorKey
	opts.once = *once
	return &opts, *asJSON, *quiet, exitOK
}

// sealReporter writes one cycle's outcome and returns its exit status.
type sealReporter struct {
	stdout io.Writer
	stderr io.Writer
	asJSON bool
	quiet  bool
}

func (r sealReporter) cycle(ctx context.Context, engine sealCycler) int {
	result, err := engine.Cycle(ctx)
	if err != nil {
		// A cancelled context during shutdown is not a failed cycle.
		if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
			return exitOK
		}
		fprintf(r.stderr, "innsegl seal: %v\n", err)
		fprintf(r.stderr, "innsegl seal: INCONCLUSIVE - the cycle could not run, so the "+
			"cold tier did not grow\n")
		return exitSealInconclusive
	}

	stuck := len(result.Unanchored)
	out := r.stdout
	if stuck > 0 {
		out = r.stderr
	}
	idle := len(result.Sealed) == 0 && len(result.Anchored) == 0 && stuck == 0
	switch {
	case r.asJSON:
		r.writeJSON(out, result)
	case r.quiet && idle:
	default:
		fprintf(out, "%s", renderSealCycle(result))
	}

	if stuck > 0 {
		fprintf(r.stderr, "innsegl seal: UNANCHORED - %d segment(s) are sealed and stored "+
			"with no entry in the transparency log. The records are durable and the next "+
			"cycle retries without re-sealing; until then nothing outside this system can "+
			"be shown to agree with them (IP §6.4).\n", stuck)
		return exitSealUnanchored
	}
	return exitOK
}

// renderSealCycle is the human report: one summary line, then one line per
// segment the cycle touched.
func renderSealCycle(c sealCycle) string {
	var b strings.Builder
	fmt.Fprintf(&b, "head %d  sealed through %d  pending %d  sealed %d  anchored %d  unanchored %d\n",
		c.Head, c.Watermark, c.Pending, len(c.Sealed), len(c.Anchored), len(c.Unanchored))
	fmt.Fprintf(&b, "  anchoring lag %.0fs of %.0fs%s\n",
		c.Lag.LagSeconds, c.Lag.BoundSeconds, amber(c.Lag.OverBound))

	for _, s := range c.Sealed {
		fmt.Fprintf(&b, "  sealed     %s  positions %d..%d (%d events)\n",
			s.SegmentID, s.First, s.Last, s.Events)
		writeAnchorLine(&b, s)
	}
	for _, s := range c.Anchored {
		fmt.Fprintf(&b, "  recovered  %s  positions %d..%d\n", s.SegmentID, s.First, s.Last)
		writeAnchorLine(&b, s)
	}
	for _, s := range c.Unanchored {
		if s.Failure == "" {
			continue
		}
		fmt.Fprintf(&b, "  unanchored %s  %s%s\n", s.SegmentID, s.Failure, alerted(s.Alerted))
	}
	return b.String()
}

func writeAnchorLine(b *strings.Builder, s sealedSegment) {
	if s.Anchored {
		fmt.Fprintf(b, "             root %s  rekor %s/%d\n", s.MerkleRoot, s.EntryUUID, s.LogIndex)
		return
	}
	fmt.Fprintf(b, "             root %s  NOT ANCHORED%s\n", s.MerkleRoot, alerted(s.Alerted))
}

func amber(over bool) string {
	if over {
		return "  OVER BOUND"
	}
	return ""
}

func alerted(raised bool) string {
	if raised {
		return " (ledger_drift_detected appended)"
	}
	return ""
}

// sealReportJSON is the machine-readable report. A view rather than json tags
// on sealCycle, so the wire shape is this command's contract and not a
// consequence of a field rename elsewhere.
type sealReportJSON struct {
	Head       int64               `json:"head"`
	Watermark  int64               `json:"watermark"`
	Pending    int64               `json:"pending"`
	Sealed     []sealSegmentJSON   `json:"sealed"`
	Anchored   []sealSegmentJSON   `json:"anchored"`
	Unanchored []sealSegmentJSON   `json:"unanchored"`
	Lag        segment.LagSnapshot `json:"anchoring"`
}

type sealSegmentJSON struct {
	SegmentID  string `json:"segment_id"`
	MerkleRoot string `json:"segment_merkle_root"`
	First      int64  `json:"first_position"`
	Last       int64  `json:"last_position"`
	Events     int    `json:"events"`
	Anchored   bool   `json:"anchored"`
	LogIndex   int64  `json:"anchor_rekor_log_index,omitempty"`
	EntryUUID  string `json:"anchor_rekor_entry_uuid,omitempty"`
	Failure    string `json:"failure,omitempty"`
	Alerted    bool   `json:"alerted,omitempty"`
}

func (r sealReporter) writeJSON(out io.Writer, c sealCycle) {
	view := sealReportJSON{
		Head: c.Head, Watermark: c.Watermark, Pending: c.Pending, Lag: c.Lag,
		Sealed:     sealSegmentsJSON(c.Sealed),
		Anchored:   sealSegmentsJSON(c.Anchored),
		Unanchored: sealSegmentsJSON(c.Unanchored),
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(view); err != nil {
		fprintf(r.stderr, "innsegl seal: writing the JSON report: %v\n", err)
	}
}

func sealSegmentsJSON(in []sealedSegment) []sealSegmentJSON {
	out := make([]sealSegmentJSON, 0, len(in))
	for _, s := range in {
		out = append(out, sealSegmentJSON{
			SegmentID: s.SegmentID, MerkleRoot: s.MerkleRoot,
			First: s.First, Last: s.Last, Events: s.Events,
			Anchored: s.Anchored, LogIndex: s.LogIndex, EntryUUID: s.EntryUUID,
			Failure: s.Failure, Alerted: s.Alerted,
		})
	}
	return out
}

// openSealer is the production wiring: the chain, the WORM bucket, and the
// transparency log.
func openSealer(ctx context.Context, opts sealOptions) (sealCycler, func(), error) {
	store, err := ledger.Open(ctx, opts.dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("opening the ledger: %w", err)
	}
	closeAll := store.Close

	worm, err := segment.NewWORM(ctx, segment.WORMConfig{
		Endpoint:  opts.endpoint,
		AccessKey: opts.accessKey,
		SecretKey: opts.secretKey,
		UseTLS:    opts.useTLS,
		Region:    opts.region,
		Bucket:    opts.bucket,
		Prefix:    opts.prefix,
		Mode:      segment.RetentionMode(opts.mode),
		Retention: opts.retention,
		OpTimeout: opts.opTimeout,
	})
	if err != nil {
		closeAll()
		return nil, nil, fmt.Errorf("opening the segment store: %w", err)
	}

	signer, err := anchorSigner(opts.anchorKey)
	if err != nil {
		closeAll()
		return nil, nil, err
	}
	log := &segment.RekorClient{BaseURL: opts.rekorURL, Signer: signer}

	return &sealEngine{
		chain:  store,
		sealer: &segment.Sealer{Store: worm},
		anchorer: &segment.Anchorer{
			Log:    log,
			Policy: segment.RetryPolicy{Attempts: opts.anchorAttempts},
			Bound:  opts.anchorBound,
		},
		opts: opts,
		now:  time.Now,
	}, closeAll, nil
}

// anchorSigner resolves the key that signs log submissions.
//
// The key is not what a verifier checks — an inclusion proof verifies against
// the *log's* key, and the claim a segment anchor makes is that this root was
// in the log at this index — so an ephemeral key is sound, and it is the
// default so that the reference deployment needs no mounted secret to start
// producing a cold tier. A deployment that wants every one of its segment
// anchors to carry one recognizable submitter points -anchor-key at a PEM.
func anchorSigner(path string) (segment.AnchorSigner, error) {
	if path == "" {
		signer, err := segment.GenerateAnchorSigner()
		if err != nil {
			return nil, fmt.Errorf("generating an anchoring key: %w", err)
		}
		return signer, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the anchoring key: %w", err)
	}
	key, err := parseECPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("reading the anchoring key from %s: %w", path, err)
	}
	signer, err := segment.NewECDSAAnchorSigner(key)
	if err != nil {
		return nil, fmt.Errorf("using the anchoring key from %s: %w", path, err)
	}
	return signer, nil
}

// parseECPrivateKey reads a PEM-encoded EC private key in either of the two
// encodings openssl produces: SEC 1 ("EC PRIVATE KEY") and PKCS#8.
func parseECPrivateKey(raw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the %q block is neither a SEC 1 nor a PKCS#8 EC private key: %w",
			block.Type, err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("the %q block holds a %T, want an EC private key", block.Type, parsed)
	}
	return key, nil
}
