// SPDX-License-Identifier: Apache-2.0

package reconciler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/event"
)

// witness.go — RM-247 (#392), E18 (ADR-0057's third witness).
//
// # What this cross-checks
//
// record.go's own gatewayToolCallBody now carries tool_use_id (#392's own
// gateway-side change). internal/gateway's own TelemetryHandler, when a
// deployment points the harness's OTLP exporter at the gateway, keeps a
// small record of each claude_code.tool_result it sees, keyed by the SAME
// tool_use_id, under LogDir/telemetry (the SAME LogDir this pass shares with
// commitwatch.go and writes.go). This pass joins the two:
//
//	DIRECTION 1  a tool_call the gateway relayed, with no telemetry record
//	             for its tool_use_id once Window has passed since the call —
//	             `WitnessMissingTelemetry`. doc 02 §3's `ledger_drift_detected`
//	             fits exactly here: the tool_call event IS the ledger's own
//	             claim that this call happened, and the harness's own
//	             telemetry is the external proof that never arrived
//	             ("a ledger claim with no external proof").
//	DIRECTION 2  a telemetry record for a tool_use_id no tool_call this cycle
//	             can find — `WitnessOrphanTelemetry`. There is no ledger
//	             event this could be the SUBJECT of (the gateway never
//	             relayed it, so nothing on the chain names it), and doc 02's
//	             schema admits no field for "no subject" — inventing one
//	             would be exactly the kind of protected-schema addition doc
//	             08 §3 gates behind a major release. So this direction is
//	             reported (Result.Witness.Findings, the Alert sink) and
//	             NEVER appended. See witnessintegration_test.go's own doc
//	             comment for the full reasoning and its consequence for
//	             idempotency.
//
// # Sharing a subject space with commit watch
//
// Both this pass and commitwatch.go use a tool_call's own event_id as their
// `ledger_drift_detected` subject, and both derive their `idempotency_key`
// from LedgerDriftKey(subjectEventID) alone — drift.go's own scheme,
// documented there as sound because "exactly one of the reasons below can
// ever hold for one subject" of a `commit_recorded`. That premise does not
// automatically extend to a tool_call subject shared by two DIFFERENT
// checks with two DIFFERENT reason spaces: a Bash git-commit call that
// bypassed signing AND was never corroborated by telemetry is a real,
// possible state. appendWitnessAlert's own dedupe therefore checks not just
// whether the key is already spent, but whether the record it names carries
// THIS finding's own reason — if it carries commit watch's instead, it
// counts as "already accounted for by another check", not as this cycle's
// own new finding, and appends nothing further.
//
// # Deriving "telemetry active since"
//
// A deployment that never enabled telemetry must not alert on every tool
// call it relays. TelemetryActive and TelemetrySince are derived from the
// EARLIEST telemetry record this gateway has ever kept (by the record's own
// stored `time` — the gateway's OWN receive clock, per witness.go's own
// counterpart in internal/gateway, never the harness-asserted
// event.timestamp), read via the file's own mtime rather than by opening
// and parsing every file: the atomic write in internal/gateway/witness.go
// renames a temp file into place at write time, so the final file's mtime
// IS the record's own receive time, and a directory listing's own stat
// calls get that value without a single body read. Only a tool_call made
// AT OR AFTER TelemetrySince is ever judged for direction 1 — one made
// before it proves nothing about an absence, because telemetry was not yet
// running to prove it.

// DefaultWitnessWindow is how long this pass waits, after a tool_call is
// relayed, before treating a still-missing telemetry record as drift — and,
// symmetrically, how long it waits after a telemetry record is received
// before treating a still-unmatched tool_use_id as orphaned. Thirty
// minutes: longer than a core restart. While the core is down the client
// holds the harness's telemetry and delivers it once the core answers
// (internal/client/outbox.go); a shorter window reported every tool
// call of a restart as drift before its telemetry arrived.
const DefaultWitnessWindow = 30 * time.Minute

// reasonNoTelemetryWitness is this pass's one `reason` constant for
// direction 1. PROTECTED-ADJACENT, exactly as commitwatch.go and drift.go
// record for their own: `reason` is part of the canonical preimage (doc 02
// §4) of an event in an append-only chain.
const reasonNoTelemetryWitness = "the harness's own OTLP telemetry recorded no tool_result for this tool call"

// ---------------------------------------------------------------------------
// Findings.
// ---------------------------------------------------------------------------

// WitnessFindingKind says which direction of the cross-check produced a
// finding.
type WitnessFindingKind string

const (
	// WitnessMissingTelemetry: the gateway relayed this tool_call and no
	// telemetry record corroborated it once the window passed. Appended as
	// a `ledger_drift_detected`.
	WitnessMissingTelemetry WitnessFindingKind = "missing_telemetry"
	// WitnessOrphanTelemetry: the harness's own telemetry named a
	// tool_use_id the gateway never relayed. Reported, never appended — see
	// this file's own package doc comment.
	WitnessOrphanTelemetry WitnessFindingKind = "orphan_telemetry"
)

// WitnessFinding is one verdict, and the operator-visible half of this pass.
type WitnessFinding struct {
	Kind WitnessFindingKind
	// ToolCallEventID is set on WitnessMissingTelemetry: the tool_call this
	// finding is about, and this alert's subject_event_id.
	ToolCallEventID string
	// ToolUseID is set on both kinds.
	ToolUseID string
	RunID     string
	SPIFFEID  string
	ToolName  string
	// Reason is the constant that goes into the ledger_drift_detected this
	// finding produced. Empty on WitnessOrphanTelemetry, which appends
	// nothing.
	Reason string
	// Detail is why, in words an operator reads, with the identifiers
	// Reason deliberately leaves out.
	Detail string
	// AppendedEventID is the alert this finding produced. Empty when it was
	// already reported (idempotent), when nothing could be appended, or —
	// always, by design — on WitnessOrphanTelemetry.
	AppendedEventID string
}

// WitnessReport is what one pass did.
type WitnessReport struct {
	// Enabled is false when no Config.Witness was given, so a reader never
	// mistakes "not run" for "nothing to find".
	Enabled bool
	// TelemetryActive is whether this gateway has EVER kept a telemetry
	// record, derived from LogDir/telemetry's own contents. False means
	// this pass compared nothing this cycle — direction 1 would alert on
	// every relayed call otherwise, and direction 2 has nothing to read.
	TelemetryActive bool
	// TelemetrySince is the earliest telemetry record's own receive time.
	// Zero when !TelemetryActive.
	TelemetrySince time.Time
	// Checked is how many tool_call events this pass could read a
	// tool_use_id for: a readable body naming one that has the harness's
	// own id shape (commitpath.IsToolUseID).
	Checked int
	// Unchecked is how many tool_call events this pass could not read a
	// verdict for: an unreadable body, or one with no usable tool_use_id
	// (including every tool_call recorded before #392 shipped). Never a
	// finding.
	Unchecked int
	// RunsWithoutTelemetry is how many runs had Checked calls and not one
	// of them matched by a telemetry record: a harness that exports no
	// telemetry. Their calls are not judged, because an absence proves
	// nothing where nothing was ever sent (#434). Reported, never appended.
	RunsWithoutTelemetry int
	// Matched is how many Checked calls have a corroborating telemetry
	// record on disk, regardless of window or TelemetryActive — a match is
	// a match.
	Matched int
	// Pending is how many Checked calls have no telemetry yet, but are
	// still inside the window (or were excluded because TelemetrySince is
	// after the call — see this file's own package doc comment). Never a
	// finding.
	Pending int
	// Missing is how many NEW WitnessMissingTelemetry findings this cycle
	// produced. A subject already reported (view.drift.subjects) is
	// skipped before it is re-judged, exactly commitwatch.go's own
	// convention.
	Missing int
	// Orphaned is how many WitnessOrphanTelemetry findings this cycle
	// reported — including ones reported in an earlier cycle too; this
	// direction cannot be deduped against the chain (this file's own
	// package doc comment explains why) and recurs for as long as it stays
	// true.
	Orphaned int
	// Findings is one entry per Missing and Orphaned case this cycle,
	// direction 1 first.
	Findings []WitnessFinding
	// Appended is the event_id of each alert this cycle wrote — direction 1
	// only, ever. Empty on a cycle over already-reported state.
	Appended []string
}

// ---------------------------------------------------------------------------
// Configuration.
// ---------------------------------------------------------------------------

// WitnessConfig turns the pass on. Nil leaves it OFF, and
// Result.Witness.Enabled says so on every cycle.
type WitnessConfig struct {
	// LogDir is where the gateway retains tool-call bodies AND, under its
	// own "telemetry" subdirectory, telemetry records
	// (internal/gateway/witness.go's own Dir) — the SAME directory
	// CommitWatchConfig.LogDir and WritesConfig.LogDir already read.
	// Required: a detector that cannot read either side reports agreement
	// it never checked.
	LogDir string
	// Window is how long this pass waits before treating a still-missing
	// telemetry record, or a still-unmatched telemetry record, as a
	// finding. Zero means DefaultWitnessWindow.
	Window time.Duration
	// Alert receives every finding, including the ones already reported
	// and the ones this pass can never append. Defaults to an error-level
	// slog line.
	Alert func(context.Context, WitnessFinding)
}

func (c *WitnessConfig) validate() error {
	if c == nil {
		return nil
	}
	if c.LogDir == "" {
		return errors.New("reconciler: the telemetry witness is configured with no body " +
			"directory; a detector that cannot read a tool call's body or the gateway's own " +
			"telemetry records reports agreement it never checked")
	}
	if c.Window < 0 {
		return fmt.Errorf("reconciler: a witness window of %d is not a window; zero means "+
			"the default of %s", c.Window, DefaultWitnessWindow)
	}
	return nil
}

func (c *WitnessConfig) window() time.Duration {
	if c.Window <= 0 {
		return DefaultWitnessWindow
	}
	return c.Window
}

func (c *WitnessConfig) alert(ctx context.Context, finding WitnessFinding) {
	if c.Alert != nil {
		c.Alert(ctx, finding)
		return
	}
	defaultWitnessAlert(ctx, finding)
}

// ---------------------------------------------------------------------------
// The ledger side of the check, folded out of the same chain walk.
// ---------------------------------------------------------------------------

// witnessCall is one tool_call this pass has to judge: cheap to collect
// during the walk (event fields only), expensive to judge (a body read) —
// commitWatchCall's own split, held for the same reason.
type witnessCall struct {
	eventID  string
	runID    string
	spiffeID string
	digest   string
	at       time.Time
}

// witnessView is this pass's fold of the chain: every tool_call this pass
// may need to cross-check.
type witnessView struct {
	calls []witnessCall
}

func newWitnessView() *witnessView { return &witnessView{} }

// observe folds one event in. Called for EVERY event, like drift's,
// writes's and commitWatch's own.
func (v *witnessView) observe(record event.Fields) {
	if recordString(record, event.FieldEventType) != event.EventTypeToolCall {
		return
	}
	eventID := recordString(record, event.FieldEventID)
	runID := recordString(record, event.FieldRunID)
	digest := recordString(record, event.FieldPayloadDigest)
	if eventID == "" || runID == "" || digest == "" {
		return
	}
	at, err := event.ParseTimestamp(recordString(record, event.FieldTS))
	if err != nil {
		return
	}
	v.calls = append(v.calls, witnessCall{
		eventID:  eventID,
		runID:    runID,
		spiffeID: recordString(record, event.FieldSpiffeID),
		digest:   digest,
		at:       at.Time(),
	})
}

// ---------------------------------------------------------------------------
// The retained tool_call body, as this pass reads it.
// ---------------------------------------------------------------------------

// witnessCallBody is the part of a gateway-recorded tool_call body this
// pass reads: internal/gateway/record.go's own gatewayToolCallBody,
// restated here rather than imported — the same restatement commitwatch.go
// already holds itself to, for the identical reason (that type is
// unexported to its own package).
type witnessCallBody struct {
	Tool           string          `json:"tool"`
	ToolUseID      string          `json:"tool_use_id"`
	ResultObserved bool            `json:"result_observed"`
	Result         json.RawMessage `json:"result,omitempty"`
	IsError        bool            `json:"is_error,omitempty"`
}

// harnessBlockedPrefix begins the content of the tool_result a harness
// answers the model with when its own input validation refuses a tool call
// before any permission decision is made (a blocked `sleep`, an Edit of a
// file not yet read). The text is the harness's, observed in recorded
// tool_results (#451), not ours. The harness emits no tool_result telemetry
// and no reject decision for such a call: it never ran.
const harnessBlockedPrefix = "<tool_use_error>"

// harnessBlocked reports whether the recorded result says the harness
// refused this call itself: observed, marked is_error, and starting with
// harnessBlockedPrefix. An error without the prefix is a tool that ran and
// failed, and that still reports a tool_result.
func (b witnessCallBody) harnessBlocked() bool {
	if !b.ResultObserved || !b.IsError {
		return false
	}
	text, ok := resultText(b.Result)
	return ok && strings.HasPrefix(text, harnessBlockedPrefix)
}

// ---------------------------------------------------------------------------
// The telemetry side: internal/gateway/witness.go's own on-disk records.
// ---------------------------------------------------------------------------

// witnessTelemetryRecord mirrors internal/gateway's own telemetryRecord
// exactly, restated for the same reason witnessCallBody is.
type witnessTelemetryRecord struct {
	ToolUseID string    `json:"tool_use_id"`
	ToolName  string    `json:"tool_name"`
	Success   bool      `json:"success"`
	SessionID string    `json:"session_id"`
	Time      time.Time `json:"time"`
}

// telemetryDir is LogDir's own "telemetry" subdirectory — the SAME path
// internal/gateway/witness.go's own TelemetryConfig.Dir resolves to.
func telemetryDir(logDir string) string { return filepath.Join(logDir, "telemetry") }

// witnessTelemetryEntry is one file found under telemetryDir, read cheaply
// (a directory listing's own stat, never a body read — see this file's own
// package doc comment, "Deriving telemetry active since").
type witnessTelemetryEntry struct {
	toolUseID  string
	receivedAt time.Time
}

// listTelemetry reads every telemetry record's own filename and mtime.
// Absent directory (telemetry never active at all) is not an error: it
// answers zero entries, exactly as "no records" would.
func listTelemetry(logDir string) ([]witnessTelemetryEntry, error) {
	entries, err := os.ReadDir(telemetryDir(logDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]witnessTelemetryEntry, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue // a "."-prefixed partial write, mid-rename, or stray file
		}
		toolUseID := strings.TrimSuffix(name, ".json")
		info, ierr := e.Info()
		if ierr != nil {
			continue // gone between the listing and the stat; next cycle sees it
		}
		out = append(out, witnessTelemetryEntry{toolUseID: toolUseID, receivedAt: info.ModTime()})
	}
	return out, nil
}

// telemetryActiveSince reports the earliest entry's own receive time, and
// whether any entry exists at all.
func telemetryActiveSince(entries []witnessTelemetryEntry) (time.Time, bool) {
	var since time.Time
	found := false
	for _, e := range entries {
		if !found || e.receivedAt.Before(since) {
			since = e.receivedAt
			found = true
		}
	}
	return since, found
}

// telemetryExists reports whether a record for toolUseID is on disk right
// now — direction 1's own "matched" check. toolUseID has already passed
// commitpath.IsToolUseID by the time this is called, so it is safe to use
// as a filename.
func telemetryExists(logDir, toolUseID string) bool {
	_, err := os.Stat(filepath.Join(telemetryDir(logDir), toolUseID+".json"))
	return err == nil
}

// readTelemetryRecord reads one telemetry record's own content, for a
// finding's Detail — the only place this pass ever opens a telemetry file
// rather than just stating it.
func readTelemetryRecord(logDir, toolUseID string) (witnessTelemetryRecord, bool) {
	raw, err := os.ReadFile(filepath.Join(telemetryDir(logDir), toolUseID+".json"))
	if err != nil {
		return witnessTelemetryRecord{}, false
	}
	var rec witnessTelemetryRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return witnessTelemetryRecord{}, false
	}
	return rec, true
}

// ---------------------------------------------------------------------------
// The cycle.
// ---------------------------------------------------------------------------

// checkWitness judges every tool_call this cycle can read a tool_use_id
// for (direction 1), then every telemetry record this cycle can read
// (direction 2).
func (r *Reconciler) checkWitness(ctx context.Context, view *ledgerView) WitnessReport {
	report := WitnessReport{Enabled: true}
	cfg := r.cfg.Witness
	now := r.now()

	entries, err := listTelemetry(cfg.LogDir)
	if err != nil {
		// The telemetry directory could not be read (permissions, a
		// mount gone) — this is "we could not tell", never "telemetry is
		// off": treating it as off would let a filesystem fault silence
		// every alert this pass exists to raise. Every call this cycle is
		// therefore Unchecked, and direction 2 finds nothing to compare.
		report.Unchecked += len(view.witness.calls)
		return report
	}
	since, active := telemetryActiveSince(entries)
	report.TelemetryActive = active
	if active {
		report.TelemetrySince = since
	}

	relayed := make(map[string]struct{}, len(view.witness.calls))
	window := cfg.window()

	// First pass: read each call's tool_use_id and whether telemetry
	// corroborates it, and find, per run, when its own harness's telemetry
	// first arrived. Telemetry is a property of the harness that ran a
	// session, not of this machine (#434): a run none of whose calls was
	// ever matched exported nothing, and its absences prove nothing.
	type readCall struct {
		call      witnessCall
		toolUseID string
		tool      string
		matched   bool
		blocked   bool // the harness refused it itself; no telemetry is expected
	}
	var read []readCall
	runSince := map[string]time.Time{}
	runSeen := map[string]bool{}
	for _, call := range view.witness.calls {
		// A call relayed more than a window before telemetry began arriving
		// anywhere can be neither matched nor missed: it is not counted, and
		// its body is not read. The window's slack keeps a call whose
		// telemetry was the first to arrive.
		if active && call.at.Before(since.Add(-window)) {
			continue
		}
		raw, ok := readRunBody(cfg.LogDir, call.runID, call.digest)
		if !ok {
			report.Unchecked++
			continue
		}
		var body witnessCallBody
		if err := json.Unmarshal(raw, &body); err != nil || body.ToolUseID == "" ||
			!commitpath.IsToolUseID(body.ToolUseID) {
			report.Unchecked++
			continue
		}
		report.Checked++
		relayed[body.ToolUseID] = struct{}{}
		runSeen[call.runID] = true
		rc := readCall{call: call, toolUseID: body.ToolUseID, tool: body.Tool,
			blocked: body.harnessBlocked()}
		if telemetryExists(cfg.LogDir, body.ToolUseID) {
			rc.matched = true
			report.Matched++
			if first, ok := runSince[call.runID]; !ok || call.at.Before(first) {
				runSince[call.runID] = call.at
			}
		}
		read = append(read, rc)
	}
	for runID := range runSeen {
		if _, ok := runSince[runID]; !ok {
			report.RunsWithoutTelemetry++
		}
	}

	// Second pass: judge only calls of runs whose harness is proven to
	// export telemetry, made at or after the first call it corroborated.
	for _, rc := range read {
		call := rc.call
		if rc.matched || rc.blocked {
			continue
		}
		if _, already := view.drift.subjects[call.eventID]; already {
			// Already reported in an earlier cycle. Still Checked and still
			// contributes to relayed above; not re-judged.
			continue
		}
		first, proven := runSince[call.runID]
		if !proven || call.at.Before(first) {
			// This run's telemetry was not yet proven when this call was
			// relayed (or never was): an absence here proves nothing, and
			// this call is neither Pending nor Missing.
			continue
		}
		if now.Sub(call.at) < window {
			report.Pending++
			continue
		}

		report.Missing++
		finding := WitnessFinding{
			Kind:            WitnessMissingTelemetry,
			ToolCallEventID: call.eventID,
			ToolUseID:       rc.toolUseID,
			RunID:           call.runID,
			SPIFFEID:        call.spiffeID,
			ToolName:        rc.tool,
			Reason:          reasonNoTelemetryWitness,
			Detail: fmt.Sprintf(
				"tool_call %s (tool_use_id %s) was relayed by the gateway %s ago, past this "+
					"pass's %s window, and no telemetry record for it exists; the harness's own "+
					"OTLP export never corroborated this call",
				call.eventID, rc.toolUseID, now.Sub(call.at).Truncate(time.Second), window),
		}
		r.appendWitnessAlert(ctx, &report, finding)
	}

	for _, e := range entries {
		if _, known := relayed[e.toolUseID]; known {
			continue
		}
		if now.Sub(e.receivedAt) < window {
			// Give the gateway's own asynchronous recording (record.go's
			// recordAsync) time to catch up before calling this an orphan.
			continue
		}
		report.Orphaned++
		rec, _ := readTelemetryRecord(cfg.LogDir, e.toolUseID)
		finding := WitnessFinding{
			Kind:      WitnessOrphanTelemetry,
			ToolUseID: e.toolUseID,
			ToolName:  rec.ToolName,
			Detail: fmt.Sprintf(
				"telemetry named tool_use_id %s, received %s ago, past this pass's %s window, "+
					"and no tool_call this cycle relays that id: the harness reported a tool "+
					"result the gateway never saw. doc 02's ledger_drift_detected has no honest "+
					"subject for this — nothing on the chain claims this tool_use_id — so this "+
					"is reported and never appended",
				e.toolUseID, now.Sub(e.receivedAt).Truncate(time.Second), window),
		}
		report.Findings = append(report.Findings, finding)
		cfg.alert(ctx, finding)
	}

	return report
}

// appendWitnessAlert writes one alert and records what happened.
//
// See this file's own package doc comment, "Sharing a subject space with
// commit watch", for why the returned record's own reason is checked
// against finding.Reason rather than only its event type.
func (r *Reconciler) appendWitnessAlert(
	ctx context.Context, report *WitnessReport, finding WitnessFinding,
) {
	body := event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeLedgerDriftDetected,
		event.FieldSource:         event.SourceReconciler,
		event.FieldIdempotencyKey: LedgerDriftKey(finding.ToolCallEventID),
		event.FieldSubjectEventID: finding.ToolCallEventID,
		event.FieldReason:         finding.Reason,
	}
	if finding.RunID != "" && finding.SPIFFEID != "" {
		body[event.FieldRunID] = finding.RunID
		body[event.FieldSpiffeID] = finding.SPIFFEID
	}
	record, err := r.cfg.Appender.Append(ctx, body)
	switch {
	case err != nil:
		finding.Detail += fmt.Sprintf("; and this alert could not be appended to the chain: %v", err)
	case recordString(record, event.FieldEventType) != event.EventTypeLedgerDriftDetected:
		finding.Detail += fmt.Sprintf("; and the idempotency key %q names a %s rather than this alert",
			recordString(body, event.FieldIdempotencyKey), recordString(record, event.FieldEventType))
	case recordString(record, event.FieldReason) != finding.Reason:
		// The idempotency key resolved to an event ALREADY appended by a
		// different check sharing this subject (commitwatch.go's own) —
		// this cycle's own witness finding is not new, and nothing further
		// was written.
		finding.Detail += fmt.Sprintf(
			"; this tool_call already carries a ledger_drift_detected from a different check "+
				"(reason %q); not a new witness alert", recordString(record, event.FieldReason))
	default:
		finding.AppendedEventID = recordString(record, event.FieldEventID)
	}
	report.Findings = append(report.Findings, finding)
	if finding.AppendedEventID != "" {
		report.Appended = append(report.Appended, finding.AppendedEventID)
	}
	r.cfg.Witness.alert(ctx, finding)
}

// defaultWitnessAlert is the sink a deployment gets if it names none.
// Error level, unconditionally — the same standing every other alert-level
// default in this package holds.
func defaultWitnessAlert(ctx context.Context, finding WitnessFinding) {
	slog.ErrorContext(ctx, "telemetry witness: a tool call and the harness's own telemetry disagree",
		"kind", string(finding.Kind),
		"tool_call_event_id", finding.ToolCallEventID,
		"tool_use_id", finding.ToolUseID,
		"run_id", finding.RunID,
		"appended_event_id", finding.AppendedEventID,
		"detail", finding.Detail)
}
