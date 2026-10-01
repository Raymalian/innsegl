// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// Unit coverage for recordbuild.go's pure folds — status derivation, the
// brief/replies fold, and the run-facts fold — none of which need a real
// Postgres: they operate on recordEventRow slices this package already
// builds from a real chain in RPG-001.

func mkRow(eventType string, ts time.Time, body map[string]any) recordEventRow {
	return recordEventRow{EventType: eventType, TS: ts, Source: event.SourceMCP, Body: body}
}

func TestStatusAndAtActive(t *testing.T) {
	facts := ledger.RunFacts{RegisteredAt: time.Now()}
	status, at := statusAndAt(facts, time.Time{}, false, time.Now(), 0)
	if status != ledger.RunActive {
		t.Errorf("status = %q, want active", status)
	}
	if at != nil {
		t.Errorf("StatusAt = %v, want nil for an active run", at)
	}
}

func TestStatusAndAtRetired(t *testing.T) {
	retiredAt := time.Date(2026, 9, 30, 14, 31, 58, 0, time.UTC)
	facts := ledger.RunFacts{Retired: true, RetiredAt: retiredAt}
	status, at := statusAndAt(facts, retiredAt, true, time.Now(), 0)
	if status != ledger.RunRetired {
		t.Errorf("status = %q, want retired", status)
	}
	if at == nil || !at.Equal(retiredAt) {
		t.Errorf("StatusAt = %v, want %v", at, retiredAt)
	}
}

func TestStatusAndAtLapsedAndAbandoned(t *testing.T) {
	withdrawnAt := time.Now().Add(-time.Hour)
	facts := ledger.RunFacts{WithdrawnAt: withdrawnAt}
	now := time.Now()

	status, at := statusAndAt(facts, time.Time{}, false, now, 24*time.Hour)
	if status != ledger.RunLapsed {
		t.Errorf("status = %q, want lapsed (inside the horizon)", status)
	}
	if at == nil || !at.Equal(withdrawnAt) {
		t.Errorf("StatusAt = %v, want %v", at, withdrawnAt)
	}

	status, at = statusAndAt(facts, time.Time{}, false, now, time.Nanosecond)
	if status != ledger.RunAbandoned {
		t.Errorf("status = %q, want abandoned (past a near-zero horizon)", status)
	}
	if at == nil || !at.Equal(withdrawnAt) {
		t.Errorf("StatusAt = %v, want %v", at, withdrawnAt)
	}
}

func TestRunFactsFromRowsFoldsTheFourFacts(t *testing.T) {
	t0 := time.Date(2026, 9, 30, 14, 30, 0, 0, time.UTC)
	rows := []recordEventRow{
		mkRow(event.EventTypeRunRegistered, t0, nil),
		mkRow(event.EventTypeToolCall, t0.Add(time.Minute), nil),
		mkRow(event.EventTypeRunExpired, t0.Add(2*time.Minute), nil),
	}
	// The reaper's own run_expired must not count as activity.
	rows[2].Source = event.SourceReaper

	facts := runFactsFromRows(rows)
	if !facts.RegisteredAt.Equal(t0) {
		t.Errorf("RegisteredAt = %v, want %v", facts.RegisteredAt, t0)
	}
	if !facts.WithdrawnAt.Equal(t0.Add(2 * time.Minute)) {
		t.Errorf("WithdrawnAt = %v, want %v", facts.WithdrawnAt, t0.Add(2*time.Minute))
	}
	if !facts.LastActivityAt.Equal(t0.Add(time.Minute)) {
		t.Errorf("LastActivityAt = %v, want the tool_call instant, not the reaper's own withdrawal", facts.LastActivityAt)
	}
	if facts.Retired {
		t.Error("Retired = true, but no run_retired was folded in")
	}
}

func TestRunFactsFromRowsEarliestRetirement(t *testing.T) {
	early := time.Date(2026, 9, 30, 14, 0, 0, 0, time.UTC)
	late := early.Add(time.Hour)
	rows := []recordEventRow{
		mkRow(event.EventTypeRunRetired, late, nil),
		mkRow(event.EventTypeRunRetired, early, nil),
	}
	facts := runFactsFromRows(rows)
	if !facts.Retired {
		t.Fatal("Retired = false")
	}
	if !facts.RetiredAt.Equal(early) {
		t.Errorf("RetiredAt = %v, want the EARLIEST retirement %v", facts.RetiredAt, early)
	}
}

func TestRetiredAtOf(t *testing.T) {
	if _, found := retiredAtOf(nil); found {
		t.Error("retiredAtOf(nil) should answer not found")
	}
	early := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	late := early.Add(time.Hour)
	rows := []recordEventRow{
		mkRow(event.EventTypeRunRetired, late, nil),
		mkRow(event.EventTypeRunRetired, early, nil),
	}
	at, found := retiredAtOf(rows)
	if !found || !at.Equal(early) {
		t.Errorf("retiredAtOf = %v, %v; want %v, true", at, found, early)
	}
}

func TestBriefAndRepliesFoldsRolesUnconfigured(t *testing.T) {
	t0 := time.Date(2026, 9, 30, 14, 30, 0, 0, time.UTC)
	rows := []recordEventRow{
		mkRow(event.EventTypeAgentMessage, t0, map[string]any{
			event.FieldRole: "brief", event.FieldPayloadDigest: "hmac-sha256:k:" + hex64(t, "brief"),
		}),
		mkRow(event.EventTypeAgentMessage, t0.Add(time.Minute), map[string]any{
			event.FieldRole: "assistant", event.FieldPayloadDigest: "hmac-sha256:k:" + hex64(t, "reply1"),
		}),
		mkRow(event.EventTypeAgentMessage, t0.Add(2*time.Minute), map[string]any{
			event.FieldRole: "assistant", event.FieldPayloadDigest: "hmac-sha256:k:" + hex64(t, "reply2"),
		}),
		mkRow(event.EventTypeToolCall, t0.Add(3*time.Minute), map[string]any{}),
	}
	// messageKeyDir == "" — the "unset means off" case: never verified,
	// whatever the candidates.
	brief, replies := briefAndReplies(rows, "", nil)
	if brief.Digest != "hmac-sha256:k:"+hex64(t, "brief") {
		t.Errorf("Brief.Digest = %q", brief.Digest)
	}
	if brief.Available || brief.Text != "" {
		t.Errorf("Brief = %+v, want Available false and Text empty — no -message-key-dir configured", brief)
	}
	if len(replies) != 2 {
		t.Fatalf("got %d replies, want 2", len(replies))
	}
	if replies[0].Digest != "hmac-sha256:k:"+hex64(t, "reply1") || replies[1].Digest != "hmac-sha256:k:"+hex64(t, "reply2") {
		t.Errorf("replies out of order: %+v", replies)
	}
}

func TestBriefAndRepliesVerifiesWithAConfiguredKey(t *testing.T) {
	dir := t.TempDir()
	const keyID = "gateway-v1"
	const key = "the-derived-key"
	writeTestMessageKey(t, dir, keyID, key)

	briefText := "add a health endpoint"
	replyText := "done"
	t0 := time.Date(2026, 9, 30, 14, 30, 0, 0, time.UTC)
	rows := []recordEventRow{
		mkRow(event.EventTypeAgentMessage, t0, map[string]any{
			event.FieldRole: "brief", event.FieldPayloadDigest: realKeyedDigest(key, keyID, []byte(briefText)),
		}),
		mkRow(event.EventTypeAgentMessage, t0.Add(time.Minute), map[string]any{
			event.FieldRole: "assistant", event.FieldPayloadDigest: realKeyedDigest(key, keyID, []byte(replyText)),
		}),
	}
	candidates := [][]byte{[]byte(briefText), []byte(replyText), []byte(`{"tool":"Bash"}`)}

	brief, replies := briefAndReplies(rows, dir, candidates)
	if !brief.Available || brief.Text != briefText {
		t.Errorf("Brief = %+v, want Available=true Text=%q", brief, briefText)
	}
	if len(replies) != 1 || !replies[0].Available || replies[0].Text != replyText {
		t.Errorf("Replies = %+v, want one Available=true Text=%q", replies, replyText)
	}
}

func TestBriefAndRepliesUnmatchedStaysUnavailableEvenWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	const keyID = "gateway-v1"
	writeTestMessageKey(t, dir, keyID, "the-derived-key")

	rows := []recordEventRow{
		mkRow(event.EventTypeAgentMessage, time.Now(), map[string]any{
			event.FieldRole: "brief", event.FieldPayloadDigest: realKeyedDigest("the-derived-key", keyID, []byte("the real brief")),
		}),
	}
	// No candidate body produces this digest.
	brief, _ := briefAndReplies(rows, dir, [][]byte{[]byte("something else entirely")})
	if brief.Available || brief.Text != "" {
		t.Errorf("Brief = %+v, want unavailable — never guessed", brief)
	}
}

func TestBriefAndRepliesNoAgentMessagesAtAll(t *testing.T) {
	brief, replies := briefAndReplies([]recordEventRow{mkRow(event.EventTypeToolCall, time.Now(), nil)}, "", nil)
	if brief.Digest != "" || brief.Available {
		t.Errorf("Brief = %+v, want the zero value", brief)
	}
	if replies != nil {
		t.Errorf("Replies = %+v, want nil", replies)
	}
}

// ---------------------------------------------------------------------------
// outcomeOf and summaryOf edge cases not already exercised by RPG-001/006.
// ---------------------------------------------------------------------------

func TestOutcomeOfNonBashNeverCarriesAnExitCode(t *testing.T) {
	out := outcomeOf("Write", gatewayBody{ResultObserved: true, IsError: false})
	if out.Kind != "ok" || out.ExitCode != nil {
		t.Errorf("outcomeOf(Write, ok) = %+v, want Kind=ok ExitCode=nil", out)
	}
	out = outcomeOf("Write", gatewayBody{ResultObserved: true, IsError: true})
	if out.Kind != "error" || out.ExitCode != nil {
		t.Errorf("outcomeOf(Write, error) = %+v, want Kind=error ExitCode=nil", out)
	}
}

func TestOutcomeOfBashSuccessIsExitZero(t *testing.T) {
	out := outcomeOf("Bash", gatewayBody{ResultObserved: true, IsError: false})
	if out.Kind != "ok" || out.ExitCode == nil || *out.ExitCode != 0 {
		t.Errorf("outcomeOf(Bash, ok) = %+v, want ExitCode=0", out)
	}
}

func TestOutcomeOfBashErrorWithNoExplicitCodeDefaultsToOne(t *testing.T) {
	out := outcomeOf("Bash", gatewayBody{
		ResultObserved: true, IsError: true, Result: json.RawMessage(`"permission denied"`),
	})
	if out.Kind != "error" || out.ExitCode == nil || *out.ExitCode != 1 {
		t.Errorf("outcomeOf = %+v, want the documented default of 1", out)
	}
}

func TestOutcomeOfUnknownWhenNoResultWasObserved(t *testing.T) {
	out := outcomeOf("Bash", gatewayBody{ResultObserved: false})
	if out.Kind != "unknown" {
		t.Errorf("outcomeOf(no result) = %+v, want unknown", out)
	}
}

// RM-273 (#436): a hook-shape body carries its outcome pre-computed
// (hookOutcomeOf, at mapping time — recordbody.go's hookBodyAsGateway); for
// such a body outcomeOf must read that back rather than fold
// ResultObserved/IsError, which a hook-shape body never sets at all. This
// is the one branch distinguishing the two paths; everything above and
// below it in this file exercises the gateway path exactly as before.
func TestOutcomeOfReadsThePrecomputedHookOutcomeWhenHookShape(t *testing.T) {
	// hookShape/hookOutcome are unexported, so this test reaches them the
	// same way stepBody does: through hookBodyAsGateway. ResultObserved and
	// IsError are left at their zero value, exactly as a real hook-shape
	// body leaves them — if outcomeOf read those instead of hookOutcome, it
	// would answer "unknown" here, not "error".
	body := hookBodyAsGateway(hookBody{ToolName: "Bash", ToolResponse: json.RawMessage(`{"interrupted":true}`)})
	out := outcomeOf("Bash", body)
	if out.Kind != "error" || out.ExitCode != nil {
		t.Errorf("outcomeOf(hook-shape, interrupted) = %+v, want Kind=error and no exit code", out)
	}
}

func TestSummaryOfEachToolShape(t *testing.T) {
	if s := summaryOf("Bash", gatewayBody{Input: json.RawMessage(`{"command":"echo hi"}`)}); s != "echo hi" {
		t.Errorf("summaryOf(Bash) = %q", s)
	}
	if s := summaryOf("Write", gatewayBody{Input: json.RawMessage(`{"file_path":"a.txt"}`)}); s != "a.txt" {
		t.Errorf("summaryOf(Write) = %q", s)
	}
	if s := summaryOf("Agent", gatewayBody{Input: json.RawMessage(`{"prompt":"do it"}`)}); s != "do it" {
		t.Errorf("summaryOf(Agent) = %q", s)
	}
	if s := summaryOf("Bash", gatewayBody{Input: json.RawMessage(`not json`)}); s != "" {
		t.Errorf("summaryOf(malformed) = %q, want empty", s)
	}
}

func TestTruncateSummaryLeavesShortTextAlone(t *testing.T) {
	short := "a short command"
	if got := truncateSummary(short); got != short {
		t.Errorf("truncateSummary(short) = %q, want unchanged", got)
	}
	long := ""
	for i := 0; i < 200; i++ {
		long += "x"
	}
	got := truncateSummary(long)
	if got == long {
		t.Error("a long summary should be truncated")
	}
	r := []rune(got)
	if len(r) == 0 || r[len(r)-1] != '…' {
		t.Errorf("truncated summary should end with an ellipsis: %q", got)
	}
}
