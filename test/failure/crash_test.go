// SPDX-License-Identifier: Apache-2.0

package failure

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/spire"
)

// MCP-011 — doc 07: "kill -9 the server at fuzzed points during each tool;
// restart; replay same request → Original result returned; no duplicate
// identity/event/commit; invariants hold post-reconcile" (IP §6.6).
//
// WHAT "REPLAY RETURNS THE ORIGINAL RESULT" MEANS PER TOOL, AND WHY IT IS NOT
// ONE SENTENCE
// ---------------------------------------------------------------------------
// IP §6.6 opens with "Every tool call is idempotent via required
// `idempotency_key`", and ADR-0004 fixes which calls that is: a key is
// required if and only if IP §4's signature carries one. Two of the four tools
// that exist carry one and two do not, so the sentence lands differently on
// each, and this file asserts the difference rather than averaging over it.
//
//	register_agent  keyed.   The reply is recorded (ADR-0017) and a replay
//	                         returns those bytes. Exactly one SPIRE entry and
//	                         exactly one `run_registered`, whatever the kill
//	                         interrupted.
//	record_event    keyed.   Same, for `tool_call`.
//	retire_agent    NO key.  ADR-0004: "idempotency is intrinsic to run_id".
//	                         IP §4: retiring a retired run returns the ORIGINAL
//	                         timestamp, and that is what a replay must return —
//	                         read back off the chain, which is the only durable
//	                         record of when it happened.
//	get_credential  NO key,  and it must NOT be deduplicated. ADR-0004: "IP
//	                         §6.2 requires transparent re-fetch when an SVID
//	                         expires, so a repeat call is a legitimate second
//	                         issuance rather than a retry of the first. Each
//	                         issuance is a distinct auditable fact." So a
//	                         replay here returns a FRESH credential, by design,
//	                         and the properties MCP-011 can hold it to are the
//	                         other two: no second identity, and exactly one
//	                         `credential_issued` per call that reached the
//	                         append — never one per crash.
//	sign_commit     RM-033 (#41). Does not exist; deferred, and measured as
//	                         absent rather than assumed.
//
// "no duplicate commit" is therefore unproven by this file and stays unproven
// until sign_commit ships.
func TestMCP011CrashAndReplayUnderFuzzedKillTiming(t *testing.T) {
	c := requireCrashCampaign(t)

	t.Run("register_agent", c.registerAgent)
	t.Run("record_event", c.recordEvent)
	t.Run("retire_agent", c.retireAgent)
	t.Run("get_credential", c.getCredential)
	t.Run("sign_commit", c.signCommit)

	t.Run("every named kill window was reached", c.census)
	t.Run("the chain verifies", c.verifyChain)
	t.Run("SPIRE holds exactly the identities the campaign asked for", c.entryCensus)
	t.Run("the reconciler finds no drift", c.reconcile)
}

// ---------------------------------------------------------------------------
// register_agent.
// ---------------------------------------------------------------------------

func (c *campaign) registerArgs(key string) map[string]any {
	return map[string]any{
		"agent_type": crashAgentType, "task_id": crashTaskID, "idempotency_key": key,
	}
}

func (c *campaign) registerAgent(t *testing.T) {
	// Calibration. The blind campaign's window is this deployment's measured
	// call duration, not a number somebody typed: a fixed window would be too
	// wide on a fast machine (most kills landing after the reply) and too
	// narrow on a slow one (most landing before anything).
	warm, took := c.callSucceeds(t, mcp.ToolRegisterAgent, c.registerArgs(c.name("reg-warm")))
	var warmReply registerReply
	decodeInto(t, warm, &warmReply)
	c.live(warmReply.SPIFFEID)
	window := took * 5 / 4
	t.Logf("register_agent completes uninterrupted in %s; blind kills are drawn from [0, %s) "+
		"across %d strata, seed %d", took, window, c.blind, c.seed)

	for i, delay := range c.strata(window, c.blind) {
		t.Logf("blind stratum %d/%d: kill %s after dispatch → %s",
			i+1, c.blind, delay,
			c.registerShot(t, fmt.Sprintf("blind stratum %d, +%s", i+1, delay), "", delay))
	}

	for _, target := range []string{winEventNoEntry, winEntryNoReply, winReplyUnseen} {
		c.aim(t, target, func(t *testing.T) string {
			return c.registerShot(t, "observed trigger for "+target, target, 0)
		})
	}
}

// registerShot runs one crash-and-replay of register_agent and returns the
// window the kill actually landed in — read out of Postgres and SPIRE, never
// inferred from the delay.
func (c *campaign) registerShot(t *testing.T, why, target string, delay time.Duration) string {
	t.Helper()
	key := c.name("reg-key")
	args := c.registerArgs(key)

	when := killWhen{label: why, after: delay}
	switch target {
	case "":
	case winEventNoEntry:
		// The window is a whole SPIRE round trip wide, so the poll wins it.
		when.trigger = c.eventKeyed(key)
	case winEntryNoReply:
		// One Postgres round trip wide: held open with the row lock rather
		// than chased.
		trigger, release := c.parkedOnTheReply(t, key)
		when.trigger, when.release = trigger, release
		defer release()
	case winReplyUnseen:
		when.trigger, when.hold = c.replyRecorded(key), true
	default:
		t.Fatalf("register_agent has no trigger for %q", target)
	}

	s := c.fire(t, mcp.ToolRegisterAgent, args, when)
	if when.trigger != nil && !s.triggerFired {
		t.Fatalf("%s: the state to interrupt never appeared within %s (seed %d)",
			why, crashTriggerBudget, c.seed)
	}

	// --- what the SIGKILL actually left behind -----------------------------
	rec, claimed := c.idemRecord(t, key)
	before, appended := c.eventByKey(t, key)
	runID := ""
	if appended {
		id, ok := before[event.FieldRunID].(string)
		if !ok {
			t.Fatalf("%s: the run_registered under key %q carries a non-string run_id", why, key)
		}
		runID = id
		if runID == "" {
			t.Fatalf("%s: the run_registered under key %q carries no run_id", why, key)
		}
		// Remembered here and not only after the replay: an iteration that
		// fails on a later assertion still created this identity, and the
		// datastore census must account for it rather than report it as an
		// entry nobody asked for.
		c.live(c.spiffeIDOf(t, runID))
	}
	entry := runID != "" && c.hasEntry(t, crashRunRef(runID))

	window := ""
	switch {
	case !claimed && appended:
		t.Fatalf("%s: `run_registered` is on the chain under key %q and the idempotency store "+
			"holds no claim for it. The claim is written before the tool body runs (ADR-0017 §2), "+
			"so this ordering cannot happen and something other than the crash produced it. (seed %d)",
			why, key, c.seed)
	case !claimed:
		window = winBeforeClaim
	case rec.Status == crashInProgress && !appended:
		window = winClaimedNoWork
	case rec.Status == crashInProgress && !entry:
		window = winEventNoEntry
	case rec.Status == crashInProgress:
		window = winEntryNoReply
	case rec.Status != crashCompleted:
		t.Fatalf("%s: the idempotency row for %q is in state %q, which the store has no name for",
			why, key, rec.Status)
	case !appended:
		t.Fatalf("%s: a reply is recorded for key %q and no `run_registered` is on the chain. "+
			"I3 admits no action without a record, and the append precedes the entry and the "+
			"reply (ADR-0018). (seed %d)", why, key, c.seed)
	case !entry:
		t.Fatalf("%s: a reply is recorded for key %q and SPIRE holds no entry for run %q. "+
			"The reply is recorded only after RegisterRun returned. (seed %d)", why, key, runID, c.seed)
	case s.delivered == nil:
		window = winReplyUnseen
	default:
		window = winReplySeen
	}
	c.landed(target, window)

	// --- restart, and replay the same request ------------------------------
	first, second := c.replay(t, mcp.ToolRegisterAgent, args)
	c.sameReply(t, why, "two replays of one request", first, second)

	if claimed && rec.Status == crashCompleted {
		// The reply was recorded before the kill, so IP §6.6's "returns the
		// original result" is a claim about THOSE BYTES.
		c.requireOriginalReply(t, why, first, rec.Response)
	}
	if s.delivered != nil {
		c.sameReply(t, why, "the reply the caller had before the crash and the replay", s.delivered, first)
	}

	var reply registerReply
	decodeInto(t, first, &reply)
	if runID != "" && reply.RunID != runID {
		t.Fatalf("%s: the crashed execution registered run %q and the replay named %q. "+
			"The run id is derived from the request so that a second execution asks SPIRE for "+
			"the identity that already exists (ADR-0017 §5). (seed %d)", why, runID, reply.RunID, c.seed)
	}

	records := c.chain(t)
	if n := countEvents(records, event.EventTypeRunRegistered, reply.RunID); n != 1 {
		t.Fatalf("%s: the chain holds %d `run_registered` events for run %q, want exactly 1. "+
			"IP §6.6: never a second identity, second event, or second commit. (seed %d)",
			why, n, reply.RunID, c.seed)
	}
	if n := countKeyed(records, key); n != 1 {
		t.Fatalf("%s: %d events carry idempotency_key %q, want exactly 1 (LED-008). (seed %d)",
			why, n, key, c.seed)
	}
	// hasEntry goes through the shipped LookupRun, which refuses to pick a
	// favourite when SPIRE holds more than one entry for a run: a second
	// identity is an error here, not a silent true.
	if !c.hasEntry(t, crashRunRef(reply.RunID)) {
		t.Fatalf("%s: SPIRE holds no entry for run %q after the replay (seed %d)", why, reply.RunID, c.seed)
	}
	c.verifyChainNow(t, records)
	c.live(reply.SPIFFEID)
	return window
}

// ---------------------------------------------------------------------------
// record_event.
// ---------------------------------------------------------------------------

func (c *campaign) recordEvent(t *testing.T) {
	run := c.freshRun(t, "rec")
	recordArgs := func(key string) map[string]any {
		return map[string]any{
			"run_id":          run.RunID,
			"event_type":      "shell.exec",
			"payload_digest":  event.Digest([]byte(key)),
			"idempotency_key": key,
		}
	}

	_, took := c.callSucceeds(t, mcp.ToolRecordEvent, recordArgs(c.name("rec-warm")))
	window := took * 5 / 4
	t.Logf("record_event completes uninterrupted in %s; blind kills are drawn from [0, %s) "+
		"across %d strata, seed %d", took, window, c.blind, c.seed)

	for i, delay := range c.strata(window, c.blind) {
		t.Logf("blind stratum %d/%d: kill %s after dispatch → %s", i+1, c.blind, delay,
			c.recordShot(t, fmt.Sprintf("blind stratum %d, +%s", i+1, delay), "", delay, run.RunID, recordArgs))
	}
	for _, target := range []string{winRecEventNoReply, winReplyUnseen} {
		c.aim(t, target, func(t *testing.T) string {
			return c.recordShot(t, "observed trigger for "+target, target, 0, run.RunID, recordArgs)
		})
	}
}

func (c *campaign) recordShot(t *testing.T, why, target string, delay time.Duration,
	runID string, argsFor func(string) map[string]any,
) string {
	t.Helper()
	key := c.name("rec-key")
	args := argsFor(key)

	when := killWhen{label: why, after: delay}
	switch target {
	case "":
	case winRecEventNoReply:
		trigger, release := c.parkedOnTheReply(t, key)
		when.trigger, when.release = trigger, release
		defer release()
	case winReplyUnseen:
		when.trigger, when.hold = c.replyRecorded(key), true
	default:
		t.Fatalf("record_event has no trigger for %q", target)
	}

	s := c.fire(t, mcp.ToolRecordEvent, args, when)
	if when.trigger != nil && !s.triggerFired {
		t.Fatalf("%s: the state to interrupt never appeared within %s (seed %d)",
			why, crashTriggerBudget, c.seed)
	}

	rec, claimed := c.idemRecord(t, key)
	_, appended := c.eventByKey(t, key)

	window := ""
	switch {
	case !claimed && appended:
		t.Fatalf("%s: `tool_call` is on the chain under key %q with no claim recorded for it "+
			"(ADR-0017 §2 writes the claim first). (seed %d)", why, key, c.seed)
	case !claimed:
		window = winBeforeClaim
	case rec.Status == crashInProgress && !appended:
		window = winClaimedNoWork
	case rec.Status == crashInProgress:
		window = winRecEventNoReply
	case rec.Status != crashCompleted:
		t.Fatalf("%s: the idempotency row for %q is in state %q", why, key, rec.Status)
	case !appended:
		t.Fatalf("%s: a reply is recorded for key %q and no `tool_call` is on the chain (I3). (seed %d)",
			why, key, c.seed)
	case s.delivered == nil:
		window = winReplyUnseen
	default:
		window = winReplySeen
	}
	c.landed(target, window)

	first, second := c.replay(t, mcp.ToolRecordEvent, args)
	c.sameReply(t, why, "two replays of one request", first, second)
	if claimed && rec.Status == crashCompleted {
		c.requireOriginalReply(t, why, first, rec.Response)
	}
	if s.delivered != nil {
		c.sameReply(t, why, "the reply the caller had before the crash and the replay", s.delivered, first)
	}

	var reply recordReply
	decodeInto(t, first, &reply)
	if reply.EventID == "" || reply.ChainPosition <= 0 {
		t.Fatalf("%s: record_event replied %+v; IP §4 requires both members", why, reply)
	}

	records := c.chain(t)
	if n := countKeyed(records, key); n != 1 {
		t.Fatalf("%s: %d events carry idempotency_key %q, want exactly 1. "+
			"IP §6.6: never a second event. (seed %d)", why, n, key, c.seed)
	}
	if n := countEventsAt(records, reply.ChainPosition, event.EventTypeToolCall, runID); n != 1 {
		t.Fatalf("%s: the reply names chain_position %d and %d `tool_call` events for run %q "+
			"sit there (seed %d)", why, reply.ChainPosition, n, runID, c.seed)
	}
	c.verifyChainNow(t, records)
	return window
}

// ---------------------------------------------------------------------------
// retire_agent. No idempotency_key, by ADR-0004: idempotency is intrinsic to
// run_id, so a fresh run is registered for every shot.
// ---------------------------------------------------------------------------

func (c *campaign) retireAgent(t *testing.T) {
	warmRun := c.freshRun(t, "ret-warm")
	_, took := c.callSucceeds(t, mcp.ToolRetireAgent, map[string]any{"run_id": warmRun.RunID})
	c.gone(warmRun.SPIFFEID)
	window := took * 5 / 4
	t.Logf("retire_agent completes uninterrupted in %s; blind kills are drawn from [0, %s) "+
		"across %d strata, seed %d", took, window, c.blind, c.seed)

	for i, delay := range c.strata(window, c.blind) {
		t.Logf("blind stratum %d/%d: kill %s after dispatch → %s", i+1, c.blind, delay,
			c.retireShot(t, fmt.Sprintf("blind stratum %d, +%s", i+1, delay), "", delay))
	}
	c.aim(t, winRetireNoDelete, func(t *testing.T) string {
		return c.retireShot(t, "observed trigger for "+winRetireNoDelete, winRetireNoDelete, 0)
	})
}

func (c *campaign) retireShot(t *testing.T, why, target string, delay time.Duration) string {
	t.Helper()
	run := c.freshRun(t, "ret")
	args := map[string]any{"run_id": run.RunID}
	from := c.headPosition(t)

	when := killWhen{label: why, after: delay}
	if target == winRetireNoDelete {
		when.trigger = c.eventAppendedAfter(from, event.EventTypeRunRetired, run.RunID)
	} else if target != "" {
		t.Fatalf("retire_agent has no trigger for %q", target)
	}

	s := c.fire(t, mcp.ToolRetireAgent, args, when)
	if when.trigger != nil && !s.triggerFired {
		t.Fatalf("%s: `run_retired` for %q never appeared within %s (seed %d)",
			why, run.RunID, crashTriggerBudget, c.seed)
	}

	records := c.chain(t)
	retired := countEvents(records, event.EventTypeRunRetired, run.RunID)
	entry := c.hasEntry(t, crashRunRef(run.RunID))

	window := ""
	switch {
	case retired > 1:
		t.Fatalf("%s: the chain holds %d `run_retired` events for run %q after ONE call. "+
			"A run retires once (ADR-0004). (seed %d)", why, retired, run.RunID, c.seed)
	case retired == 0 && !entry:
		t.Fatalf("%s: run %q has no `run_retired` on the chain and SPIRE holds no entry for it. "+
			"ADR-0020 records before it deletes, so an identity cannot go without the record "+
			"going first. I3. (seed %d)", why, run.RunID, c.seed)
	case retired == 0:
		window = winRetireNoRecord
	case entry:
		window = winRetireNoDelete
	case s.delivered == nil:
		window = winRetireNoReply
	default:
		window = winRetireSeen
	}
	c.landed(target, window)

	first, second := c.replay(t, mcp.ToolRetireAgent, args)
	c.sameReply(t, why, "two replays of one retirement", first, second)
	if s.delivered != nil {
		c.sameReply(t, why, "the reply the caller had before the crash and the replay", s.delivered, first)
	}

	var reply retireReply
	decodeInto(t, first, &reply)
	records = c.chain(t)
	if n := countEvents(records, event.EventTypeRunRetired, run.RunID); n != 1 {
		t.Fatalf("%s: the chain holds %d `run_retired` events for run %q after the replay, want 1. "+
			"IP §6.6: never a second event. (seed %d)", why, n, run.RunID, c.seed)
	}
	// IP §4: "retiring a retired run returns success with the original
	// timestamp", and the ledger is the only durable record of what that was.
	recorded := c.retiredAt(t, records, run.RunID)
	if reply.RetiredAt != recorded {
		t.Fatalf("%s: the replay answered retired_at %q; the `run_retired` on the chain carries "+
			"ts %q. IP §4 requires the ORIGINAL instant. (seed %d)",
			why, reply.RetiredAt, recorded, c.seed)
	}
	if c.hasEntry(t, crashRunRef(run.RunID)) {
		t.Fatalf("%s: SPIRE still holds an entry for retired run %q after the replay; "+
			"retirement is effective immediately (IP §6.2). (seed %d)", why, run.RunID, c.seed)
	}
	c.verifyChainNow(t, records)
	c.gone(run.SPIFFEID)
	return window
}

// ---------------------------------------------------------------------------
// get_credential. No idempotency_key and — ADR-0004 — it must NOT be
// deduplicated, so what a replay owes the caller is a working credential for
// the same identity, not the original token.
// ---------------------------------------------------------------------------

func (c *campaign) getCredential(t *testing.T) {
	run := c.freshRun(t, "cred")
	args := map[string]any{"run_id": run.RunID, "audience": mcp.AudienceSigstore}

	warm, took := c.callSucceeds(t, mcp.ToolGetCredential, args)
	c.requireCredentialFor(t, "the uninterrupted control", warm, run.SPIFFEID)
	window := took * 5 / 4
	t.Logf("get_credential completes uninterrupted in %s; blind kills are drawn from [0, %s) "+
		"across %d strata, seed %d", took, window, c.blind, c.seed)

	for i, delay := range c.strata(window, c.blind) {
		t.Logf("blind stratum %d/%d: kill %s after dispatch → %s", i+1, c.blind, delay,
			c.credentialShot(t, fmt.Sprintf("blind stratum %d, +%s", i+1, delay), "", delay, run))
	}
	c.aim(t, winCredNoReply, func(t *testing.T) string {
		return c.credentialShot(t, "observed trigger for "+winCredNoReply, winCredNoReply, 0, run)
	})
}

func (c *campaign) credentialShot(t *testing.T, why, target string, delay time.Duration, run registerReply) string {
	t.Helper()
	args := map[string]any{"run_id": run.RunID, "audience": mcp.AudienceSigstore}
	from := c.headPosition(t)
	issuedBefore := countEvents(c.chain(t), event.EventTypeCredentialIssued, run.RunID)

	when := killWhen{label: why, after: delay}
	if target == winCredNoReply {
		when.trigger = c.eventAppendedAfter(from, event.EventTypeCredentialIssued, run.RunID)
		when.hold = true
	} else if target != "" {
		t.Fatalf("get_credential has no trigger for %q", target)
	}

	s := c.fire(t, mcp.ToolGetCredential, args, when)
	if when.trigger != nil && !s.triggerFired {
		t.Fatalf("%s: `credential_issued` for %q never appeared within %s (seed %d)",
			why, run.RunID, crashTriggerBudget, c.seed)
	}

	records := c.chain(t)
	issuedAfter := countEvents(records, event.EventTypeCredentialIssued, run.RunID)
	delta := issuedAfter - issuedBefore

	window := ""
	switch {
	case delta > 1:
		t.Fatalf("%s: one get_credential call left %d `credential_issued` events on the chain. "+
			"IP §6.6: never a second event. (seed %d)", why, delta, c.seed)
	case delta == 0 && s.delivered != nil:
		t.Fatalf("%s: a credential was released and no `credential_issued` is on the chain. "+
			"I3, and get_credential records BEFORE it returns the token. (seed %d)", why, c.seed)
	case delta == 0:
		window = winCredNoRecord
	case s.delivered == nil:
		window = winCredNoReply
	default:
		window = winCredSeen
	}
	c.landed(target, window)

	// A replay mints a fresh credential, on purpose (ADR-0004). What must hold
	// is that it is this run's, that the identity did not multiply, and that
	// the chain gained exactly one record per call that reached the append.
	first, second := c.replay(t, mcp.ToolGetCredential, args)
	c.requireCredentialFor(t, why+": first replay", first, run.SPIFFEID)
	c.requireCredentialFor(t, why+": second replay", second, run.SPIFFEID)

	records = c.chain(t)
	if got, want := countEvents(records, event.EventTypeCredentialIssued, run.RunID), issuedBefore+delta+2; got != want {
		t.Fatalf("%s: the chain holds %d `credential_issued` events for run %q and %d calls "+
			"reached the append. Each issuance is one auditable fact and no more (ADR-0004). (seed %d)",
			why, got, run.RunID, want, c.seed)
	}
	if !c.hasEntry(t, crashRunRef(run.RunID)) {
		t.Fatalf("%s: SPIRE holds no entry for run %q after the replay (seed %d)", why, run.RunID, c.seed)
	}
	c.verifyChainNow(t, records)
	return window
}

// requireCredentialFor checks the reply is a credential for this run.
//
// The token's `sub` is read WITHOUT verifying its signature — that is the
// verifier's job (RM-037) and Fulcio's, and this file does not pretend to do
// it. What it does prove is that the identity the MCP released a token for
// after a crash is the identity the run had before it: no second identity.
func (c *campaign) requireCredentialFor(t *testing.T, why string, reply any, spiffeID string) {
	t.Helper()
	var out credentialReply
	decodeInto(t, reply, &out)
	if out.JWTSVID == "" || out.ExpiresAt == "" {
		t.Fatalf("%s: get_credential replied %+v; IP §4 requires both members", why, out)
	}
	sub, err := jwtSubject(out.JWTSVID)
	if err != nil {
		t.Fatalf("%s: reading the JWT-SVID's subject: %v", why, err)
	}
	if sub != spiffeID {
		t.Fatalf("%s: the credential names %q and the run is %q; a credential belongs to one "+
			"run (I2, IP §6.2). (seed %d)", why, sub, spiffeID, c.seed)
	}
}

// jwtSubject decodes a JWT payload's `sub`. No signature check: see above.
func jwtSubject(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("a JWT has three parts, this has %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decoding the payload: %w", err)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return "", fmt.Errorf("parsing the payload: %w", err)
	}
	return claims.Sub, nil
}

// ---------------------------------------------------------------------------
// sign_commit — measured absent rather than assumed absent.
// ---------------------------------------------------------------------------

func (c *campaign) signCommit(t *testing.T) {
	srv, err := mcp.New(mcp.Config{Version: "v0.0.0-mcp-011"})
	if err != nil {
		t.Fatalf("mcp.New: %v", err)
	}
	if !slices.Contains(srv.MissingTools(), mcp.ToolSignCommit) {
		// PENDING, not silently skipped. RM-033 (#41) bound sign_commit, so MCP-011
		// must fuzz it and assert IP §6.6's third clause — "never a second commit" —
		// which has never been tested because until now no tool made one. That is
		// RM-072 (#95); it needs a Sigstore stack this harness does not yet carry.
		// Reported every run so the gap cannot be forgotten.
		t.Logf("PENDING: sign_commit is bound and MCP-011 does not fuzz it. " +
			"IP §6.6's \"never a second commit\" is untested. Tracked as RM-072 (#95). " +
			"This is a coverage gap, not a pass.")
	}
	t.Skipf("sign_commit is RM-033 (#41) and mcp.New reports it missing %v. "+
		"MCP-011's \"no duplicate commit\" half is deferred with it and is UNPROVEN here.",
		srv.MissingTools())
}

// ---------------------------------------------------------------------------
// The census — the gate that makes a vacuous campaign fail.
// ---------------------------------------------------------------------------

// inertWindows are the landings in which the kill arrived before the tool did
// anything durable. A campaign that only ever produced these would pass every
// per-iteration assertion while proving nothing at all, because a call that
// never started cannot leave a second identity behind.
var inertWindows = []string{winBeforeClaim, winClaimedNoWork, winRetireNoRecord, winCredNoRecord}

func (c *campaign) census(t *testing.T) {
	c.mu.Lock()
	all := maps.Clone(c.landings)
	blind := maps.Clone(c.blindLandings)
	c.mu.Unlock()

	for _, w := range slices.Sorted(maps.Keys(all)) {
		t.Logf("%4d landings (%d of them blind) — %s", all[w], blind[w], w)
	}

	// Every window this project has reasoned about is fired by an observed
	// trigger, so "never reached" here means the trigger did not do what it
	// claims and not that the campaign was unlucky.
	for _, w := range []string{
		winEventNoEntry, winEntryNoReply, winReplyUnseen,
		winRecEventNoReply, winRetireNoDelete, winCredNoReply,
	} {
		if all[w] == 0 {
			t.Errorf("the kill never landed in %q. Every named window is fired by polling "+
				"Postgres or SPIRE and signalling the moment the state appears, so a window "+
				"that was never reached is a harness that is not interrupting what it says "+
				"it interrupts. (seed %d)", w, c.seed)
		}
	}

	// And the blind half has to have landed on both sides of "something
	// durable happened". One-sided is the vacuous campaign.
	inert, live := 0, 0
	for w, n := range blind {
		if slices.Contains(inertWindows, w) {
			inert += n
			continue
		}
		live += n
	}
	if live == 0 {
		t.Errorf("every blind kill landed before the tool did anything durable (%d of them). "+
			"A call that never started cannot leave a second identity, so this campaign asserted "+
			"nothing. (seed %d)", inert, c.seed)
	}
	if inert == 0 {
		t.Logf("note: no blind kill landed before the tool did anything durable; the calibrated "+
			"window may be too wide for this machine (seed %d)", c.seed)
	}
	t.Logf("blind landings: %d after something durable happened, %d before", live, inert)

	// And the headline assertion has to have been made. A campaign in which
	// the kill never once landed after the reply was recorded would pass every
	// other check here without ever comparing a replay against an original.
	c.mu.Lock()
	originals := c.originals
	c.mu.Unlock()
	if originals == 0 {
		t.Errorf("not once did a kill land after the reply was recorded, so \"replaying any "+
			"request after a crash returns the original result\" (IP §6.6) was never actually "+
			"compared against an original. (seed %d)", c.seed)
	}
	t.Logf("the replay was compared against the reply recorded before the crash %d times", originals)
}

// ---------------------------------------------------------------------------
// The invariants, at the end.
// ---------------------------------------------------------------------------

func (c *campaign) verifyChain(t *testing.T) {
	records := c.chain(t)
	c.verifyChainNow(t, records)
	t.Logf("the chain walks clean from the genesis constant to its stored head over %d events, "+
		"after %d SIGKILLs (seed %d)", len(records), c.kills(), c.seed)
}

// entryCensus asks the SPIRE datastore itself — through the container-private
// admin socket, which sees every entry — what the campaign left behind.
//
// SPI-006's standard: the assertion is over the WHOLE entry set and not only
// the runs this file remembers, so an identity minted by any path, under any
// name, at any kill point shows up as a difference.
func (c *campaign) entryCensus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	after, err := c.stack.allEntrySPIFFEIDs(ctx)
	if err != nil {
		t.Fatalf("reading the SPIRE datastore after the campaign: %v", err)
	}

	c.mu.Lock()
	live := slices.Clone(c.expectLive)
	gone := slices.Clone(c.expectGone)
	c.mu.Unlock()

	for _, id := range live {
		if n := count(after, id); n != 1 {
			t.Errorf("SPIRE holds %d entries for %s, want exactly 1. IP §1 allows one identity "+
				"per run and IP §6.6 forbids a crash producing a second. (seed %d)", n, id, c.seed)
		}
	}
	for _, id := range gone {
		if n := count(after, id); n != 0 {
			t.Errorf("SPIRE holds %d entries for retired run %s, want 0 (IP §6.2). (seed %d)",
				n, id, c.seed)
		}
	}

	expected := append(slices.Clone(c.entriesAtStart), live...)
	for _, id := range after {
		if count(expected, id) < count(after, id) {
			t.Errorf("SPIRE holds an entry for %s that the campaign never asked for. It was not "+
				"in the datastore before the campaign and no tool call this test made returned it. "+
				"(seed %d)", id, c.seed)
		}
	}
	t.Logf("the SPIRE datastore held %d entries before the campaign and %d after; %d live runs "+
		"and %d retired ones were created in between (seed %d)",
		len(c.entriesAtStart), len(after), len(live), len(gone), c.seed)
}

// reconcile is doc 07 MCP-011's "invariants hold post-reconcile", asked of the
// component whose whole job that is.
//
// Restart alone is only half of what IP §6.6 says survives a kill: it says
// "after restart + reconciliation". RM-019's reconciler is what the second
// word names — it reads SPIRE's agent subtree and the chain and reports every
// way the two disagree, including the two a crash could plausibly produce: an
// identity with no record (`spire_entry_unattributed`) and a run recorded
// registered with no identity (`spire_entry_missing`).
//
// Running it here means the campaign's SPIRE-versus-ledger claim is checked by
// the shipped detection control and not only by this file's own bookkeeping.
// A drift found here would also be APPENDED, so a green run is one where the
// reconciler wrote nothing.
func (c *campaign) reconcile(t *testing.T) {
	r, err := spire.NewReconciler(spire.ReconcilerConfig{
		Entries:  c.admin,
		Ledger:   c.store,
		Appender: c.store,
		Alert: func(_ context.Context, d spire.Drift) {
			t.Errorf("the reconciler raised drift the closed schema cannot record: %+v. "+
				"That is an identity in the agent subtree the chain has never heard of, which "+
				"is exactly what IP §6.6 forbids a crash from producing. (seed %d)", d, c.seed)
		},
		Observe: func(spire.Result, error) {},
	})
	if err != nil {
		t.Fatalf("spire.NewReconciler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	res, err := r.Reconcile(ctx)
	if err != nil {
		t.Fatalf("reconciling after the campaign: %v", err)
	}
	if len(res.Drifts) != 0 {
		t.Fatalf("the reconciler found %d disagreements between SPIRE and the chain after "+
			"%d SIGKILLs: %+v. IP §6.6: kill -9 at arbitrary points must never violate I1–I6 "+
			"after restart + reconciliation. (seed %d)", len(res.Drifts), c.kills(), res.Drifts, c.seed)
	}
	if len(res.Appended) != 0 {
		t.Fatalf("the reconciler recorded %d drift alerts: %v (seed %d)", len(res.Appended), res.Appended, c.seed)
	}
	if res.ActiveRuns == 0 || res.SPIREEntries == 0 {
		t.Fatalf("the reconciler compared %d active runs against %d SPIRE entries; a comparison "+
			"with nothing on one side agrees for free and proves nothing (seed %d)",
			res.ActiveRuns, res.SPIREEntries, c.seed)
	}
	t.Logf("the reconciler compared %d SPIRE entries against %d active runs out of %d ever "+
		"registered, and found no drift", res.SPIREEntries, res.ActiveRuns, res.LedgerRuns)
	// The chain must still verify after the reconciler has had its look: it is
	// an appender, and a cycle that wrote nothing must have left the tip alone.
	c.verifyChainNow(t, c.chain(t))
}

func count(xs []string, want string) int {
	n := 0
	for _, x := range xs {
		if x == want {
			n++
		}
	}
	return n
}

func (c *campaign) verifyChainNow(t *testing.T, records []event.Fields) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	head, err := c.store.Head(ctx)
	if err != nil {
		t.Fatalf("ledger Head: %v", err)
	}
	if err := ledger.VerifyTip(records, head); err != nil {
		t.Fatalf("the chain does not verify after a crash and replay: %v. "+
			"I4 and I6: the hash chain is append-only and every event links to the one before it. "+
			"(seed %d)", err, c.seed)
	}
}

// The sensitivity control for MCP-011's headline assertion.
//
// WHY THIS TEST EXISTS. The campaign above asserts that a replay after a crash
// returns byte for byte what the idempotency store recorded. That assertion is
// worthless if it would also pass when the store held nothing — if the two
// sides happened to agree for some reason other than the store. So this case
// takes the recorded reply AWAY and shows the comparison changing its answer.
//
// The removal is a supported operation, not a hack: ADR-0017 §7 makes the
// table prunable and its Consequences state the effect exactly — "Pruning a
// completed row re-opens its key to execution. The retention window an
// operator chooses is therefore the replay window they are willing to serve
// … The ledger's own UNIQUE key remains the backstop against a second event
// whatever is pruned here."
//
// Both halves of that sentence are asserted here. The reply changes, which is
// what makes the campaign's comparison a measurement. And the identity does
// NOT: the run id is derived (ADR-0017 §5), so the re-execution asks SPIRE for
// the entry that already exists and adopts it, and the ledger's UNIQUE
// idempotency_key returns the original event rather than writing a second
// (LED-008). This is the only place in this suite where register_agent's
// "adopt the entry an earlier execution created" branch is reached without a
// crash.
func TestMCP011PruningTheRecordedReplyReopensTheKeyAndStillMintsOneIdentity(t *testing.T) {
	c := requireCrashCampaign(t)
	key := c.name("prune")
	args := c.registerArgs(key)

	original, _ := c.callSucceeds(t, mcp.ToolRegisterAgent, args)
	var before registerReply
	decodeInto(t, original, &before)
	if before.RunID == "" || before.SPIFFEID == "" || before.ExpiresAt == "" {
		t.Fatalf("register_agent returned %+v; IP §4 requires all three members", before)
	}
	c.live(before.SPIFFEID)

	rec, found := c.idemRecord(t, key)
	if !found || rec.Status != crashCompleted {
		t.Fatalf("the idempotency store holds %+v for key %q; a completed reply was expected "+
			"before it can be taken away", rec, key)
	}

	// The control's positive half: while the reply IS recorded, a repeat is
	// answered from it.
	withStore, _ := c.callSucceeds(t, mcp.ToolRegisterAgent, args)
	c.sameReply(t, "the sensitivity control", "the original reply and a repeat while it is recorded",
		original, withStore)
	c.requireOriginalReply(t, "the sensitivity control", withStore, rec.Response)

	c.pruneIdempotency(t, key)

	reran, _ := c.callSucceeds(t, mcp.ToolRegisterAgent, args)
	var after registerReply
	decodeInto(t, reran, &after)

	// (1) The comparison the campaign leans on is sensitive.
	if bytes.Equal(canonical(t, original), canonical(t, reran)) {
		t.Fatalf("with the recorded reply deleted, register_agent still answered %s — identical "+
			"to the reply it gave before. Then the campaign's byte-identity check would pass "+
			"whether or not the store held anything, and it is not measuring the store.",
			canonical(t, reran))
	}
	if after.ExpiresAt == before.ExpiresAt {
		t.Fatalf("the re-execution reported the same expires_at %q; it was expected to read a "+
			"fresh TTL off the entry it adopted", after.ExpiresAt)
	}

	// (2) And the invariants hold anyway — which is ADR-0017's own claim about
	//     what the layer below is for.
	if after.RunID != before.RunID || after.SPIFFEID != before.SPIFFEID {
		t.Fatalf("the re-execution named run %q / %q; the first execution named %q / %q. "+
			"The run id is derived so that a second execution asks SPIRE for the identity that "+
			"already exists (ADR-0017 §5).", after.RunID, after.SPIFFEID, before.RunID, before.SPIFFEID)
	}
	records := c.chain(t)
	if n := countEvents(records, event.EventTypeRunRegistered, before.RunID); n != 1 {
		t.Fatalf("the chain holds %d `run_registered` events for run %q after the key was "+
			"re-opened, want exactly 1 (LED-008 is the backstop ADR-0017 names)", n, before.RunID)
	}
	if n := countKeyed(records, key); n != 1 {
		t.Fatalf("%d events carry idempotency_key %q, want exactly 1", n, key)
	}
	if !c.hasEntry(t, crashRunRef(before.RunID)) {
		t.Fatalf("SPIRE holds no entry for run %q after the re-execution", before.RunID)
	}
	c.verifyChainNow(t, records)
	t.Logf("with the recorded reply pruned, register_agent re-executed and answered %s instead "+
		"of %s, and the chain still holds exactly one run_registered for %s with exactly one "+
		"SPIRE entry", canonical(t, reran), canonical(t, original), before.RunID)
}
