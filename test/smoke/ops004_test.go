// SPDX-License-Identifier: Apache-2.0

package smoke

import (
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/signing"
	"innsegl.dev/innsegl/internal/verify"
)

// ---------------------------------------------------------------------------
// OPS-004 — fresh-clone bootstrap.
//
// doc 07: "`docker compose up` of the reference stack from README on a clean
// machine | Full happy path (SIG-001) passes; this is the adopter's first-run
// experience."
//
// Four claims, in the order an adopter meets them.
//
//  1. THE STACK BOOTS FROM WHAT A CLONE CONTAINS. The harness copies the
//     repository's tracked and not-ignored files into a temporary directory
//     and runs everything from there, after tearing both shipped compose
//     projects down with their volumes. Nothing gitignored and no pre-existing
//     volume can carry the run. See freshClone and the clean-slate preflight
//     in smokestack_test.go for exactly what that does and does not prove.
//
//  2. THE DEMO AGENT COMPLETES THE HAPPY PATH. doc 05 §1's `demo-agent` row:
//     "Scripted agent that registers, makes a scratch-repo commit, retires.
//     This is the OPS-004 smoke test body." It calls the five IP §4 tools on
//     the real MCP server over the real transport — no in-process shortcut —
//     and the commit that comes back is signed by a real Fulcio and logged in
//     a real Rekor.
//
//  3. VERIFICATION NEEDS NONE OF IT. `innsegl verify` runs in a container with
//     no route to the ledger — proved unreachable by address and by name, from
//     the same container, seconds before the verification runs — and all three
//     checks pass. This is VER-001's independence property demonstrated on
//     first contact with the project, which is what the whole exercise is for:
//     an adopter sees in their first five minutes that verification does not
//     need our database.
//
//  4. SIG-001's LEDGER HALF HOLDS. "intent+recorded events in order," read
//     back from the real Postgres the MCP wrote to, by chain position. It
//     comes last because the route this process needs to read the chain is the
//     one the stage before it proved absent.
// ---------------------------------------------------------------------------

func TestOPS004FreshCloneBootstrap(t *testing.T) {
	s := requireStack(t)

	// ---- 1. the stack an adopter's `docker compose up` produced ------------
	s.reportReadiness(t)

	// ---- 2. the demo agent ------------------------------------------------
	run := s.demoAgent(t)

	if want := "spiffe://" + trustDomain + "/agent/" + demoAgentType + "/" +
		run.taskRef + "/" + run.runID; run.spiffeID != want {
		t.Errorf("register_agent minted %q; the SPIFFE ID grammar (VERSIONING.md "+
			"protected surface 3) requires %q", run.spiffeID, want)
	}
	for key, want := range map[string]string{
		signing.TrailerAgentIdentity: run.spiffeID,
		signing.TrailerAgentRun:      run.runID,
		signing.TrailerAgentTask:     run.taskRef,
	} {
		if got := run.trailers[key]; got != want {
			t.Errorf("sign_commit returned %s=%q, want %q", key, got, want)
		}
	}
	// The trailers are on the object, not merely in the tool's answer. A
	// commit is what a third party reads; the response is what we say.
	object := s.git(t, run.worktree, "cat-file", "commit", run.commitSHA)
	for _, key := range []string{
		signing.TrailerAgentIdentity, signing.TrailerAgentRun, signing.TrailerAgentTask,
	} {
		if line := key + ": " + run.trailers[key]; !strings.Contains(object, line) {
			t.Errorf("commit %s does not carry %q:\n%s", run.commitSHA, line, object)
		}
	}
	if !strings.Contains(object, "gpgsig ") {
		t.Errorf("commit %s carries no signature at all:\n%s", run.commitSHA, object)
	}
	if run.rekorUUID == "" || run.rekorLogIndex < 0 {
		t.Errorf("sign_commit returned no transparency-log entry: uuid=%q index=%d",
			run.rekorUUID, run.rekorLogIndex)
	}

	// ---- 3. VER-001's independence property, on first contact -------------
	//
	// The control half first: the ledger this run just wrote to IS reachable
	// from its own network. Without it, "unreachable" would be satisfied by a
	// database that is simply not running.
	s.proveLedgerReachableFromItsOwnNetwork(t)

	out := s.verifyWithTheLedgerDetached(t, run.commitSHA)
	for _, want := range []string{
		verify.CheckCertificateChain,
		verify.CheckRekorInclusion,
		verify.CheckTrailerIdentity,
		run.spiffeID,
		noRouteByAddress,
		noRouteByName,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the ledger-detached verification transcript does not carry %q:\n%s",
				want, out)
		}
	}
	if n := strings.Count(out, string(verify.Verified)); n < 3 {
		t.Errorf("%d checks reported %s; doc 07 VER-001 requires all three to pass "+
			"using only git + Fulcio + Rekor:\n%s", n, verify.Verified, out)
	}
	if strings.Contains(out, string(verify.Unavailable)) {
		t.Errorf("a check reported %s. Every one of them must be settled from git, "+
			"Fulcio and Rekor alone — that is I5, and it is the claim an adopter is "+
			"here to see:\n%s", verify.Unavailable, out)
	}

	// ---- 4. SIG-001's ledger half -----------------------------------------
	//
	// Last, and that ordering is the point: reading the chain from this process
	// needs a route into the ledger's network, and a route into the ledger's
	// network is exactly what the stage above just demonstrated the absence of.
	// So it is built now, used, and taken away again — see
	// openLedgerThroughARelay.
	events := s.ledgerEventsForRun(t, run.runID)
	types := make([]string, 0, len(events))
	byType := map[string]event.Fields{}
	for _, e := range events {
		typ, _ := e[event.FieldEventType].(string)
		types = append(types, typ)
		byType[typ] = e
	}
	t.Logf("OPS-004 ledger, run %s: %s", run.runID, strings.Join(types, " -> "))

	for _, want := range []string{
		event.EventTypeRunRegistered,
		event.EventTypeCredentialIssued,
		event.EventTypeCommitIntent,
		event.EventTypeCommitRecorded,
		event.EventTypeRunRetired,
	} {
		if _, ok := byType[want]; !ok {
			t.Errorf("the ledger holds no %s for run %s; the happy path is "+
				"%v", want, run.runID, types)
		}
	}
	intent, recorded := byType[event.EventTypeCommitIntent], byType[event.EventTypeCommitRecorded]
	if intent != nil && recorded != nil {
		ip, _ := intent[event.FieldChainPosition].(int64)
		rp, _ := recorded[event.FieldChainPosition].(int64)
		if ip >= rp {
			t.Errorf("commit_intent is at chain position %d and commit_recorded at %d; "+
				"doc 07 SIG-001 requires intent+recorded IN ORDER, and IP §6.5's "+
				"two-phase protocol is what lets the reconciler tell a crash from a "+
				"lie", ip, rp)
		}
		if got, _ := recorded[event.FieldCommitSHA].(string); got != run.commitSHA {
			t.Errorf("commit_recorded names commit %q; sign_commit returned %q",
				got, run.commitSHA)
		}
		if intent[event.FieldCommitSHA] != nil {
			t.Errorf("commit_intent names a commit_sha (%v); the intent is appended "+
				"BEFORE the commit exists and naming one would mean the two-phase "+
				"protocol collapsed into one", intent[event.FieldCommitSHA])
		}
		if got, _ := recorded[event.FieldIntentEventID].(string); got == "" ||
			got != intent[event.FieldEventID] {
			t.Errorf("commit_recorded's intent_event_id is %q and the intent's "+
				"event_id is %v; the link is what makes the pair a protocol rather "+
				"than two rows", got, intent[event.FieldEventID])
		}
	}
}
