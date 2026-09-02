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

	if err := event.ValidateSPIFFEID(run.spiffeID); err != nil {
		t.Errorf("register_agent minted %q, which is not "+
			"spiffe://{trust_domain}/agent/{agent_type}/{task_id}/{run_id} "+
			"(VERSIONING.md protected surface 3): %v", run.spiffeID, err)
	}
	if !strings.HasPrefix(run.spiffeID, "spiffe://"+trustDomain+"/agent/") ||
		!strings.HasSuffix(run.spiffeID, "/"+run.runID) {
		t.Errorf("register_agent minted %q; it must be this trust domain's, in the "+
			"/agent/ subtree, and name this run", run.spiffeID)
	}
	for key, want := range map[string]string{
		signing.TrailerAgentIdentity: run.spiffeID,
		signing.TrailerAgentRun:      run.runID,
	} {
		if got := run.trailers[key]; got != want {
			t.Errorf("sign_commit returned %s=%q, want %q", key, got, want)
		}
	}
	// Agent-Task is not compared to the ticket reference any more. It is the
	// identity's {task_id} segment, which under RM-079's default is a
	// pseudonym; what has to hold is that the three trailers still agree with
	// each other, because that agreement is what lets check 3 settle all three
	// from the certificate alone.
	if got, want := run.trailers[signing.TrailerAgentTask], taskSegmentOf(run.spiffeID); got != want {
		t.Errorf("sign_commit returned %s=%q; it must be the {task_id} segment of %q, "+
			"which is %q — otherwise check 3 compares two strings that cannot match",
			signing.TrailerAgentTask, got, run.spiffeID, want)
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
		typ := memberString(t, e, event.FieldEventType)
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
		ip := memberInt64(t, intent, event.FieldChainPosition)
		rp := memberInt64(t, recorded, event.FieldChainPosition)
		if ip >= rp {
			t.Errorf("commit_intent is at chain position %d and commit_recorded at %d; "+
				"doc 07 SIG-001 requires intent+recorded IN ORDER, and IP §6.5's "+
				"two-phase protocol is what lets the reconciler tell a crash from a "+
				"lie", ip, rp)
		}
		if got := memberString(t, recorded, event.FieldCommitSHA); got != run.commitSHA {
			t.Errorf("commit_recorded names commit %q; sign_commit returned %q",
				got, run.commitSHA)
		}
		if intent[event.FieldCommitSHA] != nil {
			t.Errorf("commit_intent names a commit_sha (%v); the intent is appended "+
				"BEFORE the commit exists and naming one would mean the two-phase "+
				"protocol collapsed into one", intent[event.FieldCommitSHA])
		}
		got := memberString(t, recorded, event.FieldIntentEventID)
		if want := memberString(t, intent, event.FieldEventID); got == "" || got != want {
			t.Errorf("commit_recorded's intent_event_id is %q and the intent's "+
				"event_id is %q; the link is what makes the pair a protocol rather "+
				"than two rows", got, want)
		}
	}

	// ---- 5. PRI-004: the ticket reference is in none of it ----------------
	//
	// RM-079 (#116). Everything scanned here is an artifact this run really
	// produced, on the real stack, and every one of them is public somewhere:
	//
	//   - the commit object, which is `git log` and, in a public repository,
	//     the internet;
	//   - the verification transcript, whose `identity` line and whose check-1
	//     `certificate identity` fact are read OFF THE FULCIO CERTIFICATE by
	//     internal/verify (uriSANOf), and whose check-2 facts come from the
	//     Rekor entry the log returned. So this scan covers the certificate's
	//     URI SAN — and with it the certificate inside the Rekor entry, which
	//     is the only part of that entry any of these values could reach —
	//     without this package having to parse either.
	//
	// The scan is not vacuous: stage 3 above already REQUIRES the transcript to
	// contain run.spiffeID, so a transcript with no identity in it fails there
	// before it can pass silently here.
	//
	// Revert the pseudonymisation and all of them carry ACME-90210 again.
	for what, text := range map[string]string{
		"the commit object":                     object,
		"the verification transcript":           out,
		"the spiffe_id register_agent returned": run.spiffeID,
	} {
		for _, private := range []string{demoTaskRef, demoAgentType} {
			if strings.Contains(strings.ToLower(text), strings.ToLower(private)) {
				t.Errorf("%s carries %q. Under public Sigstore that is a PERMANENT "+
					"PUBLIC RECORD of which ticket this run came from and what kind of "+
					"work it was (RM-079, #116):\n%s", what, private, text)
			}
		}
	}

	// And the other half: the ledger still holds both, unchanged. The
	// `run_registered` row IS the mapping from the pseudonymous identity back
	// to the ticket — there is no second table — so a system that had simply
	// thrown the values away would pass the scan above and fail here.
	if reg, ok := byType[event.EventTypeRunRegistered]; ok {
		if got := memberString(t, reg, event.FieldAgentType); got != demoAgentType {
			t.Errorf("run_registered carries agent_type %q, want %q", got, demoAgentType)
		}
		if got := memberString(t, reg, event.FieldTaskRef); got != demoTaskRef {
			t.Errorf("run_registered carries task_ref %q, want the caller's own %q",
				got, demoTaskRef)
		}
		if got := memberString(t, reg, event.FieldSpiffeID); got != run.spiffeID {
			t.Errorf("run_registered carries spiffe_id %q and register_agent returned %q; "+
				"the mapping only works if the row names the identity that is public",
				got, run.spiffeID)
		}
	}
}

// taskSegmentOf returns the {task_id} component of a SPIFFE ID that has
// already passed event.ValidateSPIFFEID, which guarantees the five parts.
func taskSegmentOf(spiffeID string) string {
	parts := strings.Split(strings.TrimPrefix(spiffeID, "spiffe://"), "/")
	if len(parts) != 5 {
		return ""
	}
	return parts[3]
}

// memberString and memberInt64 read one member of an appended event.
//
// They FAIL on a member of the wrong type rather than returning a zero value,
// because doc 02 §5 fixes the type of every field and a `chain_position` that
// is not an integer is a protected-surface violation — while a silent zero
// would turn OPS-004's ordering assertion (`ip >= rp` on two zeroes) into a
// comparison that can only ever be trivially satisfied. An absent member is a
// different thing and is answered with the zero value, because absence is what
// several of these assertions are about: `commit_intent` carries no commit_sha.
func memberString(t *testing.T, e event.Fields, name string) string {
	t.Helper()
	raw, present := e[name]
	if !present {
		return ""
	}
	s, ok := raw.(string)
	if !ok {
		t.Fatalf("the ledger's %s is %T; doc 02 §5 makes it a string", name, raw)
	}
	return s
}

func memberInt64(t *testing.T, e event.Fields, name string) int64 {
	t.Helper()
	raw, present := e[name]
	if !present {
		t.Fatalf("the ledger's event carries no %s at all", name)
	}
	n, ok := raw.(int64)
	if !ok {
		t.Fatalf("the ledger's %s is %T; doc 02 §5 makes it an integer", name, raw)
	}
	return n
}
