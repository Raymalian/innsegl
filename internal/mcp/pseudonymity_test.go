// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/signing"
	"innsegl.dev/innsegl/internal/spire"
)

// RM-079 (#116) — a ticket reference reaches no public record.
//
// Test ID: PRI-003.
//
// # What this case is written against
//
// The obvious version of this test asks the pseudonymiser for a pseudonym and
// checks it is not the ticket number. That assertion cannot fail: it tests the
// function against itself, and it would keep passing if `register_agent` never
// called the function at all.
//
// So no assertion here compares anything to a pseudonymiser's output. It drives
// the real `register_agent` over the real HTTP transport onto a real Postgres,
// drives the real `sign_commit` phases, and then SCANS THE RENDERED ARTIFACTS
// for the ticket reference. (A pseudonymiser is built, but only to address the
// SPIRE entry by the identity SPIRE was asked to create; every assertion is a
// scan.) What is scanned:
//
//   - the `spiffe_id` the tool returned, which is verbatim the URI SAN of the
//     Fulcio certificate and verbatim the `Agent-Identity` trailer;
//   - the SPIRE registration entry as SPIRE was actually asked to create it,
//     with its selectors;
//   - the three trailers `sign_commit` returned;
//   - the COMMIT MESSAGE, rendered by `signing.CommitMessage` — the same
//     function `signing.Signer.Sign` renders the signed bytes with.
//
// Delete the pseudonymisation and every one of those scans finds the ticket
// again, which is what "it would fail on a revert" has to mean.
//
// The other half is just as load bearing: the REAL values must still be in the
// ledger. `run_registered` carrying the pseudonymous `spiffe_id` alongside the
// real `agent_type` and `task_ref` IS the mapping — there is no second table —
// so a test that only proved absence would be satisfied by a system that had
// thrown the ticket away.
const (
	// priSecret is a deployment secret, not a password: 32 bytes, and the only
	// thing it is ever used for is keying the HMAC.
	priSecret = "0f7a1c93e5b28d46a0f7a1c93e5b28d4"
	// priAgentType and priTaskRef are the two values that must not escape.
	// Deliberately distinctive strings: a scan for "demo" would match half the
	// repository, and a scan that can match by accident is one that can pass
	// by accident too.
	priAgentType = "refactor-billing"
	priTaskRef   = "ACME-90210"
)

func priPseudonymiser(t *testing.T) *identity.Pseudonymiser {
	t.Helper()
	p, err := identity.New(identity.ModePseudonymous, priSecret)
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	return p
}

// priScan fails if text carries either value that RM-079 keeps private.
//
// The comparison is case-insensitive because `ACME-90210` and `acme-90210` are
// the same leak, and the lowercased form is exactly what used to go into the
// SPIFFE ID.
func priScan(t *testing.T, what, text string) {
	t.Helper()
	lowered := strings.ToLower(text)
	for _, secret := range []string{priTaskRef, priAgentType} {
		if strings.Contains(lowered, strings.ToLower(secret)) {
			t.Errorf("%s carries %q, which is a permanent public record of what this "+
				"run was and which ticket it came from (RM-079, #116):\n%s",
				what, secret, text)
		}
	}
}

func TestPRI003NoTicketReferenceReachesAPublicRecord(t *testing.T) {
	p := priPseudonymiser(t)

	// ---- register_agent, through the real tool and the real transport -----
	env := raSetup(t, DefaultIdempotencyLease, func(cfg *RegisterAgentConfig) {
		cfg.Pseudonyms = p
	})
	session := raServe(t)
	out := raCallOK(t, session, map[string]any{
		"agent_type":      priAgentType,
		"task_id":         priTaskRef,
		"idempotency_key": "pri-003",
	})

	// (1) The SPIFFE ID. This string IS the certificate's URI SAN and IS the
	// Agent-Identity trailer; nothing downstream can put back what is not here.
	priScan(t, "the spiffe_id register_agent returned", out.SPIFFEID)
	if err := event.ValidateSPIFFEID(out.SPIFFEID); err != nil {
		t.Fatalf("the pseudonymous identity %q is not a SPIFFE ID: %v\n\n"+
			"doc 02 §5's grammar is a PROTECTED SURFACE and RM-079 changes what goes "+
			"into the fields, never their shape.", out.SPIFFEID, err)
	}

	// (2) The SPIRE registration entry, as SPIRE was asked to create it.
	entry, held, err := env.identities.LookupRun(context.Background(),
		spire.RunRef{
			AgentType: mustPseudo(t, p.AgentType, priAgentType),
			TaskID:    mustPseudo(t, p.TaskID, priTaskRef),
			RunID:     out.RunID,
		})
	if err != nil || !held {
		t.Fatalf("SPIRE holds no entry for the run just registered (%v, held=%t)", err, held)
	}
	priScan(t, "the SPIRE entry's SPIFFE ID", entry.SPIFFEID)
	for _, sel := range entry.Selectors {
		priScan(t, "a SPIRE selector", sel.String())
	}

	// ---- the ledger still holds both, unchanged ---------------------------
	//
	// This is the mapping. Without it the pseudonym would be a one-way door.
	events := env.runRegisteredFor(t, out.RunID)
	if len(events) != 1 {
		t.Fatalf("the chain holds %d run_registered events for %s, want 1", len(events), out.RunID)
	}
	rec := events[0]
	if got := rec[event.FieldAgentType]; got != priAgentType {
		t.Errorf("run_registered carries agent_type %q, want the caller's own %q. "+
			"RM-079 pseudonymises the SPIFFE ID and nothing else; the ledger row IS "+
			"the mapping back", got, priAgentType)
	}
	if got := rec[event.FieldTaskRef]; got != priTaskRef {
		t.Errorf("run_registered carries task_ref %q, want the caller's own %q, "+
			"verbatim and with its own casing (doc 02 §6, golden fixture 01)", got, priTaskRef)
	}
	if got := rec[event.FieldSpiffeID]; got != out.SPIFFEID {
		t.Errorf("run_registered carries spiffe_id %q, want %q", got, out.SPIFFEID)
	}

	// ---- sign_commit, through the real phases -----------------------------
	//
	// The run directory answers exactly as `internal/rundir` does: the SPIFFE
	// ID and the two REAL values, all four read off the run_registered event
	// above.
	w := newSCWiring()
	w.runs.run = CredentialRun{
		RunID:     out.RunID,
		AgentType: priAgentType,
		TaskID:    priTaskRef,
		SPIFFEID:  out.SPIFFEID,
	}
	w.cfg.Runs = w.runs
	w.cfg.Pseudonyms = p
	signed, err := w.call(t, signCommitIn{
		RunID:          out.RunID,
		Repo:           scRepo,
		StagedRef:      scStagedRef,
		Message:        scMessage,
		TaskRef:        priTaskRef,
		IdempotencyKey: "pri-003-sign",
	})
	if err != nil {
		t.Fatalf("sign_commit: %v", err)
	}

	// (3) The three trailers the tool returned.
	if len(signed.Trailers) != 3 {
		t.Fatalf("sign_commit returned %d trailers, want the three of IP §1", len(signed.Trailers))
	}
	for _, tr := range signed.Trailers {
		priScan(t, "the "+tr.Key+" trailer", tr.Key+": "+tr.Value)
	}

	// (4) The commit message as it will be signed. Rendered by the production
	// renderer from the claim the production tool built, so a revert that put
	// the ticket back in the claim shows up here in the bytes.
	claim := w.signer.reqs[0].Claim
	message, err := signing.CommitMessage(
		signing.AuthorPolicy{Operators: []string{scAuthorEmail}, AllowUnlinked: true},
		signing.Commit{Message: scMessage, AuthorEmail: scAuthorEmail, Claim: claim})
	if err != nil {
		t.Fatalf("CommitMessage: %v", err)
	}
	priScan(t, "the commit message that will be signed", message)

	// And the trailers must still be internally consistent, or check 3 — the
	// comparison of Agent-Identity against the certificate, which is what a
	// stranger settles all three trailers with — has nothing to compare.
	if !strings.Contains(message, signing.TrailerAgentIdentity+": "+out.SPIFFEID) {
		t.Errorf("the message does not carry %s: %s\n%s",
			signing.TrailerAgentIdentity, out.SPIFFEID, message)
	}
	if _, err := claim.Trailers(); err != nil {
		t.Errorf("the claim sign_commit built is not internally consistent, so check 3 "+
			"cannot settle Agent-Task from the certificate alone: %v", err)
	}
}

// PRI-003, the other direction: `literal` reproduces exactly what the system
// did before RM-079, so a deployment that chooses the old behaviour on purpose
// gets the old behaviour and not a third one.
func TestPRI003LiteralModeIsWhatTheSystemDidBefore(t *testing.T) {
	p, err := identity.New(identity.ModeLiteral, "")
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	env := raSetup(t, DefaultIdempotencyLease, func(cfg *RegisterAgentConfig) {
		cfg.Pseudonyms = p
	})
	session := raServe(t)
	out := raCallOK(t, session, map[string]any{
		"agent_type":      raAgentType,
		"task_id":         raTaskID,
		"idempotency_key": "pri-003-literal",
	})
	want := "spiffe://" + raTrustDomain + "/agent/" + raAgentType + "/" +
		strings.ToLower(raTaskID) + "/" + out.RunID
	if out.SPIFFEID != want {
		t.Errorf("literal mode minted %q, want golden fixture 01's own shape %q",
			out.SPIFFEID, want)
	}
	events := env.runRegisteredFor(t, out.RunID)
	if len(events) != 1 || events[0][event.FieldTaskRef] != raTaskID {
		t.Errorf("literal mode did not record the caller's task_ref verbatim: %v", events)
	}
}

// PRI-003 — the pseudonym is stable across a replay, which is what stops a
// retried register_agent minting a second identity for one run.
func TestPRI003AReplayMintsTheSameIdentity(t *testing.T) {
	p := priPseudonymiser(t)
	env := raSetup(t, DefaultIdempotencyLease, func(cfg *RegisterAgentConfig) {
		cfg.Pseudonyms = p
	})
	session := raServe(t)
	args := map[string]any{
		"agent_type":      priAgentType,
		"task_id":         priTaskRef,
		"idempotency_key": "pri-003-replay",
	}
	first := raCallOK(t, session, args)
	second := raCallOK(t, session, args)
	if first.SPIFFEID != second.SPIFFEID || first.RunID != second.RunID {
		t.Errorf("a replay produced %s / %s and then %s / %s; IP §1 allows one identity per run",
			first.RunID, first.SPIFFEID, second.RunID, second.SPIFFEID)
	}
	if n := env.identities.entryCount(); n != 1 {
		t.Errorf("SPIRE holds %d entries after a replay, want 1", n)
	}
}

// PRI-003 — CredentialRun.Ref refuses an identity that is not one.
//
// IP §2 puts a 100% BRANCH floor on every error-return path. This one is
// unreachable from either shipped caller — both put the same string through
// credentialRunIdentity first — but the run directory is an interface, and the
// alternative to returning an error here is asking SPIRE about
// `spiffe://{td}/agent///`, which is an entry lookup against a wildcard.
func TestPRI003RefRefusesAnIdentityThatIsNotOne(t *testing.T) {
	for _, id := range []string{"", "spiffe://innsegl.dev/innsegl/rogue", "not a spiffe id"} {
		run := CredentialRun{RunID: "run-a", SPIFFEID: id}
		ref, err := run.Ref()
		if err == nil {
			t.Errorf("Ref() on %q returned %+v and no error", id, ref)
			continue
		}
		requireClass(t, err, ClassInvariantViolation)
	}
	// And it succeeds on a real one, reading the SEGMENTS off the identity and
	// not off the recorded values — which under `pseudonymous` differ.
	run := CredentialRun{
		RunID:     "run-a",
		AgentType: priAgentType,
		TaskID:    priTaskRef,
		SPIFFEID:  "spiffe://innsegl.dev/agent/a7f3c91b/e2d5f004/run-a",
	}
	ref, err := run.Ref()
	if err != nil {
		t.Fatalf("Ref(): %v", err)
	}
	want := spire.RunRef{AgentType: "a7f3c91b", TaskID: "e2d5f004", RunID: "run-a"}
	if ref != want {
		t.Errorf("Ref() = %+v, want %+v; SPIRE holds the segments and nothing else", ref, want)
	}
}

func mustPseudo(t *testing.T, f func(string) (string, error), v string) string {
	t.Helper()
	got, err := f(v)
	if err != nil {
		t.Fatalf("pseudonymising %q: %v", v, err)
	}
	return got
}
