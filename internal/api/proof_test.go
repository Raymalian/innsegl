// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/sha1" //nolint:gosec // git's object id is SHA-1; this recomputes it, it does not choose it
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/verify"
)

// TC-API — the proof BFF.
//
// FD §7: "proof checks may execute in a backend-for-frontend for
// CORS/performance, but the response includes the raw inputs and outputs so
// the client (and the user) can re-derive the verdict." These cases hold the
// response to that, and API-006 holds it to the harder half — FD P2's third
// state, which must never collapse into either of its neighbours.

// gitObjectID recomputes a commit's object name from its bytes, the way git
// does: sha1("commit " + len + "\x00" + content). It is the test's own
// arithmetic, not the package's.
func gitObjectID(object []byte) string {
	h := sha1.New() //nolint:gosec // see the import comment
	h.Write([]byte("commit " + itoa(len(object)) + "\x00"))
	h.Write(object)
	return hex.EncodeToString(h.Sum(nil))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// API-004 — the proof response carries the raw material its verdict was
// computed from, and that material re-derives the commit it names.
func TestAPI004TheProofResponseCarriesTheRawMaterial(t *testing.T) {
	s := newProofScenario(t, proofOptions{})
	p, err := s.prover(t).Prove(t.Context(), fixtureRepo, s.commit)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	if p.Verdict != string(verify.VerdictVerified) {
		t.Fatalf("verdict %q on a commit whose certificate, trailer and log entry "+
			"all agree; checks: %+v, notes: %v", p.Verdict, p.Checks, p.Notes)
	}
	if len(p.Checks) != 3 {
		t.Fatalf("the response carries %d checks; FD §4.1 requires three that never "+
			"collapse", len(p.Checks))
	}

	m := p.Material
	for _, f := range []struct {
		name  string
		value string
	}{
		{"the commit object", m.CommitObject},
		{"the signing certificate, PEM", m.CertificatePEM},
		{"Fulcio's published root, PEM", m.FulcioRootPEM},
		{"the log's public key, PEM", m.RekorLogPublicKeyPEM},
		{"the log entry", string(m.RekorEntry)},
	} {
		if f.value == "" {
			t.Errorf("the response carries no %s; FD §7 requires the raw inputs and "+
				"outputs, and FD §3.6 names the cert PEM and the log index by hand", f.name)
		}
	}
	if len(m.Gaps) != 0 {
		t.Errorf("the response reports gaps in its own material with every upstream up: %+v", m.Gaps)
	}
	if m.CollectedAt.IsZero() {
		t.Error("the material carries no collection time; a reader cannot tell how " +
			"old the evidence is")
	}

	// The material is bound to the user's own input, which is what makes it
	// evidence rather than assertion: re-hashing the object reproduces the SHA
	// that was asked about.
	if got := gitObjectID([]byte(m.CommitObject)); got != p.CommitSHA {
		t.Errorf("the commit object hashes to %s, the response is about %s", got, p.CommitSHA)
	}
	if m.CommitObjectID != p.CommitSHA {
		t.Errorf("the response reports the object id %s for the commit %s",
			m.CommitObjectID, p.CommitSHA)
	}

	// The certificate PEM is the one the log recorded, so it is bound to the
	// entry rather than merely asserted beside it.
	if !strings.Contains(m.CertificatePEM, "BEGIN CERTIFICATE") {
		t.Errorf("the certificate material is not PEM: %q", m.CertificatePEM)
	}

	// Both upstreams are named with what was asked of them.
	if len(p.Upstreams) != 2 {
		t.Fatalf("the response names %d upstreams, want Fulcio and Rekor", len(p.Upstreams))
	}
	for _, u := range p.Upstreams {
		if !u.Reachable {
			t.Errorf("%s reported unreachable with the server up: %s", u.Name, u.Error)
		}
		if u.URL == "" {
			t.Errorf("%s is named without the endpoint a third party would use", u.Name)
		}
	}

	// The artifact the log is keyed on is arithmetic anyone can redo, and the
	// test redoes it with its own base64 and JSON rather than the package's.
	var served map[string]struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(m.RekorEntry, &served); err != nil {
		t.Fatalf("the served log entry is not a Rekor entry map: %v", err)
	}
	entry, ok := served[p.Entry.UUID]
	if !ok {
		t.Fatalf("the served entry map holds no entry %s", p.Entry.UUID)
	}
	body, err := base64.StdEncoding.DecodeString(entry.Body)
	if err != nil {
		t.Fatalf("the entry body is not base64: %v", err)
	}
	digest := sha256.Sum256([]byte(p.CommitSHA))
	if !strings.Contains(string(body), hex.EncodeToString(digest[:])) {
		t.Errorf("the served log entry is not keyed on sha256 of this commit's SHA: %s", body)
	}
}

// API-006 — when an upstream is gone the answer is "verification unavailable",
// which is a third state and never either of its neighbours.
//
// The database is deliberately loaded with a commit_recorded event naming this
// very commit before the check runs. A BFF that fell back on the ledger would
// have everything it needed to say "verified"; IP §6.11 and FD P2 forbid it,
// and this is the case that would catch it.
func TestAPI006AnUnreachableUpstreamIsUnavailableAndNeverADatabaseAnswer(t *testing.T) {
	s := newProofScenario(t, proofOptions{})
	owner, _, readerDSN := migrated(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// The ledger knows this commit and says it was signed.
	base := func(eventType string) event.Fields {
		return event.Fields{
			event.FieldEventType: eventType,
			event.FieldRunID:     "run-1",
			event.FieldSpiffeID:  fixtureIdentity,
			event.FieldSource:    event.SourceMCP,
		}
	}
	reg := base(event.EventTypeRunRegistered)
	reg[event.FieldAgentType] = "fix-ci"
	reg[event.FieldTaskRef] = "rm-040"
	reg[event.FieldIdempotencyKey] = "run-1-register"
	appendOrFail(t, ctx, owner, reg)

	intent := base(event.EventTypeCommitIntent)
	intent[event.FieldRepo] = fixtureRepo
	intent[event.FieldTreeHash] = strings.Repeat("a", 40)
	intent[event.FieldIdempotencyKey] = "run-1-intent"
	rec := appendOrFail(t, ctx, owner, intent)

	done := base(event.EventTypeCommitRecorded)
	done[event.FieldRepo] = fixtureRepo
	done[event.FieldTreeHash] = strings.Repeat("a", 40)
	done[event.FieldCommitSHA] = s.commit
	done[event.FieldIntentEventID] = rec[event.FieldEventID]
	done[event.FieldRekorEntryUUID] = strings.Repeat("b", 64)
	done[event.FieldRekorLogIndex] = int64(1)
	done[event.FieldIdempotencyKey] = "run-1-recorded"
	appendOrFail(t, ctx, owner, done)

	store, _ := readStore(t, readerDSN)
	if _, err := store.Run(ctx, "run-1"); err != nil {
		t.Fatalf("the fixture did not land in the ledger: %v", err)
	}

	prover := s.prover(t)
	s.fulcio.stop()
	s.log.stop()

	p, err := prover.Prove(ctx, fixtureRepo, s.commit)
	if err != nil {
		t.Fatalf("Prove returned an error rather than an unavailable verdict: %v", err)
	}
	if p.Verdict != string(verify.VerdictUnavailable) {
		t.Fatalf("verdict %q with Fulcio and Rekor both unreachable; FD P2 makes "+
			"unavailable a third state that never collapses into verified or "+
			"failed. checks: %+v", p.Verdict, p.Checks)
	}
	for _, c := range p.Checks {
		if c.Name == verify.CheckTrailerIdentity {
			continue // local, and it can still be settled offline
		}
		if c.Result != verify.Unavailable {
			t.Errorf("check %q is %q with its upstream unreachable", c.Name, c.Result)
		}
	}

	// The response says which upstream is gone, and why.
	for _, u := range p.Upstreams {
		if u.Reachable {
			t.Errorf("%s reported reachable after its listener was closed", u.Name)
		}
		if u.Error == "" {
			t.Errorf("%s is reported unreachable with no reason; FD §6.1 wants the "+
				"error to say what failed", u.Name)
		}
	}
	// And it still hands over what can be checked offline.
	if p.Material.CommitObject == "" {
		t.Error("the response carries no commit object with the upstreams down; FD " +
			"§6.1's copy is \"verify offline with the material below\", so there has " +
			"to be material below")
	}
	if len(p.Material.Gaps) == 0 {
		t.Error("the response reports no gaps although Fulcio and Rekor were both " +
			"unreachable; silence reads as \"collected and fine\"")
	}
	// The ledger holds a commit_recorded for this SHA. It changed nothing.
	if strings.Contains(strings.ToLower(strings.Join(p.Notes, " ")), "ledger") {
		t.Error("the notes reach for the ledger; IP §6.11 forbids a database-only answer")
	}
}

// The two states a commit without a signature can be in, held apart. E7,
// VER-006 and FD P2: a commit that claims nothing is UNATTRIBUTED, and a
// commit that claims an identity nothing proves is FAILED. Collapsing them
// would make every pre-adoption commit look like an attack.
func TestAnUnclaimedCommitIsUnattributedAndAnUnprovenClaimIsFailed(t *testing.T) {
	t.Run("no signature and no trailer is unattributed", func(t *testing.T) {
		s := newProofScenario(t, proofOptions{
			unsigned: true,
			message:  "RM-040: an ordinary commit from before any of this\n",
		})
		p, err := s.prover(t).Prove(t.Context(), fixtureRepo, s.commit)
		if err != nil {
			t.Fatalf("Prove: %v", err)
		}
		if p.Verdict != string(verify.VerdictUnattributed) {
			t.Fatalf("verdict %q on a commit that makes no attribution claim; E7 says "+
				"commits from before adoption are simply unattributed", p.Verdict)
		}
		if len(p.Checks) != 0 {
			t.Errorf("a commit that claims nothing carries %d check results", len(p.Checks))
		}
		if bad := Contradictions(Rederive(p)); len(bad) != 0 {
			t.Errorf("the re-derivation convicts an honest unattributed response: %+v", bad)
		}
	})

	t.Run("a trailer with no signature is failed, never verified", func(t *testing.T) {
		s := newProofScenario(t, proofOptions{unsigned: true})
		p, err := s.prover(t).Prove(t.Context(), fixtureRepo, s.commit)
		if err != nil {
			t.Fatalf("Prove: %v", err)
		}
		if p.Verdict != string(verify.VerdictFailed) {
			t.Fatalf("verdict %q on a commit claiming an identity nothing proves", p.Verdict)
		}
	})
}

// A repository this deployment does not serve is not found, not empty.
func TestProveRefusesARepositoryItDoesNotServe(t *testing.T) {
	s := newProofScenario(t, proofOptions{})
	if _, err := s.prover(t).Prove(t.Context(), "github.com/someone/else", s.commit); err == nil {
		t.Fatal("Prove answered for a repository this deployment does not serve")
	}
}
