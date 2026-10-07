// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/trusthistory"
	"innsegl.dev/innsegl/internal/trustwatch"
	"innsegl.dev/innsegl/internal/verify"
)

// ADR-0073 through the BFF. The deployment's Fulcio now publishes another
// root; the commit was signed under the old one. The history file is read on
// every proof, so a history the core writes after this process started is
// used without a restart: on a first update the two start together, and the
// API must not keep answering from before the seed.
func TestTheProverReadsTheTrustHistoryOnEveryProof(t *testing.T) {
	s := newProofScenario(t, proofOptions{})
	s.fulcio = newFakeCA(t, newTestCA(t).pem) // rotated: Fulcio publishes root B
	path := filepath.Join(t.TempDir(), trusthistory.FileName)

	p, err := NewProver(ProofConfig{
		FulcioURL: s.fulcio.URL, RekorURL: s.log.URL,
		Repos:            staticRepos{fixtureRepo: s.repo},
		Now:              func() time.Time { return s.integrated.Add(365 * 24 * time.Hour) },
		TrustHistoryFile: path,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// No file yet: the published root alone, and the commit fails.
	proof, err := p.Prove(ctx, fixtureRepo, s.commit)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Verdict != string(verify.VerdictFailed) {
		t.Fatalf("before the history: verdict %s, want failed", proof.Verdict)
	}

	h := trusthistory.New()
	if _, err = h.Record(trusthistory.KindFulcioRoot, s.ca.pem, s.integrated); err != nil {
		t.Fatal(err)
	}
	if err = trusthistory.Save(path, h); err != nil {
		t.Fatal(err)
	}
	proof, err = p.Prove(ctx, fixtureRepo, s.commit)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Verdict != string(verify.VerdictVerified) {
		t.Fatalf("with the history: verdict %s, want verified: %+v", proof.Verdict, proof.Checks)
	}

	// A history that cannot be read is said out loud, and the proof is still
	// an answer: the narrower verifier, never a wider one.
	if err = os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	proof, err = p.Prove(ctx, fixtureRepo, s.commit)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Verdict != string(verify.VerdictFailed) {
		t.Errorf("with an unreadable history: verdict %s, want failed", proof.Verdict)
	}
	if !strings.Contains(strings.Join(proof.Notes, "\n"), "trust history could not be read") {
		t.Errorf("the proof does not say the history was unreadable: %q", proof.Notes)
	}
}

// The CAs in use and their expiry, from the same history, for the dashboard.
func TestTheProverReportsTheExpiryOfEveryCAInUse(t *testing.T) {
	s := newProofScenario(t, proofOptions{})
	path := filepath.Join(t.TempDir(), trusthistory.FileName)
	p, err := NewProver(ProofConfig{
		FulcioURL: s.fulcio.URL, RekorURL: s.log.URL,
		Repos:            staticRepos{fixtureRepo: s.repo},
		TrustHistoryFile: path,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.TrustExpiries(time.Now()); len(got) != 0 {
		t.Errorf("no history yet, and expiries %+v", got)
	}
	h := trusthistory.New()
	if _, err := h.Record(trusthistory.KindFulcioRoot, s.ca.pem, s.integrated); err != nil {
		t.Fatal(err)
	}
	if err := trusthistory.Save(path, h); err != nil {
		t.Fatal(err)
	}
	got := p.TrustExpiries(s.ca.cert.NotAfter.AddDate(0, 0, -30))
	if len(got) != 1 || got[0].Warning != trusthistory.Warning90Days {
		t.Errorf("expiries = %+v, want the Fulcio root with a 90-day warning", got)
	}
	var none Prover
	if none.TrustExpiries(time.Now()) != nil {
		t.Error("a prover with no history file reports expiries")
	}
}

// The trust watch's problems, from beside the history, for the dashboard.
func TestTheProverReportsTheTrustWatchsProblems(t *testing.T) {
	dir := t.TempDir()
	p := &Prover{cfg: ProofConfig{TrustHistoryFile: filepath.Join(dir, trusthistory.FileName)}}
	if got := p.TrustProblems(); len(got) != 0 {
		t.Errorf("no status yet, and problems %+v", got)
	}
	body := `{"checked_at":"2026-10-07T00:00:00Z","problems":[{"text":"sentinel x failed","since":"2026-10-06T00:00:00Z"}]}`
	if err := os.WriteFile(filepath.Join(dir, trustwatch.StatusFileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := p.TrustProblems(); len(got) != 1 || got[0].Text != "sentinel x failed" {
		t.Errorf("problems = %+v", got)
	}
	var none *Prover
	if none.TrustProblems() != nil || (&Prover{}).TrustProblems() != nil {
		t.Error("a prover with no history file reports problems")
	}
}
