// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/signing"
)

// ADP-008 — sign_commit's `adopt_run`, ADR-0051 decisions 1 to 4, #298.
//
// The dead run's work is proved against its own bodies (ADP-001..003 prove
// the rebuild itself); what is asserted here is that sign_commit asks that
// question before it records anything, refuses by name when the answer is no,
// and when it is yes records the handover as its own event, ties the intent
// to it, and has the signer name both runs.

// scAdoption is the evidence sign_commit reads about the dead run.
type scAdoption struct {
	state   string
	events  []event.Fields
	bodyDir string
	staged  map[string][]byte
	err     error
}

func (a *scAdoption) AdoptionEvidence(context.Context, string) (string, []event.Fields, error) {
	return a.state, a.events, a.err
}

func (a *scAdoption) StagedFiles(context.Context, string) (map[string][]byte, error) {
	return a.staged, nil
}

func (a *scAdoption) BodyDir() string { return a.bodyDir }

// adoptWiring is a sign_commit whose staged index holds exactly what the dead
// run's last Write left in one path.
func adoptWiring(t *testing.T) (*scWiring, *scAdoption, *adpFixture) {
	t.Helper()
	w := newSCWiring()
	f := newADPFixture(t)
	f.write("pkg/left.go", "package pkg\n\n// left behind\n")
	a := &scAdoption{
		state:   "retired",
		events:  f.events,
		bodyDir: f.bodyDir,
		staged:  map[string][]byte{"pkg/left.go": []byte("package pkg\n\n// left behind\n")},
	}
	w.cfg.Adoption = a
	return w, a, f
}

func adoptIn(f *adpFixture) signCommitIn {
	in := scIn()
	in.AdoptRun = f.runID
	return in
}

func TestADP008AnAdoptionIsRecordedTiedToItsIntentAndNamedInTheCommit(t *testing.T) {
	w, _, f := adoptWiring(t)

	if _, err := w.call(t, adoptIn(f)); err != nil {
		t.Fatalf("sign_commit: %v", err)
	}

	adopted := w.ledger.only(t, event.EventTypeRunAdopted)
	if got := scMember[string](t, adopted, event.FieldAdoptedRunID); got != f.runID {
		t.Errorf("adopted_run_id = %q, want %q", got, f.runID)
	}
	if got := scMember[string](t, adopted, event.FieldAdoptedRunState); got != "retired" {
		t.Errorf("adopted_run_state = %q, want the ledger's word, retired", got)
	}
	if got := scMember[string](t, adopted, event.FieldRunID); got != scRunID {
		t.Errorf("run_id = %q, want the signing run %q", got, scRunID)
	}

	// The claim is a stored body, and it says what was handed over and which
	// tool call proved it.
	digest := scMember[string](t, adopted, event.FieldPayloadDigest)
	raw, err := os.ReadFile(filepath.Join(f.bodyDir, scRunID,
		strings.TrimPrefix(digest, event.HashPrefix)+observeBodyExt))
	if err != nil {
		t.Fatalf("the claim is not stored under its digest: %v", err)
	}
	if event.Digest(raw) != digest {
		t.Fatal("the stored claim does not match its digest")
	}
	var claim adoptionClaim
	if err := json.Unmarshal(raw, &claim); err != nil {
		t.Fatalf("the claim is not the adoption claim: %v", err)
	}
	if claim.AdoptedRunID != f.runID || len(claim.Paths) != 1 ||
		claim.Paths[0].Path != "pkg/left.go" || claim.Paths[0].ToolCall != f.events[0][event.EventHashField] {
		t.Errorf("claim = %+v", claim)
	}

	// Recorded BEFORE the intent, and the intent names it.
	intent := w.ledger.only(t, event.EventTypeCommitIntent)
	if scMember[int64](t, adopted, event.FieldChainPosition) >= scMember[int64](t, intent, event.FieldChainPosition) {
		t.Error("run_adopted was appended after the intent it is the reason for")
	}
	if got := scMember[string](t, intent, event.FieldAdoptionEventID); got != scMember[string](t, adopted, event.FieldEventID) {
		t.Errorf("adoption_event_id = %q, want the run_adopted event's id", got)
	}

	// The signer was asked to name both runs.
	if len(w.signer.reqs) != 1 || w.signer.reqs[0].Claim.AdoptedRun != f.runID {
		t.Errorf("the signer's claim did not name the adopted run: %+v", w.signer.reqs)
	}
}

func TestADP008APlainCommitIsUnchanged(t *testing.T) {
	w, _, _ := adoptWiring(t)
	if _, err := w.call(t, scIn()); err != nil {
		t.Fatalf("sign_commit: %v", err)
	}
	if got := w.ledger.ofType(event.EventTypeRunAdopted); len(got) != 0 {
		t.Errorf("a commit adopting nothing appended %d run_adopted", len(got))
	}
	if _, ok := w.ledger.only(t, event.EventTypeCommitIntent)[event.FieldAdoptionEventID]; ok {
		t.Error("a plain intent carries adoption_event_id")
	}
	if w.signer.reqs[0].Claim.AdoptedRun != "" {
		t.Error("a plain commit's claim names an adopted run")
	}
}

func TestADP008EveryRefusalRecordsNothingAndSaysWhy(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*scWiring, *scAdoption, *signCommitIn)
		want  string
		class Class
	}{
		{"a deployment with no adoption configured", func(w *scWiring, _ *scAdoption, _ *signCommitIn) {
			w.cfg.Adoption = nil
		}, "not configured", ClassInvariantViolation},
		{"a run adopting itself", func(_ *scWiring, _ *scAdoption, in *signCommitIn) {
			in.AdoptRun = scRunID
		}, "adopt its own", ClassInvariantViolation},
		{"a run the ledger still calls active", func(_ *scWiring, a *scAdoption, _ *signCommitIn) {
			a.state = "active"
		}, "active", ClassInvariantViolation},
		{"a run the ledger does not know", func(_ *scWiring, a *scAdoption, _ *signCommitIn) {
			a.state, a.events = "", nil
		}, "no run", ClassRunNotFound},
		{"staged bytes that are not what the run left", func(_ *scWiring, a *scAdoption, _ *signCommitIn) {
			a.staged["pkg/left.go"] = []byte("package pkg\n\n// edited since\n")
		}, "pkg/left.go", ClassInvariantViolation},
		{"a staged path the run never wrote", func(_ *scWiring, a *scAdoption, _ *signCommitIn) {
			a.staged["pkg/mine.go"] = []byte("x\n")
		}, "pkg/mine.go", ClassInvariantViolation},
		{"an empty index", func(_ *scWiring, a *scAdoption, _ *signCommitIn) {
			a.staged = map[string][]byte{}
		}, "nothing", ClassInvariantViolation},
		{"evidence that cannot be read", func(_ *scWiring, a *scAdoption, _ *signCommitIn) {
			a.err = errors.New("ledger down")
		}, "", ClassLedgerUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, a, f := adoptWiring(t)
			in := adoptIn(f)
			tc.setup(w, a, &in)

			_, err := w.call(t, in)
			e := requireClassed(t, err, tc.class)
			if tc.want != "" && !strings.Contains(e.Error(), tc.want) {
				t.Errorf("err = %v, want it to say %q", err, tc.want)
			}
			if n := len(w.ledger.records); n != 0 {
				t.Errorf("a refused adoption appended %d events", n)
			}
			if w.signer.calls != 0 {
				t.Error("a refused adoption reached the signer")
			}
		})
	}
}

// The trailer rides on the claim, so the rendered commit names both runs.
func TestADP008TheSignedTrailersNameBothRuns(t *testing.T) {
	w, _, f := adoptWiring(t)
	out, err := w.call(t, adoptIn(f))
	if err != nil {
		t.Fatalf("sign_commit: %v", err)
	}
	var found bool
	for _, tr := range out.Trailers {
		if tr.Key == signing.TrailerAgentAdoptedRun && tr.Value == f.runID {
			found = true
		}
	}
	if !found {
		t.Errorf("trailers = %+v, want %s: %s", out.Trailers, signing.TrailerAgentAdoptedRun, f.runID)
	}
}

// Every remaining error return, each on its own (IP §2's branch floor over an
// MCP tool's error paths). None may record anything or reach the signer
// except where the failure is itself the recording.
func TestADP008EveryOtherErrorReturnAnswers(t *testing.T) {
	t.Run("the staged files cannot be read", func(t *testing.T) {
		w, a, f := adoptWiring(t)
		w.cfg.Adoption = stagedErr{a}
		_, err := w.call(t, adoptIn(f))
		requireClass(t, err, ClassInvariantViolation)
	})

	t.Run("the claim cannot be encoded", func(t *testing.T) {
		w, _, f := adoptWiring(t)
		old := adoptionMarshal
		adoptionMarshal = func(any) ([]byte, error) { return nil, errors.New("no") }
		t.Cleanup(func() { adoptionMarshal = old })
		_, err := w.call(t, adoptIn(f))
		requireClass(t, err, ClassInvariantViolation)
	})

	t.Run("the claim cannot be stored", func(t *testing.T) {
		w, a, f := adoptWiring(t)
		// The signing run's directory is a FILE, so no body can go under it.
		if err := os.WriteFile(filepath.Join(a.bodyDir, scRunID), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := w.call(t, adoptIn(f)); err == nil {
			t.Fatal("a claim that could not be stored was recorded")
		}
		if n := len(w.ledger.ofType(event.EventTypeRunAdopted)); n != 0 {
			t.Errorf("run_adopted appended with no claim behind it: %d", n)
		}
	})

	t.Run("run_adopted cannot be appended", func(t *testing.T) {
		w, _, f := adoptWiring(t)
		w.ledger.failOn[event.EventTypeRunAdopted] = errors.New("ledger down")
		if _, err := w.call(t, adoptIn(f)); err == nil {
			t.Fatal("an adoption the ledger refused went on to sign")
		}
		if n := len(w.ledger.ofType(event.EventTypeCommitIntent)); n != 0 {
			t.Errorf("an intent was appended for an adoption that was not: %d", n)
		}
	})
}

type stagedErr struct{ *scAdoption }

func (stagedErr) StagedFiles(context.Context, string) (map[string][]byte, error) {
	return nil, errors.New("index unreadable")
}
