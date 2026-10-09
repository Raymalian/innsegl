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
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/signing"
)

// Adoption on the commit path — ADR-0079.
//
// ADP-021 (PROPOSED for doc 07): the search prepare-commit-msg runs. It names
// a dead run only when exactly one candidate proves the whole change, and the
// committing run touched none of it.
//
// ADP-008 and ADP-014, re-homed: the commit-sign path proves the run the
// payload's trailer names, before Phase A, with ADR-0051's refusals, records
// run_adopted before the intent that names it, and records nothing when it
// refuses.

const (
	cpDead  = "run-cpdead"
	cpDead2 = "run-cpdead2"
	cpWork  = "commit-sign path unit fixture\n" // spLocalRepo's staged work.txt
)

// cpAdoption is the commit path's adoption evidence, in memory.
type cpAdoption struct {
	states     map[string]string
	events     map[string][]event.Fields
	bodyDir    string
	changed    map[string][]byte
	parent     map[string]string
	candidates []string
	candErr    error
	evErr      error
	evErrFor   map[string]error
	changedErr error
	prior      map[string][]ledger.Adoption
	asked      int // DeadRuns calls
	since      time.Time
}

func (a *cpAdoption) AdoptionEvidence(_ context.Context, runID string) (string, []event.Fields, error) {
	if a.evErr != nil {
		return "", nil, a.evErr
	}
	if err := a.evErrFor[runID]; err != nil {
		return "", nil, err
	}
	return a.states[runID], a.events[runID], nil
}

func (a *cpAdoption) StagedFiles(context.Context, string) (map[string][]byte, error) {
	return a.changed, nil
}

func (a *cpAdoption) BodyDir() string { return a.bodyDir }

func (a *cpAdoption) Adoptions(_ context.Context, run string) ([]ledger.Adoption, error) {
	return a.prior[run], nil
}

func (a *cpAdoption) DeadRuns(_ context.Context, _ string, since time.Time, _ int) ([]string, error) {
	a.asked++
	a.since = since
	return a.candidates, a.candErr
}

func (a *cpAdoption) ChangedFiles(context.Context, string, string, string) (map[string][]byte, error) {
	return a.changed, a.changedErr
}

func (a *cpAdoption) ParentFile(_ context.Context, _, _, path string) ([]byte, bool, error) {
	b, ok := a.parent[path]
	return []byte(b), ok, nil
}

// newCPAdoption is a repository whose change is work.txt, written by cpDead
// (retired, registered for spRepo) through the gateway, and touched by no one
// else.
func newCPAdoption(t *testing.T) (*cpAdoption, *adpFixture) {
	t.Helper()
	f := newADPFixture(t)
	f.runID = cpDead
	f.gwWrite("work.txt", cpWork)
	a := &cpAdoption{
		states:     map[string]string{cpDead: "retired", spRunID: "active"},
		events:     map[string][]event.Fields{},
		bodyDir:    f.bodyDir,
		changed:    map[string][]byte{"work.txt": []byte(cpWork)},
		parent:     map[string]string{},
		candidates: []string{cpDead},
		prior:      map[string][]ledger.Adoption{},
	}
	a.sync(f)
	return a, f
}

// sync files the fixture's events by run, each behind its registration.
func (a *cpAdoption) sync(f *adpFixture) {
	a.events = map[string][]event.Fields{}
	for _, ev := range f.events {
		run := fieldString(ev, event.FieldRunID)
		if len(a.events[run]) == 0 {
			a.events[run] = append(a.events[run], event.Fields{
				event.FieldEventType: event.EventTypeRunRegistered, event.FieldRunID: run, event.FieldRepo: spRepo})
		}
		a.events[run] = append(a.events[run], ev)
	}
}

// cpService is a commit signer holding the adoption evidence.
func cpService(t *testing.T, a SignCommitAdoption) *signCommitService {
	t.Helper()
	w := newSCWiring()
	w.cfg.Adoption = a
	svc, err := newCommitSigner(w.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func cpSearch(t *testing.T, a *cpAdoption) (string, error) {
	t.Helper()
	return cpService(t, a).searchAdoption(context.Background(), spRunID, spRepo, "/repo",
		strings.Repeat("a", 40), strings.Repeat("b", 40), time.Now())
}

func TestADP021TheOneDeadRunThatProvesTheChangeIsProposed(t *testing.T) {
	a, _ := newCPAdoption(t)
	got, err := cpSearch(t, a)
	if err != nil || got != cpDead {
		t.Fatalf("search = %q, %v; want %s", got, err, cpDead)
	}
	if want := time.Now().Add(-AdoptionSearchWindow); a.since.After(want.Add(time.Minute)) || a.since.Before(want.Add(-time.Minute)) {
		t.Errorf("searched since %v, want the window, about %v", a.since, want)
	}
}

func TestADP021AnEditIsProvedOnTheParentsBlob(t *testing.T) {
	a, f := newCPAdoption(t)
	f.events = nil
	f.gwEdit("work.txt", "old line", "commit-sign path unit fixture", false)
	a.sync(f)
	a.parent["work.txt"] = "old line\n"
	if got, err := cpSearch(t, a); err != nil || got != cpDead {
		t.Fatalf("search = %q, %v; want the edit proved on the parent's blob", got, err)
	}
}

func TestADP021NoProposalWhenTheChangeIsNotExactlyOneDeadRunsWork(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*cpAdoption, *adpFixture)
	}{
		{"two dead runs prove it", func(a *cpAdoption, f *adpFixture) {
			f.runID = cpDead2
			f.gwWrite("work.txt", cpWork)
			a.states[cpDead2] = "retired"
			a.candidates = []string{cpDead, cpDead2}
			a.sync(f)
		}},
		{"a changed path the dead run never wrote", func(a *cpAdoption, _ *adpFixture) {
			a.changed["mine.txt"] = []byte("mine\n")
		}},
		{"bytes the dead run did not leave", func(a *cpAdoption, _ *adpFixture) {
			a.changed["work.txt"] = []byte("edited since\n")
		}},
		{"the committing run wrote a changed path too", func(a *cpAdoption, f *adpFixture) {
			f.runID = spRunID
			f.gwWrite("work.txt", cpWork)
			a.sync(f)
		}},
		{"the candidate is still active", func(a *cpAdoption, _ *adpFixture) {
			a.states[cpDead] = "active"
		}},
		{"its work was adopted and committed before", func(a *cpAdoption, _ *adpFixture) {
			spendWorkTxt(a)
		}},
		{"its bodies are gone", func(a *cpAdoption, _ *adpFixture) {
			if err := os.RemoveAll(filepath.Join(a.bodyDir, cpDead)); err != nil {
				panic(err)
			}
		}},
		{"no candidates", func(a *cpAdoption, _ *adpFixture) {
			a.candidates = nil
		}},
		{"an empty change", func(a *cpAdoption, _ *adpFixture) {
			a.changed = map[string][]byte{}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, f := newCPAdoption(t)
			tc.setup(a, f)
			if got, err := cpSearch(t, a); err != nil || got != "" {
				t.Errorf("search = %q, %v; want no proposal", got, err)
			}
		})
	}
}

func TestADP021AnUnreadableLedgerRefusesTheSearch(t *testing.T) {
	a, _ := newCPAdoption(t)
	a.candErr = &ledger.StoreError{Class: ledger.ClassLedgerUnavailable, Op: "dead_runs_for_repo",
		Retryable: true, Err: errors.New("down")}
	if _, err := cpSearch(t, a); Classify(err).Class != ClassLedgerUnavailable {
		t.Errorf("err = %v, want LEDGER_UNAVAILABLE", err)
	}
}

func TestADP021NoAdoptionEvidenceMeansNoSearch(t *testing.T) {
	svc := cpService(t, nil)
	got, err := svc.searchAdoption(context.Background(), spRunID, spRepo, "/repo",
		strings.Repeat("a", 40), strings.Repeat("b", 40), time.Now())
	if err != nil || got != "" {
		t.Errorf("search with no adoption configured = %q, %v; want none", got, err)
	}
}

// AdoptionForCommit is what the trailers step asks: it looks only for a
// plain `git commit` with a tree and at most one parent.
func TestADP021OnlyAPlainCommitIsSearched(t *testing.T) {
	for _, tc := range []struct {
		name, command string
		tree          string
		parents       []string
		want          string
	}{
		{"a plain commit", "git add -A && git commit -m x", "t", []string{"p"}, cpDead},
		{"a root commit", "git commit -m x", "t", nil, cpDead},
		{"an amend", "git commit --amend -m x", "t", []string{"p"}, ""},
		{"a merge", "git merge dev", "t", []string{"p"}, ""},
		{"no tree sent", "git commit -m x", "", []string{"p"}, ""},
		{"two parents", "git commit -m x", "t", []string{"p", "q"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := newCPAdoption(t)
			repo, _ := spLocalRepo(t)
			call := spPendingGitCommit(spRunID)
			call.Input = json.RawMessage(`{"command":` + jsonString(tc.command) + `}`)
			call.WorkingDirectory = repo
			scGit(t, repo, "remote", "add", "origin", "https://"+spRepo+".git")
			resolver := spResolver{calls: map[string]commitpath.RelayedCall{spToolUseID: call}}
			sc := newSCWiring()
			sc.runs.run = CredentialRun{RunID: spRunID, AgentType: "demo", TaskID: spTaskID,
				SPIFFEID: spSPIFFEID(spRunID), Repo: spRepo}
			sc.cfg.Adoption = a
			restore, err := ConfigureCommitSigner(sc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(restore)
			restoreSP, err := ConfigureSignPayload(SignPayloadConfig{Resolver: resolver, ClaimFor: spClaimForOK(t)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(restoreSP)

			tree := tc.tree
			if tree != "" {
				tree = strings.Repeat("a", 40)
			}
			var parents []string
			for range tc.parents {
				parents = append(parents, strings.Repeat("b", 40))
			}
			got, err := AdoptionForCommit(context.Background(), call, tree, parents)
			if err != nil || got != tc.want {
				t.Errorf("AdoptionForCommit = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// spendWorkTxt records an earlier, committed adoption of cpDead's work.txt.
func spendWorkTxt(a *cpAdoption) {
	claim, err := json.Marshal(adoptionClaim{AdoptedRunID: cpDead, Paths: []adoptionClaimPath{{
		Path: "work.txt", SHA256: strings.TrimPrefix(event.Digest([]byte(cpWork)), event.HashPrefix)}}})
	if err != nil {
		panic(err)
	}
	digest := event.Digest(claim)
	if err := observeWriteBody(a.bodyDir, "run-earlier", digest, claim); err != nil {
		panic(err)
	}
	a.prior[cpDead] = []ledger.Adoption{{EventID: "e", RunID: "run-earlier", PayloadDigest: digest, Committed: true}}
}

// ---------------------------------------------------------------------------
// ADP-008 and ADP-014 on the commit path: signing proves the named run.
// ---------------------------------------------------------------------------

// cpSigning is a commit-sign path that signs (Phase B faked) with the
// adoption evidence installed, and a payload whose trailers adopt cpDead.
func cpSigning(t *testing.T) (*scWiring, *cpAdoption, []byte) {
	t.Helper()
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{spToolUseID: spPendingGitCommit(spRunID)}}
	sc, _, tree := spWiringSigningWith(t, resolver, spSignedOK)
	a, _ := newCPAdoption(t)
	sc.cfg.Adoption = a
	restore, err := ConfigureSignCommit(sc.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	claim := spClaim(spRunID)
	claim.AdoptedRun = cpDead
	return sc, a, spPayloadWithTree(t, claim, tree, spAuthor, spAuthor)
}

func cpSign(payload []byte) error {
	_, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID, Args: []string{"--status-fd=2"}, Payload: payload,
	})
	return err
}

func TestADP008OnTheCommitPathAnAdoptionIsRecordedBeforeItsIntent(t *testing.T) {
	sc, a, payload := cpSigning(t)
	if err := cpSign(payload); err != nil {
		t.Fatalf("SignPayloadForGateway: %v", err)
	}
	adopted := sc.ledger.only(t, event.EventTypeRunAdopted)
	if got := scMember[string](t, adopted, event.FieldAdoptedRunID); got != cpDead {
		t.Errorf("adopted_run_id = %q, want %q", got, cpDead)
	}
	if got := scMember[string](t, adopted, event.FieldAdoptedRunState); got != "retired" {
		t.Errorf("adopted_run_state = %q, want the ledger's word", got)
	}
	if got := scMember[string](t, adopted, event.FieldRunID); got != spRunID {
		t.Errorf("run_id = %q, want the signing run", got)
	}
	if !strings.HasPrefix(scMember[string](t, adopted, event.FieldIdempotencyKey), "commit_sign_payload/adopted/") {
		t.Errorf("idempotency_key = %q, want the commit path's own", adopted[event.FieldIdempotencyKey])
	}
	digest := scMember[string](t, adopted, event.FieldPayloadDigest)
	raw, err := os.ReadFile(filepath.Join(a.bodyDir, spRunID, strings.TrimPrefix(digest, event.HashPrefix)+observeBodyExt))
	if err != nil || event.Digest(raw) != digest {
		t.Fatalf("the claim is not stored under its digest: %v", err)
	}
	intent := sc.ledger.only(t, event.EventTypeCommitIntent)
	if scMember[int64](t, adopted, event.FieldChainPosition) >= scMember[int64](t, intent, event.FieldChainPosition) {
		t.Error("run_adopted was appended after the intent")
	}
	if got := scMember[string](t, intent, event.FieldAdoptionEventID); got != scMember[string](t, adopted, event.FieldEventID) {
		t.Errorf("adoption_event_id = %q, want the run_adopted event's id", got)
	}
	if n := len(sc.ledger.ofType(event.EventTypeCommitRecorded)); n != 1 {
		t.Errorf("%d commit_recorded, want 1", n)
	}
}

func TestADP008OnTheCommitPathAPlainPayloadIsUnchanged(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{spToolUseID: spPendingGitCommit(spRunID)}}
	sc2, _, tree := spWiringSigningWith(t, resolver, spSignedOK)
	a, _ := newCPAdoption(t)
	sc2.cfg.Adoption = a
	restore, err := ConfigureSignCommit(sc2.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	if err := cpSign(spPayloadWithTree(t, spClaim(spRunID), tree, spAuthor, spAuthor)); err != nil {
		t.Fatalf("a plain payload: %v", err)
	}
	if n := len(sc2.ledger.ofType(event.EventTypeRunAdopted)); n != 0 {
		t.Errorf("a plain commit appended %d run_adopted", n)
	}
	if _, ok := sc2.ledger.only(t, event.EventTypeCommitIntent)[event.FieldAdoptionEventID]; ok {
		t.Error("a plain intent carries adoption_event_id")
	}
}

func TestADP008OnTheCommitPathEveryRefusalRecordsNothing(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*scWiring, *cpAdoption) []byte
		want  string
	}{
		{"the run is still active", func(_ *scWiring, a *cpAdoption) []byte {
			a.states[cpDead] = "active"
			return nil
		}, "active"},
		{"the run is unknown", func(_ *scWiring, a *cpAdoption) []byte {
			delete(a.states, cpDead)
			return nil
		}, "no run"},
		{"the run was registered for another repository", func(_ *scWiring, a *cpAdoption) []byte {
			a.events[cpDead][0][event.FieldRepo] = "github.com/example-org/elsewhere"
			return nil
		}, "elsewhere"},
		{"bytes the run did not leave", func(_ *scWiring, a *cpAdoption) []byte {
			a.changed["work.txt"] = []byte("edited since\n")
			return nil
		}, "work.txt"},
		{"a path the run never wrote", func(_ *scWiring, a *cpAdoption) []byte {
			a.changed["mine.txt"] = []byte("mine\n")
			return nil
		}, "mine.txt"},
		{"ADP-014: bytes already adopted and committed", func(_ *scWiring, a *cpAdoption) []byte {
			spendWorkTxt(a)
			return nil
		}, "spent"},
		{"evidence that cannot be read", func(_ *scWiring, a *cpAdoption) []byte {
			a.evErr = errors.New("ledger down")
			return nil
		}, "could not"},
		{"no adoption configured", func(sc *scWiring, _ *cpAdoption) []byte {
			sc.cfg.Adoption = nil
			return nil
		}, "not configured"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc, a, payload := cpSigning(t)
			tc.setup(sc, a)
			if sc.cfg.Adoption == nil {
				restore, err := ConfigureSignCommit(sc.cfg)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(restore)
			}
			err := cpSign(payload)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want a refusal containing %q", err, tc.want)
			}
			for _, typ := range []string{event.EventTypeRunAdopted, event.EventTypeCommitIntent, event.EventTypeCommitRecorded} {
				if n := len(sc.ledger.ofType(typ)); n != 0 {
					t.Errorf("%d %s appended before the refusal", n, typ)
				}
			}
		})
	}
}

// A payload adopting the signing run itself is a claim error, refused at
// gate 2 with nothing recorded.
func TestADP008OnTheCommitPathARunCannotAdoptItself(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{spToolUseID: spPendingGitCommit(spRunID)}}
	sc, _, tree := spWiringSigningWith(t, resolver, spSignedOK)
	payload := spPayloadWithTree(t, spClaim(spRunID), tree, spAuthor, spAuthor)
	payload = append(payload, []byte(signing.TrailerAgentAdoptedRun+": "+spRunID+"\n")...)
	if err := cpSign(payload); err == nil || !strings.Contains(err.Error(), "own work") {
		t.Fatalf("err = %v, want self-adoption refused", err)
	}
	if n := len(sc.ledger.ofType(event.EventTypeCommitIntent)); n != 0 {
		t.Errorf("%d commit_intent appended", n)
	}
}

// ---------------------------------------------------------------------------
// The remaining branches of the search, the proof and the commit path.
// ---------------------------------------------------------------------------

func TestADP021TheSearchSkipsTheCommittingRunAndWhatItDidNotTouch(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*cpAdoption, *adpFixture)
	}{
		{"the committing run is among the candidates", func(a *cpAdoption, _ *adpFixture) {
			a.candidates = []string{spRunID, cpDead}
		}},
		{"the committing run's write failed", func(a *cpAdoption, f *adpFixture) {
			f.runID = spRunID
			f.gwCall("Write", map[string]any{"file_path": adpTop + "/work.txt", "content": "x\n"}, "denied", true, true)
			a.sync(f)
		}},
		{"the committing run wrote another path", func(a *cpAdoption, f *adpFixture) {
			f.runID = spRunID
			f.gwWrite("other.txt", "o\n")
			a.sync(f)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, f := newCPAdoption(t)
			tc.setup(a, f)
			if got, err := cpSearch(t, a); err != nil || got != cpDead {
				t.Errorf("search = %q, %v; want %s", got, err, cpDead)
			}
		})
	}
}

func TestADP021NoProposalWhenTheEvidenceCannotBeRead(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*cpAdoption, *adpFixture)
	}{
		{"the change cannot be read", func(a *cpAdoption, _ *adpFixture) {
			a.changedErr = errors.New("git refused")
		}},
		{"a body of the committing run is gone", func(a *cpAdoption, f *adpFixture) {
			f.runID = spRunID
			f.gwWrite("other.txt", "o\n")
			a.sync(f)
			if err := os.RemoveAll(filepath.Join(a.bodyDir, spRunID)); err != nil {
				t.Fatal(err)
			}
		}},
		{"a body of the committing run is not a tool call", func(a *cpAdoption, f *adpFixture) {
			f.runID = spRunID
			f.call(spRunID, "Write", map[string]any{"neither": "shape"})
			a.sync(f)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, f := newCPAdoption(t)
			tc.setup(a, f)
			if got, err := cpSearch(t, a); err != nil || got != "" {
				t.Errorf("search = %q, %v; want no proposal", got, err)
			}
		})
	}
}

func TestADP021ALedgerThatCannotSayWhatARunWroteRefusesTheSearch(t *testing.T) {
	for _, run := range []string{spRunID, cpDead} {
		a, _ := newCPAdoption(t)
		a.evErrFor = map[string]error{run: errors.New("down")}
		if _, err := cpSearch(t, a); Classify(err).Class != ClassLedgerUnavailable {
			t.Errorf("evidence of %s unreadable: err = %v, want LEDGER_UNAVAILABLE", run, err)
		}
	}
}

func TestADP021NoProposalWhereTheCommitCannotBeRead(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  CredentialRun
		dir  func(t *testing.T) string
	}{
		{"a run with no repository", CredentialRun{RunID: spRunID, AgentType: "demo", TaskID: spTaskID,
			SPIFFEID: spSPIFFEID(spRunID)}, func(t *testing.T) string {
			dir, _ := spLocalRepo(t)
			return dir
		}},
		{"a working directory that is not the run's repository", CredentialRun{RunID: spRunID, AgentType: "demo",
			TaskID: spTaskID, SPIFFEID: spSPIFFEID(spRunID), Repo: spRepo}, func(t *testing.T) string {
			return t.TempDir()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := newCPAdoption(t)
			call := spPendingGitCommit(spRunID)
			call.WorkingDirectory = tc.dir(t)
			sc := newSCWiring()
			sc.runs.run = tc.run
			sc.cfg.Adoption = a
			restore, err := ConfigureCommitSigner(sc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(restore)
			restoreSP, err := ConfigureSignPayload(SignPayloadConfig{
				Resolver: spResolver{calls: map[string]commitpath.RelayedCall{spToolUseID: call}}, ClaimFor: spClaimForOK(t)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(restoreSP)
			if got, err := AdoptionForCommit(context.Background(), call, strings.Repeat("a", 40), nil); err != nil || got != "" {
				t.Errorf("AdoptionForCommit = %q, %v; want none", got, err)
			}
		})
	}
}

// sign_commit's adopt_run replays a gateway Edit on HEAD's blob when its
// evidence can read one (ADR-0079 decision 4).
func TestADP008SignCommitReplaysAGatewayEditOnHEAD(t *testing.T) {
	a, f := newCPAdoption(t)
	f.events = nil
	f.gwEdit("work.txt", "old line", "commit-sign path unit fixture", false)
	a.sync(f)
	a.parent["work.txt"] = "old line\n"
	plan, err := cpService(t, a).planAdoption(context.Background(), spRunID, cpDead, "/repo")
	if err != nil || plan.adoptedRun != cpDead {
		t.Fatalf("planAdoption = %+v, %v; want the edit proved on HEAD's blob", plan, err)
	}
}

func TestADP008OnTheCommitPathAChangeThatCannotBeReadIsRefused(t *testing.T) {
	sc, a, payload := cpSigning(t)
	a.changedErr = errors.New("git refused")
	if err := cpSign(payload); err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Fatalf("err = %v, want the unreadable change refused", err)
	}
	if n := len(sc.ledger.ofType(event.EventTypeCommitIntent)); n != 0 {
		t.Errorf("%d commit_intent appended", n)
	}
}

func TestADP008OnTheCommitPathARunAdoptedThatCannotBeRecordedStopsBeforeTheIntent(t *testing.T) {
	sc, _, payload := cpSigning(t)
	sc.ledger.failOn[event.EventTypeRunAdopted] = errors.New("the chain is unreachable")
	if err := cpSign(payload); err == nil {
		t.Fatal("a run_adopted the ledger refused still signed")
	}
	if n := len(sc.ledger.ofType(event.EventTypeCommitIntent)); n != 0 {
		t.Errorf("%d commit_intent appended after run_adopted was refused", n)
	}
}

// A commit with a parent is proved against that parent.
func TestADP008OnTheCommitPathAChildCommitIsProvedAgainstItsParent(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{spToolUseID: spPendingGitCommit(spRunID)}}
	sc, _, _ := spWiringSigningWith(t, resolver, spSignedOK)
	repo, tree, parent := spLocalRepoWithParent(t)
	sc.space.dir = repo
	a, f := newCPAdoption(t)
	f.events = nil
	f.gwWrite("work.txt", "commit-sign path unit fixture: second change\n")
	a.sync(f)
	a.changed = map[string][]byte{"work.txt": []byte("commit-sign path unit fixture: second change\n")}
	sc.cfg.Adoption = a
	restore, err := ConfigureSignCommit(sc.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	claim := spClaim(spRunID)
	claim.AdoptedRun = cpDead
	if err := cpSign(spPayloadWithParent(t, claim, tree, parent, spAuthor, spAuthor)); err != nil {
		t.Fatalf("SignPayloadForGateway: %v", err)
	}
	if n := len(sc.ledger.ofType(event.EventTypeRunAdopted)); n != 1 {
		t.Errorf("%d run_adopted, want 1", n)
	}
}
