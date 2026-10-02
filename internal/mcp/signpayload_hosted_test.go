// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/mirror"
)

// #464/#465, ADR-0065: on a hosted core the commit's objects exist only on
// the client. The client pushes them to the core's mirror before asking for
// a signature, and the sign path reads the mirror — never the directory the
// client stated, which names a path on another machine.

const spInstallation = "0123456789abcdef0123456789abcdef"

// spHostedCall is a relayed `git commit` from a hosted client: it carries
// the installation and a working directory that exists only on the client.
func spHostedCall() commitpath.RelayedCall {
	call := spPendingGitCommit(spRunID)
	call.Installation = spInstallation
	call.WorkingDirectory = "/client/work/widgets"
	return call
}

// spWithMirror installs m as the sign path's mirror, the way
// spWiringSigningWith installs its signing step.
func spWithMirror(t *testing.T, m CommitMirror) {
	t.Helper()
	signPayloadMu.Lock()
	st := *signPayloadCfg
	st.mirror = m
	previous := signPayloadCfg
	signPayloadCfg = &st
	signPayloadMu.Unlock()
	t.Cleanup(func() { signPayloadMu.Lock(); signPayloadCfg = previous; signPayloadMu.Unlock() })
}

// spPushToMirror pushes the client repository's tree, as a throwaway commit,
// to the installation's staging ref in the mirror — what `innsegl sign` does
// on the client before it asks.
func spPushToMirror(t *testing.T, store *mirror.Store, clientRepo, tree string) string {
	t.Helper()
	dir, err := store.Ensure(t.Context(), spRepo)
	if err != nil {
		t.Fatal(err)
	}
	commit := scGit(t, clientRepo, "commit-tree", "--no-gpg-sign", "-m", "staging", tree)
	ref := commitpath.StagingRef(spInstallation, spToolUseID)
	scGit(t, clientRepo, "push", "--no-verify", "--quiet", dir, "+"+commit+":"+ref)
	return ref
}

func spMirrorStore(t *testing.T) *mirror.Store {
	t.Helper()
	store, err := mirror.New(filepath.Join(t.TempDir(), "mirror"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestHostedSignComputesThePatchIDFromTheMirror(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{spToolUseID: spHostedCall()}}
	sc, clientRepo, tree := spWiringSigningWith(t, resolver, spSignedOK)
	sc.space.dir = t.TempDir() // the core's own workspace must not be what is read
	store := spMirrorStore(t)
	spWithMirror(t, store)
	ref := spPushToMirror(t, store, clientRepo, tree)

	got, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID, Payload: spPayloadWithTree(t, spClaim(spRunID), tree, spAuthor, spAuthor),
	})
	if err != nil {
		t.Fatalf("hosted sign with the objects in the mirror: %v", err)
	}
	if string(got.Signature) != "SIG" {
		t.Fatalf("answer %+v", got)
	}
	want, err := commitPathPatchID(t.Context(), clientRepo, tree, nil)
	if err != nil {
		t.Fatal(err)
	}
	intents := sc.ledger.ofType(event.EventTypeCommitIntent)
	if len(intents) != 1 || intents[0][event.FieldPatchID] != want {
		t.Fatalf("commit_intent %+v, want patch id %s", intents, want)
	}
	dir, err := store.Dir(spRepo)
	if err != nil {
		t.Fatal(err)
	}
	if _, rerr := gitOut(t, dir, "rev-parse", "--verify", "--quiet", ref); rerr == nil {
		t.Fatalf("the staging ref %s survived the signature", ref)
	}
}

func TestHostedSignWithoutThePushIsRefusedNamingTheMissingObjects(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{spToolUseID: spHostedCall()}}
	sc, clientRepo, tree := spWiringSigningWith(t, resolver, spSignedOK)
	store := spMirrorStore(t)
	spWithMirror(t, store)
	// Another commit's objects arrived; this one's did not.
	other := scGit(t, clientRepo, "mktree")
	_ = spPushToMirror(t, store, clientRepo, other)

	_, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID, Payload: spPayloadWithTree(t, spClaim(spRunID), tree, spAuthor, spAuthor),
	})
	if err == nil || !strings.Contains(err.Error(), "no working tree for "+spRepo) || !strings.Contains(err.Error(), tree) {
		t.Fatalf("err = %v, want the no-working-tree refusal naming %s", err, tree)
	}
	if strings.Contains(err.Error(), "/client/work") {
		t.Fatalf("the refusal read the client's stated directory: %v", err)
	}
	if got := sc.ledger.ofType(event.EventTypeCommitIntent); len(got) != 0 {
		t.Fatalf("%d commit_intent appended before the refusal", len(got))
	}
}

func TestHostedSignRefusesARepositoryTheMirrorHasNeverSeen(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{spToolUseID: spHostedCall()}}
	_, _, tree := spWiringSigningWith(t, resolver, spSignedOK)
	spWithMirror(t, spMirrorStore(t))

	_, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID, Payload: spPayloadWithTree(t, spClaim(spRunID), tree, spAuthor, spAuthor),
	})
	if err == nil || !strings.Contains(err.Error(), "no working tree for "+spRepo) || !strings.Contains(err.Error(), "push") {
		t.Fatalf("err = %v, want the no-working-tree refusal saying what to push", err)
	}
}

func TestHostedSignRefusesWhenTheCoreKeepsNoMirror(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{spToolUseID: spHostedCall()}}
	_, clientRepo, tree := spWiringSigningWith(t, resolver, spSignedOK)
	scGit(t, clientRepo, "remote", "add", "origin", "https://"+spRepo+".git")

	_, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID, Payload: spPayloadWithTree(t, spClaim(spRunID), tree, spAuthor, spAuthor),
	})
	if err == nil || !strings.Contains(err.Error(), "no working tree for "+spRepo) || !strings.Contains(err.Error(), mirror.EnvDir) {
		t.Fatalf("err = %v, want the refusal naming %s", err, mirror.EnvDir)
	}
}

func gitOut(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	out, err := (GitRepos{}).git(t.Context(), dir, args...)
	return strings.TrimSpace(out), err
}
