// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/mirror"
	"innsegl.dev/innsegl/internal/signing"
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
	sc, clientRepo, tree := spWiringSigningWith(t, resolver, spSignedHosted)
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
	sc, clientRepo, tree := spWiringSigningWith(t, resolver, spSignedHosted)
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

// spFailingMirror holds the repository but cannot be read.
type spFailingMirror struct{}

func (spFailingMirror) Dir(string) (string, error) { return "/mirror/unreadable.git", nil }
func (spFailingMirror) Missing(context.Context, string, []string) ([]string, error) {
	return nil, errors.New("git cat-file failed: permission denied")
}
func (spFailingMirror) DropStaging(context.Context, string, string, string) error { return nil }
func (spFailingMirror) StoreSigned(context.Context, string, string, []byte) error { return nil }

// A mirror that exists but cannot be read is refused naming the read, not
// reported as missing objects: the client cannot fix it by pushing again.
func TestHostedSignRefusesWhenTheMirrorCannotBeRead(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{spToolUseID: spHostedCall()}}
	_, _, tree := spWiringSigningWith(t, resolver, spSignedOK)
	spWithMirror(t, spFailingMirror{})

	_, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID, Payload: spPayloadWithTree(t, spClaim(spRunID), tree, spAuthor, spAuthor),
	})
	if err == nil || !strings.Contains(err.Error(), "reading the core's mirror of "+spRepo) {
		t.Fatalf("err = %v, want the refusal naming the unreadable mirror", err)
	}
}

// After a hosted signature the mirror holds the signed commit itself, so a
// core that reads repositories only from its mirror can prove it (ADR-0065).
func TestHostedSignKeepsTheSignedCommitInTheMirror(t *testing.T) {
	sha := spHostedSignedSHA
	signed := spSignedHosted

	resolver := spResolver{calls: map[string]commitpath.RelayedCall{spToolUseID: spHostedCall()}}
	sc, clientRepo, tree := spWiringSigningWith(t, resolver, signed)
	sc.space.dir = t.TempDir()
	store := spMirrorStore(t)
	spWithMirror(t, store)
	spPushToMirror(t, store, clientRepo, tree)

	if _, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID, Payload: spPayloadWithTree(t, spClaim(spRunID), tree, spAuthor, spAuthor),
	}); err != nil {
		t.Fatalf("hosted sign: %v", err)
	}
	dir, err := store.Dir(spRepo)
	if err != nil {
		t.Fatal(err)
	}
	if got, rerr := gitOut(t, dir, "rev-parse", "--verify", "--quiet", mirror.SignedRefPrefix+sha); rerr != nil || strings.TrimSpace(got) != sha {
		t.Fatalf("the mirror does not hold the signed commit %s: %q %v", sha, got, rerr)
	}
}

// spHostedSigned is a signed commit object the hosted fakes hand back, with
// its real id, so the mirror can keep it as it keeps a real one.
var spHostedSigned = []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
	"author a <a@example.invalid> 0 +0000\ncommitter a <a@example.invalid> 0 +0000\n" +
	"gpgsig SIG\n\nmessage\n")

var spHostedSignedSHA = func() string {
	sum := sha1.Sum(append([]byte("commit "+strconv.Itoa(len(spHostedSigned))+"\x00"), spHostedSigned...))
	return hex.EncodeToString(sum[:])
}()

// spSignedHosted is spSignedOK with the signed commit object a hosted core
// keeps in its mirror.
func spSignedHosted(ctx context.Context, s *signing.Signer, req signing.PayloadRequest) (signing.PayloadResult, error) {
	r, err := spSignedOK(ctx, s, req)
	r.CommitSHA, r.Object = spHostedSignedSHA, spHostedSigned
	return r, err
}

// spRefusingStore is a real mirror whose StoreSigned refuses, as a full
// disk or an unwritable mirror would.
type spRefusingStore struct{ *mirror.Store }

func (spRefusingStore) StoreSigned(context.Context, string, string, []byte) error {
	return errors.New("no space left on device")
}

// A signed commit the mirror cannot keep is a signing failure: no signature
// is handed back and nothing is recorded, so the ledger never holds a commit
// the core cannot prove.
func TestHostedSignFailsWhenTheMirrorCannotKeepTheSignedCommit(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{spToolUseID: spHostedCall()}}
	sc, clientRepo, tree := spWiringSigningWith(t, resolver, spSignedHosted)
	sc.space.dir = t.TempDir()
	store := spMirrorStore(t)
	spWithMirror(t, spRefusingStore{store})
	spPushToMirror(t, store, clientRepo, tree)

	got, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID, Payload: spPayloadWithTree(t, spClaim(spRunID), tree, spAuthor, spAuthor),
	})
	if err == nil || !strings.Contains(err.Error(), "could not be kept in the mirror") {
		t.Fatalf("err = %v, want the refusal naming the mirror", err)
	}
	if len(got.Signature) != 0 {
		t.Fatal("a signature was handed back for a commit the mirror could not keep")
	}
	if recorded := sc.ledger.ofType(event.EventTypeCommitRecorded); len(recorded) != 0 {
		t.Fatalf("commit_recorded appended for a commit the mirror could not keep: %+v", recorded)
	}
}
