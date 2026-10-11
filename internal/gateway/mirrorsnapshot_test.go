// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// SNAP-008 (#467, ADR-0065 decision 3): on a hosted core the client
// snapshots its own working tree after each tool call and pushes it to the
// mirror. The recorder puts that tree on the tool call only when the mirror
// holds it -- a witness, never a gate: a snapshot that never arrives leaves
// the tool call recorded without one.

const (
	msInstallation = "0123456789abcdef0123456789abcdef"
	msRepo         = "github.com/acme/widgets"
	msTree         = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
)

// fakeMirrorSnapshots holds one snapshot, which "arrives" after `after`
// lookups.
type fakeMirrorSnapshots struct {
	mu      sync.Mutex
	asks    int
	after   int
	err     error
	key     [3]string
	lastKey [3]string
}

func (f *fakeMirrorSnapshots) SnapshotTree(_ context.Context, repo, installation, toolUseID string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asks++
	f.lastKey = [3]string{repo, installation, toolUseID}
	if f.err != nil {
		return "", false, f.err
	}
	if f.lastKey != f.key || f.asks <= f.after {
		return "", false, nil
	}
	return msTree, true, nil
}

func (f *fakeMirrorSnapshots) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.asks
}

func hostedCtx(installation string) context.Context {
	ctx := WithRequestFacts(context.Background(), RequestFacts{Stated: StatedWorkspace{Repo: msRepo}})
	if installation != "" {
		ctx = WithInstallation(ctx, installation)
	}
	return WithRunID(ctx, recTestRunID)
}

func TestSNAP008TheToolCallCarriesTheClientsSnapshotOnceTheMirrorHoldsIt(t *testing.T) {
	calls := &fakeRecordCalls{}
	snaps := &fakeMirrorSnapshots{after: 2, key: [3]string{msRepo, msInstallation, "toolu_ms1"}}
	rec := NewToolCallRecorder(ToolCallRecorderConfig{
		record: calls.fn, MirrorSnapshots: snaps, MirrorSnapshotWait: 5 * time.Second,
	})
	rec.OnToolUseContext(hostedCtx(msInstallation), recToolUse("toolu_ms1", "Write", `{}`))
	rec.HandleResults(context.Background(), recTestRunID, RequestFacts{ToolResultIDs: []string{"toolu_ms1"}},
		[]observedToolResult{recResult("toolu_ms1", `{}`, false)})
	waitForCalls(t, calls, 1)
	if got := calls.snapshot()[0].WorkspaceTreeHash; got != msTree {
		t.Fatalf("WorkspaceTreeHash = %q, want the mirror's %s", got, msTree)
	}
	if snaps.lastKey != snaps.key {
		t.Fatalf("the mirror was asked for %v, want %v", snaps.lastKey, snaps.key)
	}
}

func TestSNAP008ASnapshotTheMirrorNeverReceivesLeavesTheToolCallWithoutOne(t *testing.T) {
	for name, snaps := range map[string]*fakeMirrorSnapshots{
		"never arrives":     {after: 1 << 30},
		"mirror unreadable": {err: errors.New("disk gone")},
	} {
		t.Run(name, func(t *testing.T) {
			calls := &fakeRecordCalls{}
			rec := NewToolCallRecorder(ToolCallRecorderConfig{
				record: calls.fn, MirrorSnapshots: snaps, MirrorSnapshotWait: 300 * time.Millisecond,
			})
			rec.OnToolUseContext(hostedCtx(msInstallation), recToolUse("toolu_ms2", "Write", `{}`))
			rec.HandleResults(context.Background(), recTestRunID, RequestFacts{ToolResultIDs: []string{"toolu_ms2"}},
				[]observedToolResult{recResult("toolu_ms2", `{}`, false)})
			waitForCalls(t, calls, 1)
			if got := calls.snapshot()[0].WorkspaceTreeHash; got != "" {
				t.Fatalf("WorkspaceTreeHash = %q, want none", got)
			}
		})
	}
}

// A request with no installation (the single-host core) or no stated
// repository has no client snapshot to look for.
func TestSNAP008TheMirrorIsNotAskedWithoutAnInstallationAndARepository(t *testing.T) {
	snaps := &fakeMirrorSnapshots{}
	calls := &fakeRecordCalls{}
	rec := NewToolCallRecorder(ToolCallRecorderConfig{
		record: calls.fn, MirrorSnapshots: snaps, MirrorSnapshotWait: time.Second,
	})
	rec.OnToolUseContext(hostedCtx(""), recToolUse("toolu_ms3", "Write", `{}`))
	rec.OnToolUseContext(WithRunID(WithInstallation(context.Background(), msInstallation), recTestRunID),
		recToolUse("toolu_ms4", "Write", `{}`))
	rec.HandleResults(context.Background(), recTestRunID, RequestFacts{ToolResultIDs: []string{"toolu_ms3", "toolu_ms4"}},
		[]observedToolResult{recResult("toolu_ms3", `{}`, false), recResult("toolu_ms4", `{}`, false)})
	waitForCalls(t, calls, 2)
	if n := snaps.count(); n != 0 {
		t.Fatalf("the mirror was asked %d times", n)
	}
}
