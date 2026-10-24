// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"time"
)

// mirrorsnapshot.go — #467, ADR-0065 decision 3: a hosted core's workspace
// snapshots. The core reads no client's working tree, so it cannot take the
// snapshot itself (snapshot.go). The client takes it after each tool call
// and pushes it to the mirror as that tool call's snapshot ref; the recorder
// puts its tree on the tool call's workspace_tree_hash only when the mirror
// holds the tree. A snapshot that has not arrived within the wait is not
// recorded: a witness, never a gate. The ledger holds the tree's hash only
// (E4); the tree itself is in the mirror.

// MirrorSnapshots answers the tree of the snapshot an installation pushed
// for one tool call, and whether the mirror holds it (mirror.Store).
type MirrorSnapshots interface {
	SnapshotTree(ctx context.Context, repo, installation, toolUseID string) (string, bool, error)
}

// DefaultMirrorSnapshotWait bounds how long a recording waits for the
// client's snapshot. The client takes it before the tool call's result
// leaves the machine and pushes it at once, so it is normally there first;
// the wait covers a slow push. It is spent on the recording's own
// goroutine, never on the request.
const DefaultMirrorSnapshotWait = 10 * time.Second

// mirrorSnapshotPoll is how often a waiting recording asks the mirror again.
const mirrorSnapshotPoll = 200 * time.Millisecond

// mirrorTree answers the tree the client pushed for toolUseID, or "" when
// the mirror does not hold one within the wait. Only a call a client
// installation relayed, in a repository it stated, has one to look for.
func (r *ToolCallRecorder) mirrorTree(ctx context.Context, toolUseID string, call pendingCall) (string, bool) {
	if r.mirrorSnaps == nil || call.installation == "" || call.repo == "" {
		return "", false
	}
	deadline := time.Now().Add(r.mirrorWait)
	for {
		tree, held, err := r.mirrorSnaps.SnapshotTree(ctx, call.repo, call.installation, toolUseID)
		if err != nil {
			r.onFailure(fmt.Errorf("gateway: reading the client's workspace snapshot for tool_use %q: %w", toolUseID, err))
			return "", true
		}
		if held {
			return tree, false
		}
		if !time.Now().Add(mirrorSnapshotPoll).Before(deadline) {
			return "", false
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err() != nil
		case <-time.After(mirrorSnapshotPoll):
		}
	}
}
