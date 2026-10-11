// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

// ADR-0060 decision 5, as amended 2026-10-03: the workspace snapshot reads a
// working tree on the core's own disk, and on a hosted core no client's tree
// is there (ADR-0064 decision 2). A snapshot taken there would be of
// whatever happens to be on the core, recorded as if it were the client's.
// So the hosted core builds no snapshotter and says why, once, at start-up;
// the single-host shape keeps it.
func TestTheHostedCoreTakesNoWorkspaceSnapshots(t *testing.T) {
	t.Setenv(envObserveBodyDir, t.TempDir())

	var log bytes.Buffer
	running := &runningGateway{log: newServeLog(&log)}
	if snap := newGatewaySnapshotter(running, true); snap != nil {
		t.Fatal("the hosted core built a workspace snapshotter")
	}
	if !strings.Contains(log.String(), "hosted") || !strings.Contains(log.String(), "workspace_tree_hash") {
		t.Errorf("the start-up log does not say why there are no snapshots:\n%s", log.String())
	}
	if cfg := newToolCallRecorderConfig(running, &hostedCore{}); cfg.Snapshots != nil {
		t.Error("the hosted core's tool-call recorder carries a snapshotter")
	}

	if snap := newGatewaySnapshotter(&runningGateway{log: newServeLog(&bytes.Buffer{})}, false); snap == nil {
		t.Error("the single-host shape lost its snapshotter")
	}
}

// SNAP-008: a hosted core that keeps a mirror reads the client's snapshots
// from it (#467); without a mirror, or on a single host, it does not.
func TestSNAP008TheHostedCoreReadsClientSnapshotsFromItsMirror(t *testing.T) {
	running := &runningGateway{log: newServeLog(&bytes.Buffer{})}
	store, err := openCoreMirror(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if cfg := newToolCallRecorderConfig(running, &hostedCore{mirror: store}); cfg.MirrorSnapshots == nil {
		t.Error("the hosted core with a mirror does not read client snapshots from it")
	}
	if cfg := newToolCallRecorderConfig(running, &hostedCore{}); cfg.MirrorSnapshots != nil {
		t.Error("a hosted core with no mirror reads client snapshots")
	}
	t.Setenv(envObserveBodyDir, t.TempDir())
	if cfg := newToolCallRecorderConfig(running, nil); cfg.MirrorSnapshots != nil || cfg.Snapshots == nil {
		t.Error("the single-host shape changed its snapshot source")
	}
}
