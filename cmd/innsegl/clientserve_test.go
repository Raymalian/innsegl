// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCLI016ClientServeRefusesWithoutAnEnrolment(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runClientCommand(context.Background(), []string{"serve"}, &stdout, &stderr, t.TempDir())
	if code == exitOK || !strings.Contains(stderr.String(), "innsegl connect") {
		t.Fatalf("client serve = %d: %s", code, stderr.String())
	}
}

func TestCLI016ClientServeRefusesANonLoopbackListen(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runClientCommand(context.Background(), []string{"serve", "--listen", "0.0.0.0:28195"}, &stdout, &stderr, t.TempDir())
	if code != exitUsage || !strings.Contains(stderr.String(), "loopback") {
		t.Fatalf("client serve = %d: %s", code, stderr.String())
	}
}

func TestClientCommandNeedsAKnownStep(t *testing.T) {
	for _, args := range [][]string{nil, {"frobnicate"}} {
		var stdout, stderr bytes.Buffer
		if code := runClientCommand(context.Background(), args, &stdout, &stderr, t.TempDir()); code != exitUsage {
			t.Errorf("client %v = %d, want %d", args, code, exitUsage)
		}
	}
}
