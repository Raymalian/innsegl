// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/client"
)

func TestCLIClientOutboxListsAndExportsArchivedRecords(t *testing.T) {
	home := t.TempDir()
	p := client.ClientPaths(home)
	const id = "0123456789abcdef0123456789abcdef"
	if err := os.MkdirAll(p.Outbox, 0o700); err != nil {
		t.Fatal(err)
	}
	item := filepath.Join(p.Outbox, "00000000000000000001.exchange")
	if err := os.WriteFile(item, []byte("signed record"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ArchiveOutboxForReplacement(p, id); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := runClientCommand(context.Background(), []string{"outbox", "list"}, &stdout, &stderr, home); code != exitOK {
		t.Fatalf("list = %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), id) || !strings.Contains(stdout.String(), "1 items") {
		t.Fatalf("list output = %q", stdout.String())
	}
	destination := filepath.Join(t.TempDir(), "recovered-records")
	stdout.Reset()
	if code := runClientCommand(context.Background(), []string{"outbox", "export", id, destination}, &stdout, &stderr, home); code != exitOK {
		t.Fatalf("export = %d: %s", code, stderr.String())
	}
	if got, err := os.ReadFile(filepath.Join(destination, filepath.Base(item))); err != nil || string(got) != "signed record" {
		t.Fatalf("exported record = %q, %v", got, err)
	}
}

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
