// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// CLI-024 (PROPOSED for doc 07, #592) — where the client service's log is,
// said for the OS it runs on. macOS writes ~/Library/Logs; a systemd --user
// unit writes the user journal; anything else has no service at all.
func TestCLI024TheServiceLogHintIsRightPerOS(t *testing.T) {
	for goos, want := range map[string]string{
		"darwin":  "~/Library/Logs/" + LogFileName,
		"linux":   "journalctl --user -u " + SystemdUnit,
		"freebsd": "innsegl client serve",
	} {
		got := LogHint(goos)
		if !strings.Contains(got, want) {
			t.Errorf("LogHint(%s) = %q, want it to name %q", goos, got, want)
		}
		if goos != "darwin" && strings.Contains(got, "Library") {
			t.Errorf("LogHint(%s) = %q points at the macOS log", goos, got)
		}
	}
}

// CLI-026 (PROPOSED, #592) — on Linux the signing-down notification goes
// through notify-send, with the text as arguments after "--" so a message
// that starts with a dash is never read as an option. Without notify-send
// nothing runs, and the notifier says so once, which the service logs.
func TestCLI026LinuxNotifiesThroughNotifySend(t *testing.T) {
	var ran [][]string
	run := func(_ context.Context, name string, args ...string) error {
		ran = append(ran, append([]string{name}, args...))
		return nil
	}
	found := func(name string) (string, error) { return "/usr/bin/" + name, nil }
	n := desktopNotifier("linux", found, run)
	if err := n(t.Context(), "innsegl: signing", "-rf; $(rm)"); err != nil {
		t.Fatal(err)
	}
	if len(ran) != 1 || ran[0][0] != "notify-send" {
		t.Fatalf("ran %q; want one notify-send", ran)
	}
	args := strings.Join(ran[0], "\x00")
	if !strings.HasSuffix(args, "\x00--\x00innsegl: signing\x00-rf; $(rm)") {
		t.Fatalf("the text is not passed as arguments after --: %q", ran[0])
	}
}

func TestCLI026WithoutNotifySendNothingRunsAndItIsSaidOnce(t *testing.T) {
	var ran [][]string
	run := func(_ context.Context, name string, args ...string) error {
		ran = append(ran, append([]string{name}, args...))
		return nil
	}
	missing := func(string) (string, error) { return "", exec.ErrNotFound }
	n := desktopNotifier("linux", missing, run)
	err := n(t.Context(), "t", "b")
	if err == nil || !strings.Contains(err.Error(), "notify-send") {
		t.Fatalf("the first notification without notify-send said %v; want it named", err)
	}
	if err := n(t.Context(), "t", "b"); err != nil {
		t.Fatalf("the second notification said %v again; once is enough", err)
	}
	if len(ran) != 0 {
		t.Fatalf("ran %q without notify-send", ran)
	}
	// Another OS with no notifier: silent, nothing run.
	if err := desktopNotifier("freebsd", missing, run)(t.Context(), "t", "b"); err != nil || len(ran) != 0 {
		t.Fatalf("freebsd: %v %q", err, ran)
	}
	// A notify-send that fails is reported each time, like osascript.
	failing := desktopNotifier("linux", func(n string) (string, error) { return n, nil },
		func(context.Context, string, ...string) error { return errors.New("no session bus") })
	if err := failing(t.Context(), "t", "b"); err == nil {
		t.Fatal("a failing notify-send was not reported")
	}
}
