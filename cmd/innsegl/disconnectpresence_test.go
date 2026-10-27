// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/client/clienttest"
)

// ---------------------------------------------------------------------------
// CLI-045 (PROPOSED for doc 07, #600) — revoking this machine needs the
// person at it: `innsegl connect --disconnect` asks them to type a word on
// the terminal before it changes anything, and a process without a
// terminal, or a person who does not confirm, revokes nothing.
// ---------------------------------------------------------------------------

func TestCLI045DisconnectAsksThePersonFirst(t *testing.T) {
	f := newConnectFixtureWithoutRecoveryRoutes(t)
	revoked := 0
	f.core.Mux.HandleFunc(coreStatusPath, func(w http.ResponseWriter, _ *http.Request) {
		writeCoreJSON(w, http.StatusOK, coreStatus{Version: "clienttest"})
	})
	f.core.Mux.HandleFunc(coreDisconnectPath, func(w http.ResponseWriter, _ *http.Request) {
		revoked++
		w.WriteHeader(http.StatusNoContent)
	})
	if code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile,
		"--managed-settings", f.settings); code != exitOK {
		t.Fatalf("connect: %s", stderr)
	}
	before, err := os.ReadFile(f.settings)
	if err != nil {
		t.Fatal(err)
	}
	var question string
	f.deps.presence = func(q string) error {
		question = q
		return errNotConfirmed
	}

	code, _, stderr := f.connect("--disconnect", "--managed-settings", f.settings)
	if code == exitOK {
		t.Fatalf("disconnect went on without the person: %s", stderr)
	}
	if !strings.Contains(question, "revoke") {
		t.Errorf("the question does not say it revokes this machine: %q", question)
	}
	if revoked != 0 {
		t.Fatalf("the core was asked to revoke %d times without the person", revoked)
	}
	if _, err := os.Stat(filepath.Join(f.home, ".innsegl", "client", "core.json")); err != nil {
		t.Errorf("the enrolment was removed without the person: %v", err)
	}
	if after, rerr := os.ReadFile(f.settings); rerr != nil || string(after) != string(before) {
		t.Errorf("the managed settings were changed without the person (%v)", rerr)
	}
	if !strings.Contains(stderr, "Nothing was changed") {
		t.Errorf("stderr does not say nothing was changed:\n%s", stderr)
	}

	// Confirmed, the same disconnect goes through.
	f.deps.presence = func(string) error { return nil }
	if code, _, stderr := f.connect("--disconnect", "--managed-settings", f.settings); code != exitOK {
		t.Fatalf("confirmed disconnect: %s", stderr)
	}
	if revoked != 1 {
		t.Fatalf("revocations after confirming: %d", revoked)
	}
}

// CLI-045 (PROPOSED) — the terminal confirmation: only the word itself
// passes; anything else, or no answer, does not.
func TestCLI045TheTypedConfirmation(t *testing.T) {
	for _, c := range []struct {
		typed string
		ok    bool
	}{
		{"disconnect\n", true},
		{"  disconnect  \r\n", true},
		{"yes\n", false},
		{"y\n", false},
		{"\n", false},
		{"", false},
		{"Disconnect-ish\n", false},
	} {
		var out strings.Builder
		err := confirmTyped(strings.NewReader(c.typed), &out, "revoke it?")
		if (err == nil) != c.ok {
			t.Errorf("typed %q: %v; want ok=%v", c.typed, err, c.ok)
		}
		if !strings.Contains(out.String(), "revoke it?") || !strings.Contains(out.String(), disconnectWord) {
			t.Errorf("the prompt does not ask the question and name the word: %q", out.String())
		}
	}
}

// CLI-045 (PROPOSED) — without a terminal to ask on (an agent's shell, a
// pipe), the confirmation fails and says why.
func TestCLI045NoTerminalNoDisconnect(t *testing.T) {
	err := confirmOnTerminal(func() (*os.File, error) { return nil, errors.New("device not configured") })("revoke it?")
	if err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Fatalf("confirmation without a terminal: %v", err)
	}
}
