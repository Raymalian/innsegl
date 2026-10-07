// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// OPS-146 (PROPOSED for doc 07's TC-OPS) — `innsegl ca-custodian` refuses to
// start without what it needs, and says which (#533, ADR-0076). A custodian
// with no recipient would seal the unlock material to nobody; one with no
// store address would report a sealed CA forever.
func TestOPS146TheCustodianNamesWhatItIsMissing(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		env  map[string]string
		want string
		code int
	}{
		{"no verb", nil, nil, "init, serve, ready or restore", exitUsage},
		{"unknown verb", []string{"export"}, nil, "init, serve, ready or restore", exitUsage},
		{"no store", []string{"init"}, map[string]string{envCARecipients: id.Recipient().String(),
			envCADir: t.TempDir(), envCATokenPath: t.TempDir() + "/t"}, envCAStoreAddr, exitCACustodyFailed},
		{"no recipient", []string{"init"}, map[string]string{envCAStoreAddr: "http://127.0.0.1:1",
			envCADir: t.TempDir(), envCATokenPath: t.TempDir() + "/t"}, envCARecipients, exitCACustodyFailed},
		{"no directory", []string{"serve"}, map[string]string{envCAStoreAddr: "http://127.0.0.1:1",
			envCARecipients: id.Recipient().String(), envCATokenPath: t.TempDir() + "/t"}, envCADir, exitCACustodyFailed},
		{"unreachable store", []string{"init"}, map[string]string{envCAStoreAddr: "http://127.0.0.1:1",
			envCARecipients: id.Recipient().String(), envCADir: t.TempDir(), envCATokenPath: t.TempDir() + "/t"},
			"not answering", exitCACustodyFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			getenv := func(k string) string { return c.env[k] }
			code := runCACustodian(t.Context(), c.args, &out, &errOut, getenv)
			if code != c.code || !strings.Contains(errOut.String(), c.want) {
				t.Fatalf("exit %d (want %d), stderr %q (want it to name %q)", code, c.code, errOut.String(), c.want)
			}
		})
	}
}

// OPS-146 (PROPOSED) — `ready` is the custodian container's health: the
// store answers, is initialised and unlocked, and the CA has a token. Fulcio's
// bootstrap waits for it, so it must say no to each missing piece.
func TestOPS146ReadyIsTheStoreUnlockedAndATokenWritten(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	sealed := true
	initialised := true
	store := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"initialized":%t,"sealed":%t}`, initialised, sealed)
	}))
	defer store.Close()
	tokenPath := filepath.Join(t.TempDir(), ".vault-token")
	env := map[string]string{envCAStoreAddr: store.URL, envCARecipients: id.Recipient().String(),
		envCADir: t.TempDir(), envCATokenPath: tokenPath}
	ready := func() int {
		var out, errOut bytes.Buffer
		return runCACustodian(t.Context(), []string{"ready"}, &out, &errOut, func(k string) string { return env[k] })
	}
	if code := ready(); code != exitCACustodyFailed {
		t.Fatalf("a sealed store is ready: exit %d", code)
	}
	sealed = false
	if code := ready(); code != exitCACustodyFailed {
		t.Fatalf("an unlocked store with no token written is ready: exit %d", code)
	}
	if err = os.WriteFile(tokenPath, []byte("s.token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := ready(); code != exitOK {
		t.Fatalf("an unlocked store with a token is not ready: exit %d", code)
	}
	initialised = false
	if code := ready(); code != exitCACustodyFailed {
		t.Fatalf("an uninitialised store is ready: exit %d", code)
	}
}

// OPS-155 (PROPOSED) — `restore SNAPSHOT` puts a backup's store into a new
// store, sealed under the original keys, for the operator's machine to
// unlock. It names what it is missing, and refuses a store that holds data.
func TestOPS155RestoreNamesWhatItNeedsAndRefusesAStoreWithData(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	initialised := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"initialized":true,"sealed":true}`)
	}))
	defer initialised.Close()
	snap := filepath.Join(t.TempDir(), "store.snap")
	if err = os.WriteFile(snap, []byte("snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{envCAStoreAddr: initialised.URL, envCARecipients: id.Recipient().String(),
		envCADir: t.TempDir(), envCATokenPath: filepath.Join(t.TempDir(), "t")}
	run := func(args ...string) (int, string) {
		var out, errOut bytes.Buffer
		code := runCACustodian(t.Context(), args, &out, &errOut, func(k string) string { return env[k] })
		return code, errOut.String()
	}
	if code, msg := run("restore"); code != exitUsage || !strings.Contains(msg, "snapshot") {
		t.Fatalf("restore with no snapshot: exit %d: %s", code, msg)
	}
	if code, msg := run("restore", filepath.Join(t.TempDir(), "absent")); code != exitCACustodyFailed || !strings.Contains(msg, "absent") {
		t.Fatalf("restore of an absent file: exit %d: %s", code, msg)
	}
	if code, msg := run("restore", snap); code != exitCACustodyFailed || !strings.Contains(msg, "initialised") {
		t.Fatalf("restore over a store with data: exit %d: %s", code, msg)
	}
}
