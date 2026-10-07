// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// OPS-148 (PROPOSED for doc 07's TC-OPS) — under ADR-0076 the CA's token is
// never in an environment variable or a compose file: the custodian writes it
// to a file on memory-backed storage, and the bootstrap reads it from there,
// as Fulcio does. An environment token still wins, for the opt-in overlay
// that has always passed one.
func TestOPS148TheBootstrapReadsTheCATokenFromItsFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, ".vault-token")
	if err := os.WriteFile(file, []byte("s.from-the-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"INNSEGL_CA_STORE_TOKEN_FILE": file}
	got, err := storeToken(func(k string) string { return env[k] })
	if err != nil || got != "s.from-the-file" {
		t.Fatalf("storeToken = %q, %v; want the file's token without its newline", got, err)
	}

	env["INNSEGL_CA_STORE_TOKEN"] = "s.from-the-env"
	if got, err = storeToken(func(k string) string { return env[k] }); err != nil || got != "s.from-the-env" {
		t.Fatalf("storeToken = %q, %v; want the environment's", got, err)
	}

	env = map[string]string{"INNSEGL_CA_STORE_TOKEN_FILE": filepath.Join(dir, "absent")}
	if _, err = storeToken(func(k string) string { return env[k] }); err == nil {
		t.Fatal("an absent token file was not an error; the store is not unlocked yet and the bootstrap must say so")
	}
	if got, err = storeToken(func(string) string { return "" }); err != nil || got != "" {
		t.Fatalf("no token configured = %q, %v; want empty, for the usage message", got, err)
	}
}
