// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"innsegl.dev/innsegl/internal/cacustody"
)

// BAK-029 (PROPOSED for doc 07's TC-BAK) — `innsegl ca-custody` is the
// terminal's way to the same unlock the client service makes (#533,
// ADR-0076): it says whether the CA is sealed, and unlocks it with one
// Touch ID. No secret is typed or printed.
func TestBAK029TheOperatorUnlocksTheCAFromATerminal(t *testing.T) {
	f := newConnectFixture(t)
	f.connectServed(t, nil)
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(t.TempDir(), "identity.txt")
	if err = os.WriteFile(identity, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := cacustody.Material{UnsealKey: "unseal-key-value", RoleID: "role", SecretID: "secret-id-value",
		BackupRoleID: "backup-role", BackupSecretID: "backup-secret-value"}
	sealed, err := cacustody.Seal(m, []age.Recipient{id.Recipient()})
	if err != nil {
		t.Fatal(err)
	}
	fc := &fakeCustodian{status: cacustody.Status{Initialized: true, Sealed: true}, material: sealed,
		code: http.StatusNoContent}
	h := caCustodyHandler(fc.server(t).URL, operatorMachine(), newBackupLimiter(nil), newServeLog(os.Stderr))
	f.core.Mux.Handle(coreCACustodyPath, withInstallation("inst-1", h))
	f.core.Mux.Handle(coreCACustodyPath+"/", withInstallation("inst-1", h))

	var out, errOut bytes.Buffer
	if code := runCACustody(t.Context(), []string{"status"}, &out, &errOut, f.home); code != exitCACustodySealed ||
		!strings.Contains(out.String(), "SEALED") {
		t.Fatalf("status of a sealed CA: exit %d\n%s%s", code, out.String(), errOut.String())
	}

	out.Reset()
	if code := runCACustody(t.Context(), []string{"unlock", "--identity", identity}, &out, &errOut, f.home); code != exitOK {
		t.Fatalf("unlock: exit %d\n%s%s", code, out.String(), errOut.String())
	}
	var sent cacustody.Material
	if err = json.Unmarshal(fc.unlocked, &sent); err != nil || sent != m {
		t.Fatalf("the custodian was sent %q", fc.unlocked)
	}
	for _, secret := range []string{m.UnsealKey, m.SecretID} {
		if strings.Contains(out.String()+errOut.String(), secret) {
			t.Fatal("the command printed unlock material")
		}
	}

	fc.status.Sealed = false
	out.Reset()
	if code := runCACustody(t.Context(), []string{"status"}, &out, &errOut, f.home); code != exitOK ||
		!strings.Contains(out.String(), "unlocked") {
		t.Fatalf("status of an unlocked CA: exit %d\n%s", code, out.String())
	}

	if code := runCACustody(t.Context(), []string{"open-sesame"}, &out, &errOut, f.home); code != exitUsage {
		t.Fatalf("an unknown verb: exit %d", code)
	}
}
