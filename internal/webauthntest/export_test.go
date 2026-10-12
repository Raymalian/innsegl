// SPDX-License-Identifier: Apache-2.0

package webauthntest

import (
	"bytes"
	"strings"
	"testing"
)

// A soft passkey outlives the process that made it (#617): OPS-208 enrols an
// owner on a dev stack at the previous main, and the checks after `make
// update` sign in with the same passkey. Export and Import round-trip the key,
// the credential id and the sign counter, so the server sees one authenticator
// whose counter only goes up.
func TestExportImportKeepsTheKeyTheIdAndTheCounter(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	a.signCount = 7
	raw, err := a.Export()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Import(raw)
	if err != nil {
		t.Fatalf("Import(Export()): %v", err)
	}
	if !bytes.Equal(a.CredentialID(), b.CredentialID()) {
		t.Error("the credential id changed")
	}
	if !a.key.Equal(b.key) {
		t.Error("the private key changed")
	}
	if b.signCount != 7 {
		t.Errorf("the sign counter is %d, want 7", b.signCount)
	}
}

func TestImportRefusesWhatIsNotAnExport(t *testing.T) {
	for name, raw := range map[string]string{
		"not JSON":     "{",
		"no key":       `{"credential_id":"AAAA","sign_count":1}`,
		"a broken key": `{"key":"AAAA","credential_id":"AAAA","sign_count":1}`,
		"no id":        "",
	} {
		t.Run(name, func(t *testing.T) {
			if name == "no id" {
				a, err := New()
				if err != nil {
					t.Fatal(err)
				}
				a.credentialID = nil
				out, err := a.Export()
				if err != nil {
					t.Fatal(err)
				}
				raw = string(out)
			}
			if _, err := Import([]byte(raw)); err == nil || !strings.Contains(err.Error(), "webauthntest") {
				t.Errorf("Import(%s) = %v, want a webauthntest error", name, err)
			}
		})
	}
}
