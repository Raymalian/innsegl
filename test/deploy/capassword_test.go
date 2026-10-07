// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// A default value for the CA key's password in a shipped file is a password
// anyone can read: measured 2026-10-07, a deployment's CA key was locked with
// the reference default because nothing set its own. The trust-key backup
// reads the password but must never supply one.
func TestTheTrustKeyBackupCarriesNoDefaultCAPassword(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	withDefault := regexp.MustCompile(`INNSEGL_FULCIO_CA_PASSWORD:-[^}]+}`)
	for _, f := range []string{"deploy/compose/innsegl.yml", "deploy/compose/dev/innsegl.yml"} {
		body, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		if m := withDefault.Find(body); m != nil {
			t.Errorf("%s gives the CA password a default (%s): a shipped default is a public password", f, m)
		}
	}
}
