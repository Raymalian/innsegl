// SPDX-License-Identifier: Apache-2.0

package trustbackup

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The one path no CI runner can take: a bundle the core wrote to a Secure
// Enclave recipient, opened by age-plugin-se on the operator's machine, which
// asks for Touch ID. It runs only where all three are present, and its skip
// names whichever is missing. Run it by hand on that machine:
//
//	INNSEGL_TRUST_BACKUP_SE_IDENTITY=<identity file> \
//	INNSEGL_TRUST_BACKUP_SE_RECIPIENT=<its age1se1 recipient> \
//	go test ./internal/trustbackup -run TestASecureEnclaveIdentityOpensABundle -v
func TestASecureEnclaveIdentityOpensABundle(t *testing.T) {
	var missing []string
	identity := os.Getenv("INNSEGL_TRUST_BACKUP_SE_IDENTITY")
	recipient := os.Getenv("INNSEGL_TRUST_BACKUP_SE_RECIPIENT")
	if identity == "" {
		missing = append(missing, "INNSEGL_TRUST_BACKUP_SE_IDENTITY (an age-plugin-se identity file)")
	}
	if recipient == "" {
		missing = append(missing, "INNSEGL_TRUST_BACKUP_SE_RECIPIENT (its age1se1 recipient)")
	}
	if _, err := exec.LookPath("age-plugin-se"); err != nil {
		missing = append(missing, "age-plugin-se on PATH")
	}
	if len(missing) > 0 {
		t.Skip("needs a Secure Enclave and Touch ID; missing: " + strings.Join(missing, ", "))
	}
	rs, err := ParseRecipients(recipient)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err = WriteBundle(&buf, rs, []Source{ValueSource("a", "f", []byte("sealed"))}, testNow); err != nil {
		t.Fatal(err)
	}
	ids, err := LoadIdentities(identity, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := ReadBundle(&buf, ids, "")
	if err != nil {
		t.Fatalf("the Secure Enclave identity did not open the bundle: %v", err)
	}
	if m.Files() != 1 {
		t.Fatalf("manifest = %+v", m)
	}
}
