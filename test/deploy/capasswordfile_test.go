// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// OPS-130 (PROPOSED for doc 07's TC-OPS) — the Fulcio CA key's password is
// generated per host, and no shipped file supplies one (#533).
//
// OPS-011's guard, applied to key material. A deployment's CA key was found
// locked with the reference stack's default password, because the compose
// file defaulted it and nothing generated one. A default in a shipped file is
// a password every reader of this repository has, so the encryption protected
// the key from nobody. The value also travelled on Fulcio's command line,
// where `docker inspect` shows it.
//
// What must hold instead:
//   - no shipped file gives a key-material password a non-empty default;
//   - the password reaches Fulcio from a file on the trust volume, through
//     Fulcio's own config file, never as a command-line value;
//   - the bootstrap draws a new one from a CSPRNG.
// ---------------------------------------------------------------------------

// keyMaterialDefault matches a shell or compose default, `${NAME:-value}`, for
// a variable that unlocks key material: a CA or key password or passphrase.
// Database and object-store passwords are out of scope here; they lock no key
// a signature chains to.
var keyMaterialDefault = regexp.MustCompile(
	`\$\{([A-Z0-9_]*(?:CA|KEY|PKI|SIGNING)_(?:PASSWORD|PASSWD|PASSPHRASE)[A-Z0-9_]*):-([^}]+)\}`)

func TestOPS130NoShippedFileDefaultsAKeyPassword(t *testing.T) {
	root := repoRoot(t)
	out, err := exec.CommandContext(t.Context(), "git", "-C", root, "ls-files",
		"deploy", "runbooks", "scripts", "Dockerfile", "Makefile").Output()
	if err != nil {
		t.Fatalf("listing the shipped files: %v", err)
	}
	files := strings.Fields(string(out))
	if len(files) == 0 {
		t.Fatal("no shipped files were listed; the guard would pass vacuously")
	}
	for _, file := range files {
		body, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		for n, line := range strings.Split(string(body), "\n") {
			for _, m := range keyMaterialDefault.FindAllStringSubmatch(line, -1) {
				t.Errorf("%s:%d gives %s the default %q. A default in a shipped file is a "+
					"password everyone who reads this repository has. The bootstrap "+
					"generates one per host and keeps it on the trust volume (#533).",
					file, n+1, m[1], m[2])
			}
		}
	}
}

func TestOPS130FulcioReadsItsCAPasswordFromAFile(t *testing.T) {
	root := repoRoot(t)
	for _, f := range []string{"sigstore.yml", "sigstore.keycustody.yml"} {
		body := readFile(t, filepath.Join(root, "deploy", "compose", f))
		if strings.Contains(body, "--fileca-key-passwd") {
			t.Errorf("deploy/compose/%s passes --fileca-key-passwd: the value is then on "+
				"Fulcio's command line and in `docker inspect`", f)
		}
		if regexp.MustCompile(`pass:\$`).MatchString(body) {
			t.Errorf("deploy/compose/%s hands openssl a password on its command line "+
				"(`-passin pass:$...`); read it from the password file", f)
		}
	}
	stack := readFile(t, filepath.Join(root, "deploy", "compose", "sigstore.yml"))
	fulcio := composeService(t, stack, "fulcio")
	if !strings.Contains(fulcio, `--config=/etc/fulcio/serve.yaml`) {
		t.Errorf("fulcio is not started with --config=/etc/fulcio/serve.yaml, the file "+
			"the bootstrap writes the password into:\n%s", fulcio)
	}
	if strings.Contains(fulcio, "INNSEGL_FULCIO_CA_PASSWORD") {
		t.Errorf("fulcio's service still names INNSEGL_FULCIO_CA_PASSWORD:\n%s", fulcio)
	}
}

func TestOPS130TheBootstrapGeneratesThePassword(t *testing.T) {
	root := repoRoot(t)
	lib := readFile(t, filepath.Join(root, "deploy", "compose", "sigstore", "ca-lib.sh"))
	if !strings.Contains(lib, "openssl rand -hex 32") {
		t.Error("deploy/compose/sigstore/ca-lib.sh does not draw the CA password with " +
			"`openssl rand -hex 32` (32 bytes from a CSPRNG)")
	}
	stack := readFile(t, filepath.Join(root, "deploy", "compose", "sigstore.yml"))
	boot := composeService(t, stack, "sigstore-bootstrap")
	if !strings.Contains(boot, "./sigstore/ca-lib.sh:/ca-lib.sh:ro") {
		t.Errorf("sigstore-bootstrap does not mount the CA library it sources:\n%s", boot)
	}
}

// The update path reaches Fulcio (#533). Before, `make update` never touched
// Fulcio, so a host would keep a Fulcio started with the password on its
// command line while the bootstrap moved the key onto a password file; after
// a re-lock, that Fulcio fails on its next restart. The update recreates a
// file-CA Fulcio, leaves one under key custody alone, ensures the trust
// volumes first, and does it before the core starts.
func TestOPS130TheUpdateRecreatesAFileCAFulcio(t *testing.T) {
	root := repoRoot(t)
	mk := readFile(t, filepath.Join(root, "Makefile"))
	recipe := makeRecipe(t, mk, "fulcio-file-ca-up")
	if !strings.Contains(recipe, "*--ca=kmsca*)") {
		t.Error("fulcio-file-ca-up does not leave a Fulcio under key custody alone")
	}
	if !strings.Contains(recipe, "$(SIGSTORE_FILES) up -d fulcio") {
		t.Error("fulcio-file-ca-up does not bring fulcio up from $(SIGSTORE_FILES)")
	}
	if !regexp.MustCompile(`(?m)^fulcio-file-ca-up: innsegl-trust-volumes$`).MatchString(mk) {
		t.Error("fulcio-file-ca-up does not ensure the trust volumes first")
	}
	upd := makeRecipe(t, mk, "update")
	f, c := strings.Index(upd, "--no-print-directory fulcio-file-ca-up"), strings.Index(upd, "--no-print-directory innsegl-here-services")
	l := strings.Index(upd, "--no-print-directory rekor-log-up")
	if f < 0 || c < 0 || f > c || l > f {
		t.Error("make update does not run fulcio-file-ca-up after rekor-log-up and before it starts the core")
	}
}
