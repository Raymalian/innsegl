// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// OPS-130 (PROPOSED for doc 07's TC-OPS), widened by ADR-0078 — no shipped
// file gives ANY credential a value, and each service mounts only the
// credentials it uses.
//
// ADR-0075 applied this to the CA key's password. Every database and object
// store password had the same flaw: a compose default every reader of this
// repository has, which a deployment that set nothing ran on. The values also
// travelled on Trillian's and Rekor's command lines and in `docker inspect`.
//
// What must hold instead:
//   - no `${NAME:-value}` with a value, for any credential variable;
//   - no literal password in a compose environment, and no password inside a
//     DSN, in any shipped file;
//   - none of the old public values anywhere, except the one named constant
//     the ledger's move reads (LEDGER_OWNER_LEGACY_PUBLIC_PASSWORD);
//   - the trust credentials volume is mounted only by the generator and by
//     what sets passwords on a server; every other service mounts exactly
//     the per-credential volumes it uses.
// ---------------------------------------------------------------------------

// credentialDefault matches a shell or compose default with a value, for a
// variable that names a credential.
var credentialDefault = regexp.MustCompile(
	`\$\{([A-Z0-9_]*(?:PASSWORD|PASSWD|PASSPHRASE|SECRET_KEY|SECRET|TOKEN)):-([^}]+)\}`)

// credentialLiteral matches a compose environment entry whose key names a
// password or a secret key and whose value is not a reference to a variable
// with an empty default. `_FILE` keys end differently and are not matched.
var credentialLiteral = regexp.MustCompile(
	`^\s+-?\s*([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET_KEY))\s*[:=]\s*(\S.*)$`)

// dsnPassword matches a password inside a connection string: a URL's
// userinfo, or the user:password@tcp( form the MySQL driver takes.
var dsnPassword = regexp.MustCompile(
	`(?:[a-z]+://[A-Za-z0-9_.$%{}-]+:[^@/\s'"]+@)|(?:[A-Za-z0-9_]+:[^@/\s'"(%$]+@tcp\()`)

// legacyPublicValues are the values earlier releases shipped. Spelled here,
// in a test, so that the guard can name them; no shipped file may.
var legacyPublicValues = []string{
	"innsegl-compose-owner",
	"innsegl-compose-appender",
	"innsegl-compose-reader",
	"innsegl-compose-authwriter",
	"innsegl-compose-resolver",
	"innsegl-compose-backup",
	"innsegl-compose-objects",
	"zaphod",
	"'rekor-index'",
	"rekor:rekor-index@",
}

// The one line allowed to carry an old value: the constant the ledger's move
// tries when the file's password is refused (ADR-0078 decision 6).
const legacyConstantLine = "LEDGER_OWNER_LEGACY_PUBLIC_PASSWORD='innsegl-compose-owner'"

func credentialShippedFiles(t *testing.T) []string {
	t.Helper()
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
	return files
}

func TestOPS130NoShippedFileDefaultsAnyCredential(t *testing.T) {
	root := repoRoot(t)
	for _, file := range credentialShippedFiles(t) {
		body, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		compose := strings.HasSuffix(file, ".yml") || strings.HasSuffix(file, ".yaml")
		for n, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, m := range credentialDefault.FindAllStringSubmatch(line, -1) {
				t.Errorf("%s:%d gives %s the default %q. A default in a shipped file is a "+
					"credential everyone who reads this repository has; it is generated per "+
					"host instead (ADR-0078)", file, n+1, m[1], m[2])
			}
			if compose {
				if m := credentialLiteral.FindStringSubmatch(line); m != nil && !emptyReference(m[2]) {
					t.Errorf("%s:%d sets %s to %q in the compose file. Credentials reach a "+
						"service as a file (%s_FILE), never as a value (ADR-0078)",
						file, n+1, m[1], m[2], m[1])
				}
			}
			if m := dsnPassword.FindString(line); m != "" {
				t.Errorf("%s:%d carries a password inside a connection string (%q). Name a "+
					"passfile or a config file instead (ADR-0078)", file, n+1, m)
			}
			if strings.TrimSpace(line) == legacyConstantLine {
				continue
			}
			for _, v := range legacyPublicValues {
				if strings.Contains(line, v) {
					t.Errorf("%s:%d holds %q, a value earlier releases shipped as a "+
						"credential. Only %s may name an old value", file, n+1, v, legacyConstantLine)
				}
			}
		}
	}
}

// emptyReference reports whether a compose value is `${NAME:-}` or `${NAME}`:
// a read of the operator's environment that ships nothing.
func emptyReference(v string) bool {
	v = strings.Trim(strings.TrimSpace(v), `"'`)
	return regexp.MustCompile(`^\$\{[A-Z0-9_]+(?::-)?\}$`).MatchString(v)
}

// The constant exists exactly once, where the move reads it.
func TestOPS130TheOldOwnerPasswordIsOneNamedConstant(t *testing.T) {
	root := repoRoot(t)
	n := 0
	for _, file := range credentialShippedFiles(t) {
		body, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(body), "\n") {
			if strings.TrimSpace(line) == legacyConstantLine {
				n++
				if file != "deploy/compose/innsegl/db-init.sh" {
					t.Errorf("%s defines the old owner password; only db-init.sh may", file)
				}
			}
		}
	}
	if n != 1 {
		t.Errorf("found %d definitions of the old owner password, want exactly 1 (db-init.sh)", n)
	}
}

// renderAll renders a compose file set with every profile on, so no service is
// left out of a mount-table read.
func renderAll(t *testing.T, files ...string) composeDoc {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is not on PATH: %v", err)
	}
	root := repoRoot(t)
	args := []string{"compose"}
	for _, f := range files {
		args = append(args, "-f", filepath.Join(root, f))
	}
	args = append(args, "--profile", "*", "config", "--format", "json")
	cmd := exec.CommandContext(t.Context(), "docker", args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"INNSEGL_SPIRE_JWT_ISSUER=http://spire-oidc:8080",
		"INNSEGL_SPIRE_PARENT_ID=unset",
		"INNSEGL_MCP_ADMIN_LISTEN=0.0.0.0:8090")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker compose %v config: %v\n%s", files, err, stderr.String())
	}
	var doc composeDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// credentialMounts lists, per service, the credential volumes it mounts: the
// trust volume as "TRUST" (with ":rw" when writable), and each per-credential
// volume by the name after its prefix.
func credentialMounts(doc composeDoc, trustKey, prefix string) map[string][]string {
	got := map[string][]string{}
	for name, svc := range doc.Services {
		for _, v := range svc.Volumes {
			if v.Type != "volume" {
				continue
			}
			switch {
			case v.Source == trustKey:
				m := "TRUST"
				if !v.ReadOnly {
					m += ":rw"
				}
				got[name] = append(got[name], m)
			case strings.HasPrefix(v.Source, prefix):
				m := strings.TrimPrefix(v.Source, prefix)
				if !v.ReadOnly {
					m += ":rw"
				}
				got[name] = append(got[name], m)
			}
		}
		sort.Strings(got[name])
	}
	return got
}

// The mount table is the grant (ADR-0078 decision 3).
func TestOPS130EachServiceMountsOnlyTheCredentialsItUses(t *testing.T) {
	core := renderAll(t, coreBase)
	want := map[string][]string{
		// The generator writes the trust volume and every rendered volume.
		"innsegl-credentials": {
			"TRUST:rw",
			"authwriter:rw", "backup:rw", "ledger-owner:rw", "objects-root:rw",
			"objects-sealer:rw", "reader:rw", "resolver:rw", "appender:rw",
		},
		// What sets passwords on a server reads the trust volume.
		"innsegl-db-init":       {"TRUST"},
		"innsegl-s3-identities": {"TRUST"},
		"innsegl-trust-backup":  {"TRUST"},
		"postgres":              {"ledger-owner"},
		"innsegl-object-init":   {"objects-root", "objects-sealer"},
		"innsegl-mcp":           {"appender", "authwriter", "objects-sealer"},
		"innsegl-reconciler":    {"appender"},
		"innsegl-sealer":        {"appender", "objects-sealer"},
		"innsegl-backup":        {"backup", "objects-sealer"},
		"innsegl-api":           {"authwriter", "reader", "resolver"},
		"innsegl-canary":        {"objects-sealer"},
	}
	for k := range want {
		sort.Strings(want[k])
	}
	got := credentialMounts(core, "innsegl-credentials-store", "innsegl-credential-")
	for svc, w := range want {
		if strings.Join(got[svc], ",") != strings.Join(w, ",") {
			t.Errorf("%s mounts credentials %v, want %v", svc, got[svc], w)
		}
	}
	for svc, g := range got {
		if _, ok := want[svc]; !ok && len(g) > 0 {
			t.Errorf("%s mounts credentials %v and is not one of the services that uses them", svc, g)
		}
	}

	sig := renderAll(t, "deploy/compose/sigstore.yml")
	wantSig := map[string][]string{
		"sigstore-bootstrap":  {"TRUST:rw", "logdb:rw", "rekor-index:rw", "trillian:rw"},
		"trillian-db":         {"logdb"},
		"trillian-log-server": {"trillian"},
		"trillian-log-signer": {"trillian"},
		"rekor":               {"rekor-index"},
	}
	gotSig := credentialMounts(sig, "sigstore-credentials-store", "sigstore-credential-")
	for svc, w := range wantSig {
		sort.Strings(w)
		if strings.Join(gotSig[svc], ",") != strings.Join(w, ",") {
			t.Errorf("sigstore.yml: %s mounts credentials %v, want %v", svc, gotSig[svc], w)
		}
	}
	for svc, g := range gotSig {
		if _, ok := wantSig[svc]; !ok && len(g) > 0 {
			t.Errorf("sigstore.yml: %s mounts credentials %v and does not use them", svc, g)
		}
	}
}

// Every innsegl connection string names a passfile and carries no password,
// and every object-store secret is read from a file.
func TestOPS130ServicesReadCredentialsFromFiles(t *testing.T) {
	core := renderAll(t, coreBase)
	dsnVars := []string{"INNSEGL_LEDGER_DSN", "INNSEGL_GATEWAY_ACCOUNTS_DSN",
		"INNSEGL_API_DSN", "INNSEGL_API_AUTH_DSN", "INNSEGL_API_RESOLVER_DSN"}
	seen := 0
	for name, svc := range core.Services {
		for _, k := range dsnVars {
			v := svc.Environment[k]
			if v == nil {
				continue
			}
			seen++
			if !strings.Contains(*v, "passfile=/run/innsegl/credentials/") {
				t.Errorf("%s: %s=%q names no passfile", name, k, *v)
			}
			if dsnPassword.MatchString(*v) {
				t.Errorf("%s: %s carries a password", name, k)
			}
		}
		if v := svc.Environment["INNSEGL_OBJECT_STORE_SECRET_KEY"]; v != nil {
			t.Errorf("%s: INNSEGL_OBJECT_STORE_SECRET_KEY is a value; use INNSEGL_OBJECT_STORE_SECRET_KEY_FILE", name)
		}
		for k, v := range svc.Environment {
			if v != nil && strings.HasSuffix(k, "PASSWORD") && *v != "" {
				t.Errorf("%s: %s is set to a value; use %s_FILE", name, k, k)
			}
		}
		for _, arg := range svc.Command {
			if strings.Contains(arg, "secret-key") && !strings.Contains(arg, "-file") {
				t.Errorf("%s: a secret on the command line (%s)", name, arg)
			}
		}
	}
	if seen < 7 {
		t.Errorf("found %d connection strings in the core; the read did not reach them", seen)
	}
	if pg := core.Services["postgres"].Environment["POSTGRES_PASSWORD_FILE"]; pg == nil {
		t.Error("postgres does not read its owner password from POSTGRES_PASSWORD_FILE")
	}

	sig := renderAll(t, "deploy/compose/sigstore.yml")
	for _, name := range []string{"trillian-log-server", "trillian-log-signer"} {
		cmd := strings.Join(sig.Services[name].Command, " ")
		if !strings.Contains(cmd, "--config=/run/innsegl/credentials/trillian/flags") {
			t.Errorf("%s does not read its database credential from its flag file:\n%s", name, cmd)
		}
		if strings.Contains(cmd, "--mysql_uri") {
			t.Errorf("%s still takes --mysql_uri on its command line", name)
		}
	}
	rekor := strings.Join(sig.Services["rekor"].Command, " ")
	if !strings.Contains(rekor, "--config=/run/innsegl/credentials/rekor-index/rekor-server.yaml") ||
		strings.Contains(rekor, "mysql.dsn") {
		t.Errorf("rekor does not read its index DSN from its config file:\n%s", rekor)
	}
	db := sig.Services["trillian-db"]
	for _, k := range []string{"MYSQL_ROOT_PASSWORD_FILE", "MYSQL_PASSWORD_FILE"} {
		if db.Environment[k] == nil {
			t.Errorf("trillian-db does not set %s", k)
		}
	}
	if !strings.Contains(strings.Join(db.Command, " "), "--init-file=/run/innsegl/credentials/logdb/init.sql") {
		t.Errorf("trillian-db does not run the rendered init file:\n%v", db.Command)
	}
}
