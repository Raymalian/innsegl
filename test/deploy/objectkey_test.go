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
// S3's gRPC port requires a per-host key (#451).
//
// The object store reads this key as its filer signing key. It is generated
// once per host by innsegl-s3-identities, kept in the volume only that one-shot
// and the object store mount, and handed to the process by its start script.
// No shipped file carries a value for it, and the store refuses to start
// without one. The shape is OPS-011/OPS-012's for the identity secret.
// ---------------------------------------------------------------------------

const (
	s3IdentitiesScript   = "deploy/compose/innsegl/s3-identities.sh"
	objectStoreStartPath = "deploy/compose/innsegl/object-store-start.sh"
	filerKeyEnv          = "INNSEGL_OBJECT_FILER_JWT_KEY"
	filerKeyFileEnv      = "INNSEGL_OBJECT_FILER_JWT_KEY_FILE"
	filerKeyFileName     = "filer-jwt.key"

	// formerFilerKeyDefault is the value the compose file used to default the
	// key to. It is public, so it must never be accepted again.
	formerFilerKeyDefault = "innsegl-compose-filer-admin"
)

// filerKeyDefault matches a shell or compose default that gives the key a
// value: `${INNSEGL_OBJECT_FILER_JWT_KEY:-something}`. An empty default
// (`:-}`) gives none and is allowed.
var filerKeyDefault = regexp.MustCompile(`INNSEGL_OBJECT_FILER_JWT_KEY:?-[^}]`)

func TestNoShippedFileDefaultsTheObjectStoreKey(t *testing.T) {
	root := repoRoot(t)
	for _, file := range shippedFiles(t, root) {
		body, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatalf("reading tracked file %s: %v", file, err)
		}
		for n, line := range strings.Split(string(body), "\n") {
			if filerKeyDefault.MatchString(line) || strings.Contains(line, formerFilerKeyDefault) ||
				regexp.MustCompile(`WEED_JWT_FILER_SIGNING_KEY:\s*\S`).MatchString(line) {
				t.Errorf("%s:%d gives the object store's key a value:\n  %s\n\nA value in this "+
					"repository is a value every reader has. The key is generated per host "+
					"by innsegl-s3-identities.", file, n+1, strings.TrimSpace(line))
			}
		}
	}
}

// runS3Identities runs the shipped one-shot against one host's directory and
// returns the key it left behind, or its output and error.
func runS3Identities(t *testing.T, dir string, env ...string) (string, string, error) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "sh", filepath.Join(repoRoot(t), s3IdentitiesScript))
	cmd.Env = append(os.Environ(),
		"INNSEGL_S3_IDENTITIES_FILE="+filepath.Join(dir, "identities.json"),
		"INNSEGL_OBJECT_STORE_ACCESS_KEY="+storeRootUser,
		"INNSEGL_OBJECT_STORE_SECRET_KEY="+storeRootPassword,
		"INNSEGL_OBJECT_STORE_SEALER_SECRET_KEY="+storeSealerPassword,
		filerKeyEnv+"=",
	)
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", string(out), err
	}
	key, rerr := os.ReadFile(filepath.Join(dir, filerKeyFileName))
	if rerr != nil {
		t.Fatalf("%s exited 0 and wrote no key: %v\n%s", s3IdentitiesScript, rerr, out)
	}
	return strings.TrimSpace(string(key)), string(out), nil
}

func TestTheObjectStoreKeyIsGeneratedPerHostAndKept(t *testing.T) {
	hostA, hostB := t.TempDir(), t.TempDir()

	first, out, err := runS3Identities(t, hostA)
	if err != nil {
		t.Fatalf("%s failed: %v\n%s", s3IdentitiesScript, err, out)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64,}$`).MatchString(first) {
		t.Fatalf("the generated key is %q; want at least 32 random bytes, hex encoded", first)
	}

	t.Run("it draws from a CSPRNG", func(t *testing.T) {
		if !strings.Contains(readFile(t, filepath.Join(repoRoot(t), s3IdentitiesScript)), "/dev/urandom") {
			t.Errorf("%s does not read /dev/urandom", s3IdentitiesScript)
		}
	})

	t.Run("a restart and an update keep it", func(t *testing.T) {
		again, out, err := runS3Identities(t, hostA)
		if err != nil {
			t.Fatalf("second run failed: %v\n%s", err, out)
		}
		if again != first {
			t.Errorf("the second run replaced the key")
		}
	})

	t.Run("another host gets another key", func(t *testing.T) {
		other, out, err := runS3Identities(t, hostB)
		if err != nil {
			t.Fatalf("run on a second host failed: %v\n%s", err, out)
		}
		if other == first {
			t.Errorf("two hosts generated the same key")
		}
	})

	t.Run("an operator's key is used", func(t *testing.T) {
		mine := strings.Repeat("ab", 24)
		got, out, err := runS3Identities(t, t.TempDir(), filerKeyEnv+"="+mine)
		if err != nil {
			t.Fatalf("an operator-supplied key was refused: %v\n%s", err, out)
		}
		if got != mine {
			t.Errorf("the key file holds %q, want the operator's %q", got, mine)
		}
	})

	t.Run("a short or public operator key is refused", func(t *testing.T) {
		for _, bad := range []string{"short", formerFilerKeyDefault} {
			if _, out, err := runS3Identities(t, t.TempDir(), filerKeyEnv+"="+bad); err == nil {
				t.Errorf("%s accepted %q as the key:\n%s", s3IdentitiesScript, bad, out)
			}
		}
	})
}

func TestTheObjectStoreRefusesToStartWithoutItsKey(t *testing.T) {
	script := filepath.Join(repoRoot(t), objectStoreStartPath)
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("%s must ship: it is what hands the key to the object store: %v", objectStoreStartPath, err)
	}
	dir := t.TempDir()
	short := filepath.Join(dir, "short.key")
	if err := os.WriteFile(short, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"absent": filepath.Join(dir, "absent.key"),
		"short":  short,
	} {
		cmd := exec.CommandContext(t.Context(), "sh", script, "server")
		cmd.Env = append(os.Environ(), filerKeyFileEnv+"="+path)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Errorf("the start script ran with a %s key file:\n%s", name, out)
		} else if !strings.Contains(string(out), "object-store-start: FAIL") {
			t.Errorf("with a %s key file the start script failed without saying why: %v\n%s", name, err, out)
		}
	}
}

func TestTheObjectStoreTakesItsKeyFromTheGeneratedFile(t *testing.T) {
	svc := objectStoreConfig(t).service(t, objectStoreService)

	if strings.Join(svc.Entrypoint, " ") != "/bin/sh /innsegl/object-store-start.sh" {
		t.Errorf("%s's entrypoint is %v; want the start script, which refuses to start "+
			"without the key", objectStoreService, svc.Entrypoint)
	}
	if v, ok := svc.Environment[filerKeyFileEnv]; !ok || v == nil || *v != "/run/innsegl/s3/"+filerKeyFileName {
		t.Errorf("%s does not name the generated key file in %s", objectStoreService, filerKeyFileEnv)
	}
	if _, ok := svc.Environment["WEED_JWT_FILER_SIGNING_KEY"]; ok {
		t.Errorf("%s sets WEED_JWT_FILER_SIGNING_KEY in compose; the start script sets it "+
			"from the generated file", objectStoreService)
	}
}
