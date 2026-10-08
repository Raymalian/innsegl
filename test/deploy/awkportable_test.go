// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/dockertest"
)

// ---------------------------------------------------------------------------
// OPS-134 (PROPOSED for doc 07's TC-OPS) — shipped awk programs run on the
// mawk that Debian 12 and Ubuntu 22.04 ship (#533).
//
// MEASURED: mawk 1.3.4 20200120, the default awk on Debian 12 and Ubuntu
// 22.04, does not read a regex interval such as `{16}`; it matches the braces
// as literal text. mawk 20240123 (Ubuntu 24.04, where CI runs) and macOS's
// awk read them as repeats. So verify.sh's cert_extension found no
// `CA:TRUE` in a CA certificate on such a host, and a CA rotation's proof
// step failed on a correct new root and rolled back. CI could not see it.
// ---------------------------------------------------------------------------

// mawk2020Image ships mawk 1.3.4 20200120 as its awk.
const mawk2020Image = "debian:12"

// awkProgram matches an awk invocation and its single-quoted program.
var awkProgram = regexp.MustCompile(`\bawk\b[^'\n|;]*'([^']*)'`)

// regexInterval matches a regex literal inside an awk program that holds an
// interval expression: /…{n}…/ or /…{n,m}…/.
var regexInterval = regexp.MustCompile(`/[^/\n]*\{[0-9]+(,[0-9]*)?\}[^/\n]*/`)

func TestOPS134AwkProgramsUseNoRegexIntervals(t *testing.T) {
	root := repoRoot(t)
	var found []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "dist", "docs":
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(p)
		if ext != ".sh" && ext != ".yml" && ext != ".yaml" && d.Name() != "Makefile" {
			return nil
		}
		body, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range awkProgram.FindAllSubmatchIndex(body, -1) {
			prog := body[m[2]:m[3]]
			for _, r := range regexInterval.FindAllIndex(prog, -1) {
				line := 1 + strings.Count(string(body[:m[2]+r[0]]), "\n")
				rel, relErr := filepath.Rel(root, p)
				if relErr != nil {
					return relErr
				}
				found = append(found, rel+":"+itoa(int64(line))+": "+string(prog[r[0]:r[1]]))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) > 0 {
		t.Fatalf("awk programs use a regex interval, which mawk 20200120 reads as literal braces; "+
			"spell the repeat out or compare with substr():\n  %s", strings.Join(found, "\n  "))
	}
}

func TestOPS134CertExtensionFindsCATrueUnderOldMawk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := dockertest.Usable(ctx); err != nil {
		t.Skipf("skipping OPS-134 (cert_extension under mawk 20200120): %v", err)
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skipf("skipping OPS-134 (cert_extension under mawk 20200120): no openssl: %v", err)
	}

	dir := t.TempDir()
	certPEM := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(certPEM, caCertPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	text, err := exec.CommandContext(ctx, "openssl", "x509", "-in", certPEM, "-noout", "-text").Output()
	if err != nil {
		t.Fatalf("openssl x509 -text: %v", err)
	}
	if err = os.WriteFile(filepath.Join(dir, "ca.txt"), text, 0o600); err != nil {
		t.Fatal(err)
	}

	verify := filepath.Join(repoRoot(t), "deploy", "compose", "sigstore", "verify.sh")
	// The container has no openssl: a shell function stands in for it and
	// prints the text the host's openssl wrote. Only the awk is under test.
	script := `sed -n '/^cert_extension()/,/^}/p' /verify.sh > /tmp/fn.sh
openssl() { cat /in/ca.txt; }
. /tmp/fn.sh
awk -W version 2>&1 | head -n 1
cert_extension /in/ca.crt 'X509v3 Basic Constraints'`
	out, err := dockertest.Docker(ctx, "run", "--rm",
		"--volume", dir+":/in:ro", "--volume", verify+":/verify.sh:ro",
		mawk2020Image, "sh", "-c", script)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "mawk 1.3.4 20200120") {
		t.Fatalf("%s no longer ships mawk 20200120, so this test proves nothing; got:\n%s", mawk2020Image, out)
	}
	if !strings.Contains(out, "CA:TRUE") {
		t.Fatalf("cert_extension under mawk 20200120 did not print CA:TRUE for a CA certificate; got:\n%s", out)
	}
}

func caCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "OPS-134 CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
