// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The parts of the wiring that can be decided without a Postgres and a SPIRE:
// the trust-bundle reader, the privilege verdict, the credential-source choice
// and the option validation.
//
// The wiring ITSELF — which dependency is handed to which tool, and in what
// order — is not asserted here and cannot be. Both orders of ADR-0025's
// wrapper compile and both produce a working tool, so the only test that can
// tell them apart is one that calls the served tool until it is refused:
// test/failure/serve_test.go, against the shipped binary.

func TestParsePEMCertificatesReadsEveryCertificateAndRefusesRubbish(t *testing.T) {
	// A trust bundle is a CHAIN: a reader that stopped at the first block
	// would silently drop an intermediate and then fail to verify a peer for a
	// reason nobody could see.
	leafPEM, _, caPEM := testSVIDPEM(t)
	two := leafPEM + caPEM

	certs, err := parsePEMCertificates([]byte(two))
	if err != nil {
		t.Fatalf("parsePEMCertificates: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("read %d certificates from a two-certificate bundle", len(certs))
	}

	for _, tc := range []struct{ name, body string }{
		{"empty", ""},
		{"no PEM at all", "this is not a certificate"},
		{"a PEM block that is not a certificate", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parsePEMCertificates([]byte(tc.body)); err == nil {
				t.Fatal("accepted; a trust bundle that parses to nothing authorizes nothing " +
					"and must not be read as an empty one")
			}
		})
	}
}

func TestLoadFileSourceRefusesEachUnusablePiece(t *testing.T) {
	dir := t.TempDir()
	leafPEM, keyPEM, caPEM := testSVIDPEM(t)
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return path
	}
	bundle := write("bundle.pem", caPEM)
	missing := filepath.Join(dir, "nothing.pem")

	for _, tc := range []struct {
		name string
		o    serveOptions
		want string
	}{
		{"no SVID file", serveOptions{
			svidFile: missing, keyFile: missing, bundleFile: bundle, trustDomain: "innsegl.dev",
		}, "load the admin SVID"},
		{"unusable trust domain", serveOptions{
			svidFile: write("svid.pem", leafPEM), keyFile: write("key.pem", keyPEM),
			bundleFile: bundle, trustDomain: "not a trust domain",
		}, "trust domain"},
		{"no trust bundle", serveOptions{
			svidFile: write("svid2.pem", leafPEM), keyFile: write("key2.pem", keyPEM),
			bundleFile: missing, trustDomain: "innsegl.dev",
		}, "read the trust bundle"},
		{"a trust bundle that is not certificates", serveOptions{
			svidFile: write("svid3.pem", leafPEM), keyFile: write("key3.pem", keyPEM),
			bundleFile: write("junk.pem", "nothing here"), trustDomain: "innsegl.dev",
		}, "parse the trust bundle"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadFileSource(tc.o)
			if err == nil {
				t.Fatal("accepted; a credential this process cannot use is not a credential")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %q", err, tc.want)
			}
		})
	}
}

func TestOpenCredentialSourceNamesWhichSourceItUsed(t *testing.T) {
	// The choice is operator-visible: "this process holds a file" and "this
	// process is an attested workload" are different assurance claims, and
	// doc 05 §1 is written about the second.
	dir := t.TempDir()
	leafPEM, keyPEM, caPEM := testSVIDPEM(t)
	svid := filepath.Join(dir, "svid.pem")
	key := filepath.Join(dir, "key.pem")
	bundle := filepath.Join(dir, "bundle.pem")
	for path, body := range map[string]string{svid: leafPEM, key: keyPEM, bundle: caPEM} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	_, closeSource, how, err := openCredentialSource(t.Context(), serveOptions{
		svidFile: svid, keyFile: key, bundleFile: bundle, trustDomain: "innsegl.dev",
	})
	if err != nil {
		t.Fatalf("openCredentialSource from files: %v", err)
	}
	defer closeSource()
	if !strings.HasPrefix(how, "files:") {
		t.Errorf("the file source reports itself as %q", how)
	}
}

func TestDialSVIDAPIRefusesAnUnusableServerID(t *testing.T) {
	_, err := dialSVIDAPI(serveOptions{
		spireAddress: "127.0.0.1:8081", serverID: "not a spiffe id",
	}, fileSource{})
	if err == nil {
		t.Fatal("accepted; a connection that authorizes nothing in particular authorizes anything")
	}
	if !strings.Contains(err.Error(), "SPIRE server id") {
		t.Errorf("error %q does not name the setting", err)
	}
}

func TestChainPrivilegesVerdict(t *testing.T) {
	for _, tc := range []struct {
		name       string
		p          chainPrivileges
		appendOnly bool
		granted    string
	}{
		{"the role doc 05 §1 describes",
			chainPrivileges{role: "innsegl_mcp", canInsert: true}, true, "INSERT"},
		{"cannot append",
			chainPrivileges{role: "reader"}, false, ""},
		{"the table owner",
			chainPrivileges{role: "innsegl", canInsert: true, canUpdate: true, canDelete: true, canTrunc: true},
			false, "INSERT,UPDATE,DELETE,TRUNCATE"},
		{"can delete but not update",
			chainPrivileges{role: "half", canInsert: true, canDelete: true}, false, "INSERT,DELETE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.appendOnly(); got != tc.appendOnly {
				t.Errorf("appendOnly() = %v, want %v", got, tc.appendOnly)
			}
			if got := strings.Join(tc.p.granted(), ","); got != tc.granted {
				t.Errorf("granted() = %q, want %q", got, tc.granted)
			}
		})
	}
}

func TestSplitOriginsIgnoresPaddingAndEmptyEntries(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"https://a.example", []string{"https://a.example"}},
		{" https://a.example , https://b.example ", []string{"https://a.example", "https://b.example"}},
		{"https://a.example,,", []string{"https://a.example"}},
	} {
		got := splitOrigins(tc.in)
		if len(got) != len(tc.want) {
			t.Fatalf("splitOrigins(%q) = %v, want %v", tc.in, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitOrigins(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

// TestValidateRefusesEveryUnusableCombination covers the settings whose
// refusal is not a plain "missing" — the ones an operator can set to something
// that looks configured and is not.
func TestValidateRefusesEveryUnusableCombination(t *testing.T) {
	base := serveOptions{
		dsn: "postgres://x", spireAddress: "h:1", trustDomain: "innsegl.dev",
		parentID: "spiffe://innsegl.dev/spire/agent/x", fulcioURL: "http://f", rekorURL: "http://r",
		listen: "127.0.0.1:0", healthListen: "127.0.0.1:0",
		rateCalls: 1, rateWindow: 60_000_000_000,
	}
	if problem := base.validate(); problem != "" {
		t.Fatalf("the complete configuration was refused: %s", problem)
	}

	for _, tc := range []struct {
		name  string
		patch func(*serveOptions)
		want  string
	}{
		{"no listen address", func(o *serveOptions) { o.listen = "" }, "-listen"},
		{"no health address", func(o *serveOptions) { o.healthListen = "" }, "-health-listen"},
		{"a negative rate limit", func(o *serveOptions) { o.rateCalls = -1 }, "-register-rate-calls"},
		{"a limit over no time", func(o *serveOptions) { o.rateWindow = 0 }, "-register-rate-window"},
		{"a negative lease", func(o *serveOptions) { o.lease = -1 }, "-idempotency-lease"},
		{"a negative shutdown bound", func(o *serveOptions) { o.shutdownTimeout = -1 }, "-shutdown-timeout"},
		{"a credential with no key", func(o *serveOptions) { o.svidFile = "svid.pem" }, "-svid, -key and -bundle"},
		{"a credential with no bundle", func(o *serveOptions) {
			o.svidFile, o.keyFile = "svid.pem", "key.pem"
		}, "-svid, -key and -bundle"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			tc.patch(&o)
			problem := o.validate()
			if problem == "" {
				t.Fatal("accepted")
			}
			if !strings.Contains(problem, tc.want) {
				t.Errorf("refusal %q does not name %q", problem, tc.want)
			}
		})
	}

	// All three together is the one credential the file source needs.
	o := base
	o.svidFile, o.keyFile, o.bundleFile = "svid.pem", "key.pem", "bundle.pem"
	if problem := o.validate(); problem != "" {
		t.Errorf("all three credential files together were refused: %s", problem)
	}
}

func TestEnvIntFallsBackOnAnythingUnreadable(t *testing.T) {
	const name = "INNSEGL_TEST_ENV_INT"
	for _, tc := range []struct {
		set  string
		want int
	}{
		{"", 7}, {"not a number", 7}, {"12", 12}, {"-3", -3},
	} {
		t.Setenv(name, tc.set)
		if got := envInt(name, 7); got != tc.want {
			t.Errorf("envInt(%q=%q) = %d, want %d", name, tc.set, got, tc.want)
		}
	}
}
