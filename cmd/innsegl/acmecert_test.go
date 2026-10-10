// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/acme"
)

// #473, ADR-0081: a publicly trusted server certificate, obtained through
// ACME DNS-01, as an option beside the core's own CA, which stays the
// default.

// TLS-007: off unless asked for; when asked for, every setting it needs is
// there, the names are the core's DNS names, and the DNS credential is read
// from its file.
func TestTLS007ACMEIsOffByDefaultAndConfiguredFromSettings(t *testing.T) {
	if cfg, on, err := acmeConfigFromEnv(env2(map[string]string{})); on || err != nil || cfg.Email != "" {
		t.Fatalf("with nothing set: on=%v err=%v; the own CA is the default", on, err)
	}

	cred := t.TempDir()
	if err := os.WriteFile(filepath.Join(cred, acmeCredentialFile), []byte("token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(roots, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	set := map[string]string{
		envACME:              "on",
		envACMEEmail:         "operator@innsegl.test",
		envACMEZone:          "innsegl.test",
		envACMEDNSProvider:   "exampledns",
		envACMECredentialVar: "EXAMPLEDNS_API_TOKEN",
		envACMECredentialDir: cred,
		envACMEStateDir:      "/acme-state",
		gatewayCertNamesEnv:  "core.innsegl.test,192.0.2.10",
	}
	var exported []string
	setenv := func(k, v string) error { exported = append(exported, k+"="+v); return nil }
	cfg, on, err := acmeConfigFromEnvSet(env2(set), setenv)
	if err != nil || !on {
		t.Fatalf("on=%v err=%v", on, err)
	}
	if cfg.DirectoryURL != acmeProductionDirectory || cfg.Zone != "innsegl.test" || cfg.ProviderName != "exampledns" ||
		cfg.StateDir != "/acme-state" || len(cfg.Names) != 1 || cfg.Names[0] != "core.innsegl.test" {
		t.Fatalf("config = %+v; want the production directory, the zone, the provider and the DNS name only", cfg)
	}
	if len(exported) != 1 || exported[0] != "EXAMPLEDNS_API_TOKEN_FILE="+filepath.Join(cred, acmeCredentialFile) {
		t.Fatalf("exported %v, want the provider's credential variable pointed at the file", exported)
	}

	if len(cfg.ChallengeOptions) != 0 {
		t.Error("challenge options set with no resolvers asked for")
	}
	set[envACMEResolvers] = "192.0.2.53:53, 192.0.2.54:53"
	if cfg, _, err = acmeConfigFromEnvSet(env2(set), setenv); err != nil || len(cfg.ChallengeOptions) != 1 {
		t.Fatalf("with resolvers: %d options, %v; want the resolvers the DNS-01 check asks", len(cfg.ChallengeOptions), err)
	}
	delete(set, envACMEResolvers)

	set[envACMEDirectory] = "https://localhost:14000/dir"
	set[envACMERootsFile] = roots
	if _, _, err = acmeConfigFromEnvSet(env2(set), setenv); err == nil {
		t.Fatal("a roots file with no certificate was accepted")
	}

	for _, missing := range []string{envACMEEmail, envACMEZone, envACMEDNSProvider, envACMECredentialVar, envACMEStateDir} {
		m := map[string]string{}
		for k, v := range set {
			m[k] = v
		}
		delete(m, envACMERootsFile)
		delete(m, missing)
		if _, _, err := acmeConfigFromEnvSet(env2(m), setenv); err == nil || !strings.Contains(err.Error(), missing) {
			t.Errorf("without %s: %v, want a refusal naming it", missing, err)
		}
	}
	m := map[string]string{}
	for k, v := range set {
		m[k] = v
	}
	delete(m, envACMERootsFile)
	m[gatewayCertNamesEnv] = "192.0.2.10"
	if _, _, err := acmeConfigFromEnvSet(env2(m), setenv); err == nil {
		t.Error("ACME with no DNS name to certify was accepted")
	}
	m[gatewayCertNamesEnv] = "core.innsegl.test"
	m[envACMECredentialDir] = t.TempDir()
	if _, _, err := acmeConfigFromEnvSet(env2(m), setenv); err == nil || !strings.Contains(err.Error(), acmeCredentialFile) {
		t.Errorf("a missing credential file: %v, want a refusal naming it", err)
	}
}

// fakeServerCerts is a certificate source with a fixed status.
type fakeServerCerts struct {
	cert *tls.Certificate
	st   serverCertStatus
}

func (f fakeServerCerts) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return f.cert, nil
}
func (f fakeServerCerts) WriteDashboardCert(string) (time.Time, error) { return f.st.NotAfter, nil }
func (f fakeServerCerts) Status() serverCertStatus                     { return f.st }

// TLS-008: the listener presents the source's certificate, and requires
// nothing of the client by itself: hosted mode still adds the client
// certificate check on top (wrap), whatever the server certificate is.
func TestTLS008TheListenerServesTheSourcesCertificate(t *testing.T) {
	want := &tls.Certificate{}
	cfg := serverTLSConfig(fakeServerCerts{cert: want})
	got, err := cfg.GetCertificate(nil)
	if err != nil || got != want || cfg.MinVersion != tls.VersionTLS12 || cfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("serverTLSConfig = %+v (%v)", cfg, err)
	}
}

// TLS-009: `innsegl status` says where the server certificate comes from
// and when it expires.
func TestTLS009StatusNamesTheServerCertificatesSourceAndExpiry(t *testing.T) {
	expires := time.Date(2027, 1, 8, 0, 0, 0, 0, time.UTC)
	deps := statusFixture(t, `[{"name":"ledger","up":true}]`, true,
		`,"server_certificate":{"source":"acme","names":["core.innsegl.test"],"not_after":"`+expires.Format(time.RFC3339)+`"}`)
	var out, errOut bytes.Buffer
	if code := runStatus(t.Context(), nil, &out, &errOut, deps); code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	for _, want := range []string{"server certificate", "public (ACME)", "core.innsegl.test", "2027-01-08"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status lacks %q:\n%s", want, out.String())
		}
	}
	if got := describeServerCert(serverCertStatus{Source: serverCertOwnCA, NotAfter: expires}); !strings.Contains(got, "own CA") {
		t.Errorf("own CA described as %q", got)
	}
	_ = acme.Status{}
}
