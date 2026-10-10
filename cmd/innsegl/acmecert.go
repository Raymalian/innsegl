// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"

	"innsegl.dev/innsegl/internal/acme"
	"innsegl.dev/innsegl/internal/gateway"
)

// acmecert.go — #473, ADR-0081: the core's server certificate, from its own
// CA (the default) or, when asked for, publicly trusted through ACME DNS-01.
// Either way the gateway reads the current certificate on every handshake
// and the dashboard's server reads its file on every handshake, so renewal
// needs no restart. Client certificates are untouched: hosted mode keeps
// requiring the deployment's own client certificates (wrap).

// The settings. Off unless envACME is "on".
const (
	envACME              = "INNSEGL_ACME"
	envACMEEmail         = "INNSEGL_ACME_EMAIL"
	envACMEDirectory     = "INNSEGL_ACME_DIRECTORY"
	envACMEZone          = "INNSEGL_ACME_ZONE"
	envACMEDNSProvider   = "INNSEGL_ACME_DNS_PROVIDER"
	envACMECredentialVar = "INNSEGL_ACME_DNS_CREDENTIAL_VAR" //nolint:gosec // G101: a setting's name, not a credential
	envACMECredentialDir = "INNSEGL_ACME_CREDENTIAL_DIR"     //nolint:gosec // G101: a setting's name, not a credential
	envACMEStateDir      = "INNSEGL_ACME_STATE_DIR"
	envACMERootsFile     = "INNSEGL_ACME_ROOTS_FILE"
	envACMEResolvers     = "INNSEGL_ACME_DNS_RESOLVERS"
)

// acmeCredentialFile is the DNS credential's file in envACMECredentialDir,
// written once per host by the operator (ADR-0078's per-host credential
// pattern: a file in a volume, never a value in the environment).
const acmeCredentialFile = "dns-token"

// acmeProductionDirectory is the default ACME directory: the public CA's
// production endpoint. Its staging endpoint is set through envACMEDirectory.
const acmeProductionDirectory = "https://acme-v02.api.letsencrypt.org/directory"

// The sources a server certificate can come from.
const (
	serverCertOwnCA = "own-ca"
	serverCertACME  = acme.SourceACME
)

// serverCertStatus is what /_core/status says about the server certificate.
type serverCertStatus = acme.Status

// serverCerts is where the gateway's and the dashboard's certificates come
// from.
type serverCerts interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	WriteDashboardCert(dir string) (time.Time, error)
	Status() serverCertStatus
}

// ownCACerts is the default source: the core's own CA (ADR-0066).
type ownCACerts struct {
	ca    *gateway.CA
	names []string
}

func (o ownCACerts) GetCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return o.ca.GetCertificate(h)
}
func (o ownCACerts) WriteDashboardCert(dir string) (time.Time, error) {
	return o.ca.WriteDashboardCert(dir)
}
func (o ownCACerts) Status() serverCertStatus {
	st := serverCertStatus{Source: serverCertOwnCA, Names: o.names}
	if c, err := o.ca.GetCertificate(nil); err == nil && c.Leaf != nil {
		st.NotAfter = c.Leaf.NotAfter
	}
	return st
}

// serverTLSConfig is the listener's TLS: the source's certificate, TLS 1.2
// and up. Hosted mode adds the client certificate check (hostedCore.wrap).
func serverTLSConfig(src serverCerts) *tls.Config {
	return &tls.Config{GetCertificate: src.GetCertificate, MinVersion: tls.VersionTLS12}
}

// describeServerCert is the status line's text.
func describeServerCert(st serverCertStatus) string {
	source := "the core's own CA"
	if st.Source == serverCertACME {
		source = "public (ACME)"
	}
	out := source
	if len(st.Names) > 0 {
		out += ", for " + strings.Join(st.Names, ", ")
	}
	if !st.NotAfter.IsZero() {
		out += ", expires " + st.NotAfter.UTC().Format(time.DateOnly)
	}
	if st.Source != serverCertACME {
		out = strings.Replace(out, "the core's own CA", "own CA", 1)
	}
	return out
}

// acmeConfigFromEnv reads the settings, exporting the DNS credential's file
// to the provider.
func acmeConfigFromEnv(getenv func(string) string) (acme.Config, bool, error) {
	return acmeConfigFromEnvSet(getenv, os.Setenv)
}

// acmeConfigFromEnvSet is acmeConfigFromEnv with the export injected. The
// provider reads its credential from its own variable, and every provider
// accepts the variable's _FILE form; that is set to the per-host file.
func acmeConfigFromEnvSet(getenv func(string) string, setenv func(string, string) error) (acme.Config, bool, error) {
	if getenv(envACME) != "on" {
		return acme.Config{}, false, nil
	}
	for _, k := range []string{envACMEEmail, envACMEZone, envACMEDNSProvider, envACMECredentialVar, envACMEStateDir} {
		if getenv(k) == "" {
			return acme.Config{}, true, fmt.Errorf("%s=on needs %s", envACME, k)
		}
	}
	names, _, err := gatewayCertNamesFromEnv(getenv)
	if err != nil {
		return acme.Config{}, true, err
	}
	if len(names) == 0 {
		return acme.Config{}, true, fmt.Errorf("%s=on needs a DNS name in %s: a public certificate names no address",
			envACME, gatewayCertNamesEnv)
	}
	credDir := getenv(envACMECredentialDir)
	if credDir == "" {
		credDir = "/run/innsegl/credentials/acme-dns" //nolint:gosec // G101: a directory, not a credential
	}
	cred := filepath.Join(credDir, acmeCredentialFile)
	if _, serr := os.Stat(cred); serr != nil {
		return acme.Config{}, true, fmt.Errorf("the DNS credential %s: %w; write it with `make innsegl-acme-credential`", cred, serr)
	}
	if err := setenv(getenv(envACMECredentialVar)+"_FILE", cred); err != nil {
		return acme.Config{}, true, err
	}
	cfg := acme.Config{
		Email: getenv(envACMEEmail), DirectoryURL: getenv(envACMEDirectory), Names: names,
		Zone: getenv(envACMEZone), StateDir: getenv(envACMEStateDir), ProviderName: getenv(envACMEDNSProvider),
	}
	if cfg.DirectoryURL == "" {
		cfg.DirectoryURL = acmeProductionDirectory
	}
	if r := getenv(envACMEResolvers); r != "" {
		// The resolvers the DNS-01 check asks whether the record is out,
		// instead of the system's (a split-horizon or test DNS).
		var servers []string
		for _, s := range strings.Split(r, ",") {
			if s = strings.TrimSpace(s); s != "" {
				servers = append(servers, s)
			}
		}
		cfg.ChallengeOptions = append(cfg.ChallengeOptions, dns01.AddRecursiveNameservers(servers))
	}
	if f := getenv(envACMERootsFile); f != "" {
		// A local ACME server's own TLS (a test server): its root beside the
		// system's, for reaching the directory only.
		raw, rerr := os.ReadFile(f) // #nosec G304 -- operator configuration
		if rerr != nil {
			return acme.Config{}, true, fmt.Errorf("%s: %w", envACMERootsFile, rerr)
		}
		pool, perr := x509.SystemCertPool()
		if perr != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(raw) {
			return acme.Config{}, true, fmt.Errorf("%s: %s holds no PEM certificate", envACMERootsFile, f)
		}
		cfg.HTTPClient = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	}
	return cfg, true, nil
}

// acmeRenewer renews the ACME certificates and rewrites the dashboard's file
// after each renewal. It checks hourly; a failure is logged and tried again
// at the next check, while the certificate in use is still valid.
type acmeRenewer struct {
	m            *acme.Manager
	dashboardDir string
	log          *serveLog
	every        time.Duration
}

func (a *acmeRenewer) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(a.every):
		}
		a.check(ctx)
	}
}

func (a *acmeRenewer) check(ctx context.Context) {
	renewed, err := a.m.RenewDue(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		a.log.warn("could not renew the server certificate; trying again", "err", err)
	}
	if renewed == 0 {
		return
	}
	a.log.info("renewed the server certificate", "expires", a.m.Status().NotAfter.UTC().Format(time.RFC3339))
	if a.dashboardDir != "" {
		if _, werr := a.m.WriteDashboardCert(a.dashboardDir); werr != nil {
			a.log.warn("could not write the renewed dashboard certificate", "dir", a.dashboardDir, "err", werr)
		}
	}
}
