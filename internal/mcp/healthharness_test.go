// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"innsegl.dev/innsegl/internal/spire"
)

// Real dependencies for MCP-012, and real ways to block them.
//
// Doc 07 puts MCP-012 in layer C, and the contract half of it — the shape of
// the reply — is asserted in health_test.go without any container. This file
// exists because the half that actually matters cannot be asserted that way.
//
// "Blocking each dependency in turn names that dependency and reports the
// others healthy" is a claim about what a probe observes. A stub that returns
// an error on demand exercises the stub; it says nothing about whether the
// probe ever ran, whether a real client's failure carries the class this file
// claims it does, or whether one dependency's outage bleeds into another's
// answer — which is the failure mode that makes a health endpoint useless
// during an incident, and the one thing MCP-012 is written to catch.
//
// So each dependency here is real and each block is real:
//
//	ledger    a Postgres container of this test's own, SIGKILLed and restarted
//	          (the same technique internal/ledger uses for LED-009, and for the
//	          same reason: "A container of its own: this test kills the server")
//	SPIRE     the SHIPPED compose stack under a project name unique to this
//	          test process (ADR-0022), reached over a socat proxy onto the
//	          admin network exactly as innsegl-mcp will reach it; blocked by
//	          removing the proxy, which closes the port for real
//	Sigstore  two real HTTP servers serving real trust material — a real
//	          X.509 CA certificate and a real ECDSA public key — blocked by
//	          closing their listeners
//
// The Sigstore half is the one honest compromise and it is named rather than
// hidden: `deploy/compose/` carries no Fulcio or Rekor yet (doc 05 §1 lists
// them; RM-030/#38 lifts them in), so there is no shipped pair to point at.
// What is real here is the probe, the transport, the artifacts it parses and
// the closure of the port; what is not real is the server behind it. See
// ADR-0024.

// ---------------------------------------------------------------------------
// Sigstore — real HTTP endpoints serving real trust material.
// ---------------------------------------------------------------------------

// healthEndpoint is one served artifact plus a count of how many times it was
// actually fetched.
//
// The counter is the anti-vacuity control. "The other dependencies were
// reported healthy" is satisfied by a probe that never ran, so every case that
// asserts Sigstore healthy also asserts that both endpoints were hit during
// that call and not before it.
type healthEndpoint struct {
	server      *httptest.Server
	calls       atomic.Int64
	path        string
	contentType string
	body        []byte

	// serveWrong replaces the body with something that is not the artifact,
	// while still answering 200. A probe that accepts any 200 passes this and
	// is therefore a check that never fails.
	serveWrong atomic.Bool
}

func newHealthEndpoint(path, contentType string, body []byte) *healthEndpoint {
	e := &healthEndpoint{path: path, contentType: contentType, body: body}
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
		e.calls.Add(1)
		if e.serveWrong.Load() {
			w.Header().Set("Content-Type", "text/html")
			healthIgnore(w.Write([]byte("<html>an ordinary web server, not this service</html>")))
			return
		}
		w.Header().Set("Content-Type", e.contentType)
		healthIgnore(w.Write(e.body))
	})
	e.server = httptest.NewServer(mux)
	return e
}

func (e *healthEndpoint) url() string { return e.server.URL }

// block closes the listener. The port is genuinely gone: a later dial gets
// ECONNREFUSED from the kernel, not an error this test wrote.
func (e *healthEndpoint) block() { e.server.Close() }

// healthFulcioRootPEM returns a genuine, self-signed CA certificate in PEM.
func healthFulcioRootPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"innsegl-test"}, CommonName: "innsegl test fulcio root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create the CA certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// healthRekorPublicKeyPEM returns a genuine PKIX ECDSA public key in PEM, the
// shape rekor serves at /api/v1/log/publicKey.
func healthRekorPublicKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a log key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal the log key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// healthSigstore is a live Fulcio/Rekor pair.
type healthSigstore struct {
	fulcio *healthEndpoint
	rekor  *healthEndpoint
}

func newHealthSigstore(t *testing.T) *healthSigstore {
	t.Helper()
	s := &healthSigstore{
		fulcio: newHealthEndpoint(DefaultFulcioRootPath, "application/pem-certificate-chain", healthFulcioRootPEM(t)),
		rekor:  newHealthEndpoint(DefaultRekorPublicKeyPath, "application/x-pem-file", healthRekorPublicKeyPEM(t)),
	}
	t.Cleanup(func() {
		s.fulcio.server.Close()
		s.rekor.server.Close()
	})
	return s
}

func (s *healthSigstore) probe(t *testing.T) *SigstoreEndpoints {
	t.Helper()
	p, err := NewSigstoreEndpoints(SigstoreConfig{
		FulcioURL: s.fulcio.url(),
		RekorURL:  s.rekor.url(),
	})
	if err != nil {
		t.Fatalf("NewSigstoreEndpoints: %v", err)
	}
	return p
}

// ---------------------------------------------------------------------------
// SPIRE — the shipped compose stack, scoped to this test process.
// ---------------------------------------------------------------------------

const (
	healthStackEnv    = "INNSEGL_SPIRE_TEST_STACK"
	healthAdminSocket = "/run/spire/admin/api.sock"
	healthAdminID     = "spiffe://innsegl.dev/innsegl/mcp"
	healthServerID    = "spiffe://innsegl.dev/spire/server"
	healthTrustDomain = "innsegl.dev"
	healthProxyImage  = "alpine/socat:1.8.0.3"
)

// healthStackPrefix names this process's stack. ADR-0022: no two packages —
// and no two harnesses inside one package — may select the same compose
// project. internal/mcp's get_credential harness is innsegl-mcptest-<pid>;
// this one is deliberately a different name.
func healthStackPrefix() string {
	return fmt.Sprintf("innsegl-mcphealth-%d", os.Getpid())
}

type healthSPIRE struct {
	composeFile  string
	overlayFile  string
	prefix       string
	adminNetwork string

	proxyName string
	proxyPort string
	adminAddr string
}

func (s *healthSPIRE) compose(ctx context.Context, args ...string) (string, error) {
	// Set immediately before every call: two harnesses in this package set
	// this variable, and the overlay interpolates it into container and
	// network names.
	if err := os.Setenv(healthStackEnv, s.prefix); err != nil {
		return "", fmt.Errorf("set %s: %w", healthStackEnv, err)
	}
	full := []string{"compose", "-p", s.prefix, "-f", s.composeFile, "-f", s.overlayFile}
	return docker(ctx, append(full, args...)...)
}

func (s *healthSPIRE) spireLocal(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"exec", "-T", "spire-server", "/opt/spire/bin/spire-server"}, args...)
	full = append(full, "-socketPath", healthAdminSocket)
	return s.compose(ctx, full...)
}

// healthMintedSVID satisfies spire.Source from `spire-server x509 mint`
// output. Deliberately this file's own rather than shared with the
// get_credential harness: a harness another agent's file has to keep
// compiling is a coupling neither of us asked for.
type healthMintedSVID struct {
	svid  *x509svid.SVID
	roots []*x509.Certificate
}

func (m healthMintedSVID) GetX509SVID() (*x509svid.SVID, error) { return m.svid, nil }

func (m healthMintedSVID) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return x509bundle.FromX509Authorities(td, m.roots), nil
}

func (s *healthSPIRE) mintAdmin(ctx context.Context) (healthMintedSVID, error) {
	out, err := s.spireLocal(ctx, "x509", "mint", "-spiffeID", healthAdminID, "-ttl", "1h")
	if err != nil {
		return healthMintedSVID{}, fmt.Errorf("mint %s: %w", healthAdminID, err)
	}
	const hSVID, hKey, hRoots = "X509-SVID:", "Private key:", "Root CAs:"
	i, j, k := strings.Index(out, hSVID), strings.Index(out, hKey), strings.Index(out, hRoots)
	if i < 0 || j < i || k < j {
		return healthMintedSVID{}, fmt.Errorf("unrecognised `x509 mint` output: %.200q", out)
	}
	svid, err := x509svid.Parse([]byte(out[i+len(hSVID):j]), []byte(out[j+len(hKey):k]))
	if err != nil {
		return healthMintedSVID{}, fmt.Errorf("parse minted SVID: %w", err)
	}
	var roots []*x509.Certificate
	rest := []byte(out[k+len(hRoots):])
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		c, perr := x509.ParseCertificate(blk.Bytes)
		if perr != nil {
			return healthMintedSVID{}, perr
		}
		roots = append(roots, c)
	}
	if len(roots) == 0 {
		return healthMintedSVID{}, errors.New("no trust bundle in `x509 mint` output")
	}
	return healthMintedSVID{svid: svid, roots: roots}, nil
}

// client dials the admin API the way innsegl-mcp will: mTLS over SPIFFE
// identities, the server authorized by ID.
func (s *healthSPIRE) client(t *testing.T) *spire.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	src, err := s.mintAdmin(ctx)
	if err != nil {
		t.Fatalf("mint the admin SVID: %v", err)
	}
	c, err := spire.Dial(ctx, spire.Config{
		Address: s.adminAddr, TrustDomain: healthTrustDomain,
		ServerID: healthServerID, Source: src,
	})
	if err != nil {
		t.Fatalf("spire.Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// startProxy publishes the admin API on a host port. ADR-0011 gives the admin
// network no published port, so this is how a host-side client reaches it —
// and removing it is how this test closes that port.
func (s *healthSPIRE) startProxy(ctx context.Context) error {
	if _, rmErr := docker(ctx, "rm", "--force", s.proxyName); rmErr != nil {
		_ = rmErr // a leftover from an interrupted run; absence is the normal case
	}
	if _, err := docker(ctx, "run", "--detach", "--name", s.proxyName,
		"--publish", "127.0.0.1:"+s.proxyPort+":8081",
		healthEnvOr("INNSEGL_TEST_PROXY_IMAGE", healthProxyImage),
		"TCP-LISTEN:8081,fork,reuseaddr", "TCP:spire-server:8081",
	); err != nil {
		return fmt.Errorf("start the admin proxy: %w", err)
	}
	if _, err := docker(ctx, "network", "connect", s.adminNetwork, s.proxyName); err != nil {
		return fmt.Errorf("join %s: %w", s.adminNetwork, err)
	}
	return nil
}

// block removes the proxy container. The published port goes with it: a dial
// to s.adminAddr afterwards is refused by the kernel.
func (s *healthSPIRE) block(ctx context.Context) error {
	_, err := docker(ctx, "rm", "--force", s.proxyName)
	return err
}

func startHealthSPIRE(ctx context.Context, root string) (*healthSPIRE, error) {
	s := &healthSPIRE{
		composeFile:  filepath.Join(root, "deploy", "compose", "spire.yml"),
		overlayFile:  filepath.Join(root, "deploy", "compose", "spire-testscope.yml"),
		prefix:       healthStackPrefix(),
		adminNetwork: healthStackPrefix() + "-spire-admin",
	}
	s.proxyName = s.prefix + "-healthproxy"

	// Only spire-server. Readiness asks SPIRE whether it can answer an admin
	// RPC; that needs no attested agent, so the agent, the OIDC provider and
	// their host port are not brought up.
	if _, err := s.compose(ctx, "up", "--detach", "--wait", "spire-server"); err != nil {
		return s, fmt.Errorf("compose up: %w", err)
	}
	port, err := freeHostPort(ctx)
	if err != nil {
		return s, fmt.Errorf("reserve a host port: %w", err)
	}
	s.proxyPort = port
	s.adminAddr = "127.0.0.1:" + port
	if err := s.startProxy(ctx); err != nil {
		return s, err
	}
	return s, nil
}

func (s *healthSPIRE) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	if s.proxyName != "" {
		if _, err := docker(ctx, "rm", "--force", s.proxyName); err != nil {
			fmt.Fprintf(os.Stderr, "warning: removing %s: %v\n", s.proxyName, err)
		}
	}
	if _, err := s.compose(ctx, "down", "--volumes", "--remove-orphans"); err != nil {
		fmt.Fprintf(os.Stderr, "warning: compose down: %v\n", err)
	}
}

// healthIgnore swallows the result of a call whose failure this fixture cannot
// act on — a write to a client that has gone, a socket option on a connection
// about to be reset. The side of the failure the tests read is the probe's.
func healthIgnore(...any) {}

func healthEnvOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// healthRepoRoot is the module root, two directories up from internal/mcp.
func healthRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	return filepath.Dir(filepath.Dir(wd))
}
