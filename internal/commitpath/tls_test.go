// SPDX-License-Identifier: Apache-2.0

// tls_test.go is an EXTERNAL test (package commitpath_test, not
// commitpath): it needs internal/gateway's real CA (gateway.LoadOrCreateCA)
// to drive a real TLS handshake, and internal/gateway's own production code
// imports internal/commitpath (record.go), so importing gateway from an
// INTERNAL commitpath test would be a genuine import cycle. An external
// test package has no such problem -- it depends on both, and neither of
// them depends on it -- which is also why every identifier it reaches for
// below is one commitpath.go already exports.
package commitpath_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/gateway"
)

// startTLSTestServer serves handler over TLS using cfg directly -- NOT
// httptest.Server.StartTLS, which (as of this Go release) injects its own
// default certificate into tls.Config.Certificates whenever that field is
// empty. A tls.Config built from gateway.CA.ServerTLSConfig() sets ONLY
// GetCertificate, and crypto/tls calls GetCertificate "if the client
// supplies SNI information OR if Certificates is empty" -- once httptest
// has populated Certificates with its own cert, and a client dialling an IP
// literal sends no SNI (RFC 6066 excludes IP literals), GetCertificate is
// never invoked and the server presents httptest's OWN certificate instead
// of the CA-issued leaf this test means to exercise. Serving manually, the
// way cmd/innsegl/gateway.go's own openGateway does, avoids that entirely.
func startTLSTestServer(t *testing.T, cfg *tls.Config, handler http.Handler) (url string) {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: handler, TLSConfig: cfg}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() {
		_ = srv.Close()
		if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("ServeTLS: %v", err)
		}
	})
	return "https://" + ln.Addr().String()
}

// TestTLS001HostClientTrustsTheCoresOwnCA is TLS-001: the gateway on
// loopback serves https with a certificate from the core's own CA, and the
// host commands (internal/commitpath.Client, built by ClientFromEnv) trust
// it. The installer agent arranges for a Node-style client to trust the
// SAME file through $NODE_EXTRA_CA_CERTS; this test proves the mechanism
// directly too -- a Go x509.CertPool built from ONLY that file (the shape
// NODE_EXTRA_CA_CERTS gives any TLS client, Node's included) accepts a real
// handshake against the real leaf.
func TestTLS001HostClientTrustsTheCoresOwnCA(t *testing.T) {
	caDir := t.TempDir()
	ca, err := gateway.LoadOrCreateCA(gateway.CAConfig{KeyDir: t.TempDir(), PublicDir: caDir})
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	url := startTLSTestServer(t, ca.ServerTLSConfig(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req commitpath.SignRequest
		if derr := json.NewDecoder(r.Body).Decode(&req); derr != nil {
			t.Errorf("decode: %v", derr)
		}
		if eerr := json.NewEncoder(w).Encode(commitpath.SignResponse{Signature: []byte("SIG")}); eerr != nil {
			t.Errorf("encode: %v", eerr)
		}
	}))

	caFile := filepath.Join(caDir, gateway.CACertFileName)
	client := commitpath.ClientFromEnv(func(k string) string {
		switch k {
		case commitpath.EnvCoreURL:
			return url
		case commitpath.EnvExtraCACerts:
			return caFile
		}
		return ""
	})

	resp, err := client.Sign(context.Background(), commitpath.SignRequest{ToolUseID: "toolu_01A"})
	if err != nil {
		t.Fatalf("Sign through a real TLS handshake against the core's own CA: %v", err)
	}
	if string(resp.Signature) != "SIG" {
		t.Errorf("Signature = %q", resp.Signature)
	}

	// The mechanism, proven directly: a pool built from ONLY the published
	// CA file accepts the same server's certificate -- the same trust
	// NODE_EXTRA_CA_CERTS would give a Node-style client pointed at this
	// same file.
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatalf("read the published CA certificate: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("the published CA certificate is not valid PEM")
	}
	dialer := tls.Dialer{Config: &tls.Config{RootCAs: pool}}
	conn, err := dialer.DialContext(t.Context(), "tcp", strings.TrimPrefix(url, "https://"))
	if err != nil {
		t.Fatalf("a client whose ONLY extra root is the CA file could not dial the gateway: %v", err)
	}
	_ = conn.Close()
}

// TestTLS001HostClientStillTrustsAfterARestart: the CA's key persists
// across a restart (internal/gateway's own TestTLS001RestartingKeepsTheSameCA
// proves the CA itself is unchanged); this proves what that means for the
// HOST side -- the SAME already-published trust file still authenticates a
// gateway process that reloaded its CA from the same KeyDir and minted a
// fresh leaf.
func TestTLS001HostClientStillTrustsAfterARestart(t *testing.T) {
	keyDir, caDir := t.TempDir(), t.TempDir()
	if _, err := gateway.LoadOrCreateCA(gateway.CAConfig{KeyDir: keyDir, PublicDir: caDir}); err != nil {
		t.Fatalf("first LoadOrCreateCA: %v", err)
	}
	caFile := filepath.Join(caDir, gateway.CACertFileName)

	// "Restart": a second CA instance loaded from the same KeyDir, as a new
	// process would be.
	restarted, err := gateway.LoadOrCreateCA(gateway.CAConfig{KeyDir: keyDir, PublicDir: caDir})
	if err != nil {
		t.Fatalf("second LoadOrCreateCA (the 'restart'): %v", err)
	}

	url := startTLSTestServer(t, restarted.ServerTLSConfig(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if eerr := json.NewEncoder(w).Encode(commitpath.TrailersResponse{Message: "ok"}); eerr != nil {
			t.Errorf("encode: %v", eerr)
		}
	}))

	client := commitpath.ClientFromEnv(func(k string) string {
		switch k {
		case commitpath.EnvCoreURL:
			return url
		case commitpath.EnvExtraCACerts:
			return caFile
		}
		return ""
	})
	if _, err := client.Trailers(context.Background(), commitpath.TrailersRequest{ToolUseID: "toolu_01A"}); err != nil {
		t.Fatalf("Trailers after a restart, against the SAME published trust file: %v", err)
	}
}

// TestTLS002SquattingProcessWithADifferentCertIsRefused is TLS-002: another
// process squats the port with a different self-signed certificate for
// 127.0.0.1 -- httptest.NewTLSServer's own default certificate, trusted by
// nobody this test configured -- and the host client refuses the handshake
// and sends nothing: the squatter's own handler, which only runs once an
// HTTP request has actually been read off the (decrypted) connection, is
// never invoked.
func TestTLS002SquattingProcessWithADifferentCertIsRefused(t *testing.T) {
	caDir := t.TempDir()
	if _, err := gateway.LoadOrCreateCA(gateway.CAConfig{KeyDir: t.TempDir(), PublicDir: caDir}); err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	caFile := filepath.Join(caDir, gateway.CACertFileName)

	var requestsReceived int32
	squatter := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requestsReceived, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer squatter.Close()

	client := commitpath.ClientFromEnv(func(k string) string {
		switch k {
		case commitpath.EnvCoreURL:
			return squatter.URL
		case commitpath.EnvExtraCACerts:
			return caFile
		}
		return ""
	})

	if _, err := client.Sign(context.Background(), commitpath.SignRequest{ToolUseID: "toolu_01A"}); err == nil {
		t.Fatal("Sign against a squatter presenting a different certificate succeeded, want a refusal")
	}
	if got := atomic.LoadInt32(&requestsReceived); got != 0 {
		t.Errorf("the squatter's own handler ran %d times, want 0 -- no HTTP request reached it", got)
	}
}
