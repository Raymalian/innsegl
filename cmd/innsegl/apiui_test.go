// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #475: `innsegl api` serves the dashboard's UI and terminates its TLS.
// The nginx container that did both is gone. These hold the command's half:
// the three settings, their environment names, the rule between them, and
// the two listeners serving one handler. internal/api's own tests hold the
// UI rules and the certificate reload.

func TestAPIUIAndTLSSettingsHaveFlagsAndEnvironmentNames(t *testing.T) {
	var seen apiOptions
	var stderr bytes.Buffer
	code := runAPI(context.Background(), minimalAPIArgs(
		"-ui-dir", "/srv/ui",
		"-tls-listen", "0.0.0.0:8443",
		"-tls-cert", "/run/tls/dashboard-tls.pem",
	), io.Discard, &stderr, stubAPIDeps(&stubAPI{serveErr: io.EOF}, &seen))
	if code == exitUsage {
		t.Fatalf("the flags were refused: %s", stderr.String())
	}
	if seen.uiDir != "/srv/ui" || seen.tlsListen != "0.0.0.0:8443" || seen.tlsCert != "/run/tls/dashboard-tls.pem" {
		t.Errorf("flags resolved to ui=%q tls-listen=%q tls-cert=%q", seen.uiDir, seen.tlsListen, seen.tlsCert)
	}

	t.Setenv(envAPIUIDir, "/env/ui")
	t.Setenv(envAPITLSListen, "0.0.0.0:9443")
	t.Setenv(envAPITLSCert, "/env/dashboard-tls.pem")
	seen = apiOptions{}
	code = runAPI(context.Background(), minimalAPIArgs(), io.Discard, &stderr, stubAPIDeps(&stubAPI{serveErr: io.EOF}, &seen))
	if code == exitUsage {
		t.Fatalf("the environment was refused: %s", stderr.String())
	}
	if seen.uiDir != "/env/ui" || seen.tlsListen != "0.0.0.0:9443" || seen.tlsCert != "/env/dashboard-tls.pem" {
		t.Errorf("environment resolved to ui=%q tls-listen=%q tls-cert=%q", seen.uiDir, seen.tlsListen, seen.tlsCert)
	}
}

// Unset, the command is what it was before #475: the API alone, plain HTTP.
func TestAPIUIAndTLSAreOffByDefault(t *testing.T) {
	var seen apiOptions
	if code := runAPI(context.Background(), minimalAPIArgs(), io.Discard, io.Discard,
		stubAPIDeps(&stubAPI{serveErr: io.EOF}, &seen)); code == exitUsage {
		t.Fatal("the minimal command line was refused")
	}
	if seen.uiDir != "" || seen.tlsListen != "" || seen.tlsCert != "" {
		t.Errorf("defaults ui=%q tls-listen=%q tls-cert=%q, want all empty", seen.uiDir, seen.tlsListen, seen.tlsCert)
	}
}

// A TLS listener needs a certificate and a certificate needs a listener.
// Either alone is refused by name, before anything is opened.
func TestAPITLSListenAndCertAreSetTogether(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-tls-listen", "0.0.0.0:8443"}, "-tls-cert"},
		{[]string{"-tls-cert", "/run/tls/dashboard-tls.pem"}, "-tls-listen"},
	} {
		opened := false
		deps := apiDeps{open: func(context.Context, apiOptions, *serveLog) (servedAPI, error) {
			opened = true
			return nil, nil
		}}
		var stderr bytes.Buffer
		code := runAPI(context.Background(), minimalAPIArgs(tc.args...), io.Discard, &stderr, deps)
		if code != exitUsage {
			t.Errorf("%v: exit %d, want %d", tc.args, code, exitUsage)
		}
		if opened {
			t.Errorf("%v: the API was opened before the refusal", tc.args)
		}
		if !strings.Contains(stderr.String(), tc.want) {
			t.Errorf("%v: stderr does not name %s: %s", tc.args, tc.want, stderr.String())
		}
	}
}

func TestAPIHelpNamesTheUIAndTLSSettings(t *testing.T) {
	var stderr bytes.Buffer
	runAPI(context.Background(), []string{"-h"}, io.Discard, &stderr, apiDeps{})
	for _, want := range []string{"-ui-dir", envAPIUIDir, "-tls-listen", envAPITLSListen, "-tls-cert", envAPITLSCert} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("help does not mention %s", want)
		}
	}
}

// writeTestDashboardPEM writes a self-signed certificate and key into one
// file, the shape the core writes.
func writeTestDashboardPEM(t *testing.T, path string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The plain listener and the TLS listener serve the same handler: the UI,
// the API under /api/, and the security headers, on both.
func TestAPIServesTheUIOnBothListeners(t *testing.T) {
	ui := t.TempDir()
	if err := os.WriteFile(filepath.Join(ui, "index.html"), []byte("<!doctype html>ui"), 0o644); err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(t.TempDir(), "dashboard-tls.pem")
	writeTestDashboardPEM(t, certFile)

	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, werr := io.WriteString(w, "api"); werr != nil {
			panic(werr)
		}
	})
	o := apiOptions{
		listen: "127.0.0.1:0", tlsListen: "127.0.0.1:0", tlsCert: certFile, uiDir: ui,
		shutdownTimeout: time.Second,
	}
	running, err := bindAPI(context.Background(), o, apiHandler, newServeLog(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	defer running.Close()
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- running.Serve(ctx) }()

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	// get answers the headers, the TLS state and the body; the response
	// itself never leaves, so its body is closed here.
	get := func(url string) (http.Header, *tls.ConnectionState, []byte) {
		t.Helper()
		req, rerr := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
		if rerr != nil {
			t.Fatal(rerr)
		}
		resp, rerr := client.Do(req)
		if rerr != nil {
			t.Fatalf("GET %s: %v", url, rerr)
		}
		defer resp.Body.Close()
		body, rerr := io.ReadAll(resp.Body)
		if rerr != nil {
			t.Fatalf("GET %s: %v", url, rerr)
		}
		return resp.Header, resp.TLS, body
	}
	for _, base := range []string{"http://" + running.Addr(), "https://" + running.TLSAddr()} {
		for path, want := range map[string]string{"/runs/x": "<!doctype html>ui", "/api/v1/health": "api"} {
			header, _, body := get(base + path)
			if string(body) != want {
				t.Errorf("GET %s%s: %q, want %q", base, path, body, want)
			}
			if header.Get("X-Frame-Options") != "DENY" {
				t.Errorf("GET %s%s: no X-Frame-Options", base, path)
			}
		}
	}
	if _, state, _ := get("https://" + running.TLSAddr() + "/"); state == nil || state.PeerCertificates[0].SerialNumber.Int64() != 42 {
		t.Error("the TLS listener did not present the dashboard's certificate")
	}

	cancel()
	if err := <-served; err != nil {
		t.Fatalf("Serve after stop: %v", err)
	}
}

func TestAPIWithoutTLSBindsOnlyThePlainListener(t *testing.T) {
	o := apiOptions{listen: "127.0.0.1:0", shutdownTimeout: time.Second}
	running, err := bindAPI(context.Background(), o, http.NotFoundHandler(), newServeLog(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	defer running.Close()
	if running.TLSAddr() != "" {
		t.Errorf("TLSAddr %q with no -tls-listen", running.TLSAddr())
	}
}

func TestAPIBindRefusesABadUIDirOrAddress(t *testing.T) {
	log := newServeLog(io.Discard)
	if _, err := bindAPI(context.Background(), apiOptions{listen: "127.0.0.1:0", uiDir: t.TempDir()},
		http.NotFoundHandler(), log); err == nil || !strings.Contains(err.Error(), "index.html") {
		t.Errorf("a UI directory with no index.html: %v", err)
	}
	if _, err := bindAPI(context.Background(), apiOptions{listen: "256.0.0.1:1"},
		http.NotFoundHandler(), log); err == nil {
		t.Error("a bad listen address was accepted")
	}
	if _, err := bindAPI(context.Background(), apiOptions{listen: "127.0.0.1:0", tlsListen: "256.0.0.1:1", tlsCert: "x"},
		http.NotFoundHandler(), log); err == nil {
		t.Error("a bad TLS listen address was accepted")
	}
}
