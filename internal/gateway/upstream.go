// SPDX-License-Identifier: Apache-2.0

// Package gateway is the model-traffic reverse proxy ADR-0057 and ADR-0060
// describe: it forwards every request to a configured upstream unchanged and
// streams the reply back as it arrives, reading an Anthropic Messages SSE
// reply for tool_use content blocks as they complete rather than waiting for
// the stream to end.
//
// # The byte path is the byte path
//
// Nothing in this package alters a forwarded request or reply. Parsing --
// SSE framing, the Messages event shape, tool_use reassembly -- runs off a
// copy of the bytes already written to the caller, never in front of them:
// see Proxy.ServeHTTP and messagesInterpreter.
//
// # Upstream trust (RM-226, #371)
//
// Every upstream connection verifies certificates and hostnames strictly,
// against the system roots -- crypto/tls's ordinary behaviour, since
// nothing in this package ever sets tls.Config.InsecureSkipVerify (see
// TestNoProductionCodeSetsInsecureSkipVerify in upstream_test.go) -- with
// TLS 1.2 as the floor. See defaultUpstreamClient.
//
// The https-or-refuse rule itself (GW-007) is enforced at start-up in
// cmd/innsegl/gateway.go, before this package ever opens a connection, not
// here: NewUpstream still accepts any scheme with a host, so a test can
// hand an Upstream its own client and root pool (NewUpstream's client
// parameter is the injectable seam) and point it at an httptest TLS server
// signed by a CA of the test's own making, without production configuration
// getting an "allow http" escape hatch anywhere in this package.
//
// # What this package does not do yet
//
// It does not relay WebSocket traffic (#372), it does not redact anything
// from a body (#373), and it refuses no harness shape (#374). Every one of
// those is a later issue in epic #357.
package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Upstream is the model provider this gateway relays to: a base URL and the
// HTTP client used to reach it.
//
// Construction lives in this file on its own, so that #371 (RM-226) -- the
// http-refusal and certificate-strictness rules this issue does not
// implement -- has one place to add them without moving anything else in the
// gateway.
type Upstream struct {
	// base is the upstream's scheme, host and any path prefix. A request's
	// own path is appended to it (singleJoiningSlash); its query string is
	// carried over unchanged.
	base *url.URL

	// Client sends every forwarded request. Configurable so a test can point
	// it at an httptest.NewTLSServer (or a purpose-built certificate of its
	// own) with that server's certificate in its own root pool -- see
	// upstream_test.go's GW-006 cases -- and so a deployment can supply a
	// client of its own. A nil client gets defaultUpstreamClient: certificate
	// and hostname verification against the system roots, TLS 1.2 as the
	// floor, InsecureSkipVerify never set (#371).
	Client *http.Client
}

// NewUpstream resolves base and returns an Upstream that sends through
// client. A nil client gets defaultUpstreamClient, which has no Timeout of
// its own: an http.Client.Timeout bounds the WHOLE request -- headers and
// body both -- and the gateway's job is to relay a reply for as long as it
// takes to arrive, a long-lived stream included, so setting one here would
// cut a legitimate reply off partway through. A caller that wants an upper
// bound gets it from the incoming request's own context, which every
// forwarded request carries (see Proxy.buildRequest). Only the connect and
// the TLS handshake are bounded, by defaultUpstreamClient's own Transport.
func NewUpstream(base string, client *http.Client) (*Upstream, error) {
	if strings.TrimSpace(base) == "" {
		return nil, fmt.Errorf("gateway: upstream base URL is empty")
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("gateway: upstream base URL %q: %w", base, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf(
			"gateway: upstream base URL %q must be absolute, with a scheme and a host", base)
	}
	if client == nil {
		client = defaultUpstreamClient()
	}
	return &Upstream{base: u, Client: client}, nil
}

// upstreamDialTimeout bounds only the TCP connect and the TLS handshake to
// the upstream -- never the whole request or reply, which
// defaultUpstreamClient leaves Client.Timeout at zero to avoid cutting off
// (see NewUpstream's own doc comment above).
const upstreamDialTimeout = 10 * time.Second

// defaultUpstreamClient is what NewUpstream builds when no client is given
// -- the production upstream client. Certificates and hostnames are
// verified against the system roots, which is crypto/tls's ordinary
// behaviour: nothing here, or anywhere else in this package, ever sets
// tls.Config.InsecureSkipVerify (TestNoProductionCodeSetsInsecureSkipVerify
// pins that as a regression test, not only a claim in this comment).
// MinVersion floors the handshake at TLS 1.2. Only the connect and the TLS
// handshake carry a bound; the request and reply do not.
func defaultUpstreamClient() *http.Client {
	dialer := &net.Dialer{Timeout: upstreamDialTimeout}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   upstreamDialTimeout,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// classifyUpstreamError maps err -- what Upstream.Client.Do returned -- to
// the status and failure-class message GW-008 requires: an upstream
// failure (TLS, connect refused, timeout) reaches the caller as a JSON body
// naming the failure class, never as a dropped connection, and never by
// echoing anything from the request itself -- err's own text is a client
// or transport failure, never a request header.
func classifyUpstreamError(err error) (status int, msg string) {
	var (
		hostErr x509.HostnameError
		authErr x509.UnknownAuthorityError
		certErr x509.CertificateInvalidError
		netErr  net.Error
	)
	switch {
	case errors.As(err, &hostErr), errors.As(err, &authErr), errors.As(err, &certErr):
		return http.StatusBadGateway, "innsegl gateway: upstream certificate rejected"
	case errors.As(err, &netErr) && netErr.Timeout():
		return http.StatusGatewayTimeout, "innsegl gateway: upstream request timed out"
	case isConnectionRefused(err):
		return http.StatusBadGateway, "innsegl gateway: upstream connection refused"
	default:
		return http.StatusBadGateway, "innsegl gateway: the upstream request failed"
	}
}

// isConnectionRefused reports whether err is, or wraps, a TCP connection
// refusal. Checked by message rather than a platform syscall errno, since a
// refusal reaches here through net/http's transport on whatever platform
// this binary runs on.
func isConnectionRefused(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return strings.Contains(opErr.Err.Error(), "connection refused")
	}
	return strings.Contains(err.Error(), "connection refused")
}

// Base returns the upstream's own base URL, as resolved by NewUpstream.
func (u *Upstream) Base() *url.URL {
	cp := *u.base
	return &cp
}

// resolve builds the upstream URL for an incoming request's path and query,
// unchanged: Base's own path, if any, prefixes the incoming path, and the
// incoming query string is carried over exactly as received.
func (u *Upstream) resolve(path, rawQuery string) *url.URL {
	out := *u.base
	out.Path = singleJoiningSlash(u.base.Path, path)
	out.RawPath = ""
	out.RawQuery = rawQuery
	return &out
}

// singleJoiningSlash joins a base path and a request path with exactly one
// slash between them, matching net/http/httputil's own reverse-proxy
// convention so a base URL with or without a trailing slash behaves the
// same way.
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash && a != "":
		return a + "/" + b
	default:
		return a + b
	}
}
