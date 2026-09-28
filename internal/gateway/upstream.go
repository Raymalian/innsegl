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
// # What this package does not do yet
//
// It does not enforce https-only or certificate strictness (RM-226, #371),
// it does not relay WebSocket traffic (#372), it does not redact anything
// from a body (#373), and it refuses no harness shape (#374). Every one of
// those is a later issue in epic #357, and this package's own construction
// is laid out so each slots in without moving what is already here:
// upstream.go is where #371 adds its rule.
package gateway

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
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
	// it at an httptest.NewTLSServer with that server's certificate in its
	// own root pool, and so a later deployment can supply a client whose
	// Transport has been hardened (#371).
	Client *http.Client
}

// NewUpstream resolves base and returns an Upstream that sends through
// client. A nil client gets one with no Timeout of its own: an
// http.Client.Timeout bounds the WHOLE request -- headers and body both --
// and the gateway's job is to relay a reply for as long as it takes to
// arrive, a long-lived stream included, so setting one here would cut a
// legitimate reply off partway through. A caller that wants an upper bound
// gets it from the incoming request's own context, which every forwarded
// request carries (see Proxy.buildRequest).
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
		client = &http.Client{}
	}
	return &Upstream{base: u, Client: client}, nil
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
