// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"testing"
)

func TestNewUpstreamRefusesAnEmptyBaseURL(t *testing.T) {
	if _, err := NewUpstream("", nil); err == nil {
		t.Fatal("NewUpstream(\"\", nil) succeeded, want a refusal")
	}
	if _, err := NewUpstream("   ", nil); err == nil {
		t.Fatal("NewUpstream(whitespace, nil) succeeded, want a refusal")
	}
}

func TestNewUpstreamRefusesAURLWithNoSchemeOrHost(t *testing.T) {
	for _, bad := range []string{"api.anthropic.com", "/just/a/path", "://broken"} {
		if _, err := NewUpstream(bad, nil); err == nil {
			t.Errorf("NewUpstream(%q, nil) succeeded, want a refusal: an upstream base URL "+
				"needs a scheme and a host to be reachable at all", bad)
		}
	}
}

func TestNewUpstreamDefaultsToAClientWithNoTimeout(t *testing.T) {
	up, err := NewUpstream("https://api.anthropic.com", nil)
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	if up.Client == nil {
		t.Fatal("Client is nil; a nil client passed in must still leave a usable one")
	}
	if up.Client.Timeout != 0 {
		t.Errorf("Client.Timeout = %v, want 0: a streamed reply must not be cut off by a "+
			"whole-request timeout (see NewUpstream's own doc comment)", up.Client.Timeout)
	}
}

func TestNewUpstreamKeepsAnExplicitClient(t *testing.T) {
	custom := &http.Client{}
	up, err := NewUpstream("https://api.anthropic.com", custom)
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	if up.Client != custom {
		t.Error("NewUpstream replaced the given client instead of keeping it")
	}
}

func TestUpstreamResolveJoinsBaseAndRequestPaths(t *testing.T) {
	for _, tc := range []struct {
		name, base, path, query, want string
	}{
		{"no base path", "https://api.anthropic.com", "/v1/messages", "beta=1", "/v1/messages"},
		{"base path, no trailing slash", "https://example.com/api", "/v1/messages", "", "/api/v1/messages"},
		{"base path with trailing slash", "https://example.com/api/", "/v1/messages", "", "/api/v1/messages"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up, err := NewUpstream(tc.base, nil)
			if err != nil {
				t.Fatalf("NewUpstream: %v", err)
			}
			got := up.resolve(tc.path, tc.query)
			if got.Path != tc.want {
				t.Errorf("resolve(%q, %q).Path = %q, want %q", tc.path, tc.query, got.Path, tc.want)
			}
			if got.RawQuery != tc.query {
				t.Errorf("resolve(%q, %q).RawQuery = %q, want %q", tc.path, tc.query, got.RawQuery, tc.query)
			}
		})
	}
}

func TestSingleJoiningSlash(t *testing.T) {
	for _, tc := range []struct{ a, b, want string }{
		{"", "/v1/messages", "/v1/messages"}, // a empty, b slashed
		{"/api", "/v1", "/api/v1"},           // a not slashed, b slashed
		{"/api/", "/v1", "/api/v1"},          // both slashed
		{"/api", "v1", "/api/v1"},            // neither slashed, a non-empty
		{"/api/", "v1", "/api/v1"},           // a slashed, b not
	} {
		if got := singleJoiningSlash(tc.a, tc.b); got != tc.want {
			t.Errorf("singleJoiningSlash(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestUpstreamBaseReturnsACopy(t *testing.T) {
	up, err := NewUpstream("https://api.anthropic.com/v1", nil)
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	got := up.Base()
	got.Path = "/mutated"
	if up.base.Path == "/mutated" {
		t.Error("Base() returned an alias of the internal URL; a caller's mutation must not reach it")
	}
}
