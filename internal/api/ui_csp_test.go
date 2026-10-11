// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FE-155 (#612): the dashboard sends a strict Content-Security-Policy, and
// the page it serves carries no script that policy would block.

// wantCSP is the policy, spelled out here rather than read from
// dashboardCSP, so a change to the constant is a change to this test too.
const wantCSP = "default-src 'self'; script-src 'self'; style-src 'self'; " +
	"img-src 'self'; font-src 'self'; connect-src 'self'; object-src 'none'; " +
	"base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

// Every path the router answers with index.html, and index.html itself,
// carries the policy exactly once.
func TestFE155EveryHTMLRouteSendsTheCSP(t *testing.T) {
	h := mustDashboardHandler(t, uiFixture(t))
	for _, path := range []string{
		"/", "/index.html", "/runs", "/runs/run-dd41951f/chain", "/account",
		"/setup?code=abc", "/alerts?kind=all", "/no/such/page",
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			rec := uiGet(t, h, method, path)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s %s: status %d, want 200", method, path, rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Fatalf("%s %s: Content-Type %q, want HTML", method, path, ct)
			}
			if got := rec.Header().Values("Content-Security-Policy"); len(got) != 1 || got[0] != wantCSP {
				t.Errorf("%s %s: Content-Security-Policy = %q, want exactly %q", method, path, got, wantCSP)
			}
		}
	}
}

// The policy has none of the escapes that would make it decorative.
func TestFE155PolicyHasNoUnsafeSources(t *testing.T) {
	for _, bad := range []string{"'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "*", "data:", "http:", "https:"} {
		for _, directive := range strings.Split(dashboardCSP, ";") {
			for _, source := range strings.Fields(directive)[1:] {
				if source == bad {
					t.Errorf("directive %q allows %s", strings.TrimSpace(directive), bad)
				}
			}
		}
	}
	for _, need := range []string{"object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "form-action 'self'", "connect-src 'self'"} {
		if !strings.Contains(dashboardCSP, need) {
			t.Errorf("policy lacks %q", need)
		}
	}
}

// The hardening headers sit beside the policy on the page and on the API.
func TestFE155HardeningHeadersBesideThePolicy(t *testing.T) {
	want := map[string]string{
		"Content-Security-Policy": wantCSP,
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"X-Frame-Options":         "DENY",
	}
	for _, tc := range []struct {
		name string
		h    http.Handler
		path string
	}{
		{"page", mustDashboardHandler(t, uiFixture(t)), "/account"},
		{"api through the UI", mustDashboardHandler(t, uiFixture(t)), "/api/v1/health"},
		{"api only", mustDashboardHandler(t, ""), "/api/v1/health"},
	} {
		rec := uiGet(t, tc.h, http.MethodGet, tc.path)
		for k, v := range want {
			if got := rec.Header().Values(k); len(got) != 1 || got[0] != v {
				t.Errorf("%s (%s): %s = %q, want exactly %q", tc.name, tc.path, k, got, v)
			}
		}
	}
}

// A built index.html with an inline script is refused at start: the policy
// would block that script in every browser, and a page that silently loses
// its theme bootstrap (or worse) is a failure better seen before serving.
func TestFE155RefusesAnIndexWithInlineScript(t *testing.T) {
	for name, page := range map[string]string{
		"inline":             "<!doctype html><head><script>alert(1)</script></head><div id=root></div>",
		"inline, upper":      "<!doctype html><HEAD><SCRIPT type=\"text/javascript\">x()</SCRIPT></HEAD>",
		"module inline":      "<html><script type=\"module\">import('/a.js')</script></html>",
		"after an external":  "<script src=\"/assets/a.js\"></script><script>\nx()\n</script>",
		"nonce is no excuse": "<script nonce=\"abc\">x()</script>",
		"event handler":      "<body onload=\"x()\"><div id=root></div></body>",
		"unterminated":       "<script>x()",
		"javascript url":     "<a href=\"javascript:x()\">x</a>",
	} {
		dir := uiFixture(t)
		if err := os.WriteFile(filepath.Join(dir, uiIndex), []byte(page), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := DashboardHandler(apiStub, dir)
		if err == nil || !strings.Contains(err.Error(), "inline") {
			t.Errorf("%s: err %v, want a refusal naming the inline script", name, err)
		}
	}
}

// What the build emits — external scripts only, comments that merely
// mention a script, empty-bodied external tags — is accepted.
func TestFE155AcceptsAnIndexWithExternalScriptsOnly(t *testing.T) {
	for name, page := range map[string]string{
		"external":         `<head><script src="/assets/theme-1a2b.js"></script><script type="module" crossorigin src="/assets/index-3f.js"></script></head>`,
		"whitespace":       "<script src=\"/a.js\">\n  </script>",
		"comment":          "<!-- a blocking <script>x()</script> once lived here --><div id=root></div>",
		"unquoted src":     "<script src=/a.js></script>",
		"no script at all": testIndexHTML,
		"word in text":     "<p>onload=nothing, javascript: none</p>",
	} {
		dir := uiFixture(t)
		if err := os.WriteFile(filepath.Join(dir, uiIndex), []byte(page), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := DashboardHandler(apiStub, dir); err != nil {
			t.Errorf("%s: %v, want accepted", name, err)
		}
	}
}
