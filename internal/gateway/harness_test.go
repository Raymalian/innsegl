// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// harnessFixture is one recorded request shape under testdata/harness --
// path and headers only, per GW-012.
type harnessFixture struct {
	Description string            `json:"description"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers"`
}

// loadHarnessFixture reads testdata/harness/<dir>/<name>.
func loadHarnessFixture(t *testing.T, dir, name string) harnessFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "harness", dir, name))
	if err != nil {
		t.Fatalf("read fixture %s/%s: %v", dir, name, err)
	}
	var fx harnessFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture %s/%s: %v", dir, name, err)
	}
	return fx
}

// request builds an *http.Request suitable for calling a recogniser
// directly -- no real network involved.
func (fx harnessFixture) request(t *testing.T) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), fx.Method, fx.Path, nil)
	for k, v := range fx.Headers {
		req.Header.Set(k, v)
	}
	return req
}

// networkRequest builds an *http.Request against a real listener at
// baseURL, for a contract test that drives the fixture all the way through
// Proxy.ServeHTTP.
func (fx harnessFixture) networkRequest(t *testing.T, baseURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), fx.Method, baseURL+fx.Path, nil)
	if err != nil {
		t.Fatalf("build request for fixture: %v", err)
	}
	for k, v := range fx.Headers {
		req.Header.Set(k, v)
	}
	return req
}

// --- GW-012: recorded request shapes of each supported harness version are
// recognised. ---

func TestRecogniseClaudeCode21MainAgentFixture(t *testing.T) {
	fx := loadHarnessFixture(t, "claude-code-2.1", "main-agent.json")
	id, ok, reason := recogniseClaudeCode21(fx.request(t))
	if !ok {
		t.Fatalf("main-agent fixture not recognised: %s", reason)
	}
	if id.Harness != "claude-code" || id.Version != "2.1" {
		t.Errorf("Harness/Version = %q/%q, want claude-code/2.1", id.Harness, id.Version)
	}
	if id.AgentID != mainAgentID {
		t.Errorf("AgentID = %q, want %q -- a main-agent request carries no agent header", id.AgentID, mainAgentID)
	}
	if id.SessionID != fx.Headers[headerClaudeCodeSessionID] {
		t.Errorf("SessionID = %q, want the fixture's own %q", id.SessionID, fx.Headers[headerClaudeCodeSessionID])
	}
}

func TestRecogniseClaudeCode21SubagentFixture(t *testing.T) {
	fx := loadHarnessFixture(t, "claude-code-2.1", "subagent.json")
	id, ok, reason := recogniseClaudeCode21(fx.request(t))
	if !ok {
		t.Fatalf("subagent fixture not recognised: %s", reason)
	}
	if id.AgentID != fx.Headers[headerClaudeCodeAgentID] {
		t.Errorf("AgentID = %q, want the fixture's own %q", id.AgentID, fx.Headers[headerClaudeCodeAgentID])
	}
	if id.AgentID == mainAgentID {
		t.Error("a subagent's own id must not collapse to \"main\"")
	}
	if id.SessionID != fx.Headers[headerClaudeCodeSessionID] {
		t.Errorf("SessionID = %q, want the fixture's own %q", id.SessionID, fx.Headers[headerClaudeCodeSessionID])
	}
}

func TestRecogniseClaudeCode21CountTokensFixture(t *testing.T) {
	fx := loadHarnessFixture(t, "claude-code-2.1", "count-tokens.json")
	id, ok, reason := recogniseClaudeCode21(fx.request(t))
	if !ok {
		t.Fatalf("count_tokens fixture not recognised: %s", reason)
	}
	if id.AgentID != mainAgentID {
		t.Errorf("AgentID = %q, want %q", id.AgentID, mainAgentID)
	}
}

// TestGW012EveryFixtureUnderTestdataIsRecognised walks every recorded shape
// under testdata/harness and checks it against every registered recogniser,
// so a new fixture added without a matching recogniser -- or a recogniser
// change that stops matching an old, still-committed fixture -- fails here
// rather than going unnoticed.
func TestGW012EveryFixtureUnderTestdataIsRecognised(t *testing.T) {
	root := filepath.Join("testdata", "harness")
	versionDirs, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}

	found := 0
	for _, vd := range versionDirs {
		if !vd.IsDir() {
			continue
		}
		entries, err := os.ReadDir(filepath.Join(root, vd.Name()))
		if err != nil {
			t.Fatalf("read %s/%s: %v", root, vd.Name(), err)
		}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
				continue
			}
			fx := loadHarnessFixture(t, vd.Name(), e.Name())
			req := fx.request(t)

			recognised := false
			var lastReason string
			for _, recognise := range registeredRecognisers {
				_, ok, reason := recognise(req)
				if ok {
					recognised = true
					break
				}
				lastReason = reason
			}
			if !recognised {
				t.Errorf("%s/%s not recognised by any registered recogniser: %s", vd.Name(), e.Name(), lastReason)
			}
			found++
		}
	}
	if found == 0 {
		t.Fatal("no fixtures found under testdata/harness -- GW-012 has nothing pinned")
	}
}

// --- Unit coverage of recogniseClaudeCode21's own refusal reasons
// (GW-011's building block). The end-to-end refusal through Proxy.ServeHTTP
// -- status, body, and that nothing reaches the upstream -- is guard_test.go. ---

const validSessionID = "7734c172-6ff1-4112-8a0e-f09fa6b6a480"

func TestRecogniseClaudeCode21RefusesAnUnknownPath(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/not-a-model-path", nil)
	req.Header.Set(headerClaudeCodeSessionID, validSessionID)

	_, ok, reason := recogniseClaudeCode21(req)
	if ok {
		t.Fatal("recognised a path this harness version does not use")
	}
	if reason != reasonUnknownPath {
		t.Errorf("reason = %q, want %q", reason, reasonUnknownPath)
	}
}

func TestRecogniseClaudeCode21RefusesAMissingSessionHeader(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/messages", nil)

	_, ok, reason := recogniseClaudeCode21(req)
	if ok {
		t.Fatal("recognised a request with no session header")
	}
	if reason != reasonMissingSessionID {
		t.Errorf("reason = %q, want %q", reason, reasonMissingSessionID)
	}
}

func TestRecogniseClaudeCode21RefusesAMalformedSessionID(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/messages", nil)
	req.Header.Set(headerClaudeCodeSessionID, "not-a-uuid")

	_, ok, reason := recogniseClaudeCode21(req)
	if ok {
		t.Fatal("recognised a malformed session id")
	}
	if reason != reasonMalformedSessionID {
		t.Errorf("reason = %q, want %q", reason, reasonMalformedSessionID)
	}
}

func TestRecogniseClaudeCode21RefusesAMalformedAgentID(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/messages", nil)
	req.Header.Set(headerClaudeCodeSessionID, validSessionID)
	req.Header.Set(headerClaudeCodeAgentID, "not-a-uuid-either")

	_, ok, reason := recogniseClaudeCode21(req)
	if ok {
		t.Fatal("recognised a malformed agent id")
	}
	if reason != reasonMalformedAgentID {
		t.Errorf("reason = %q, want %q", reason, reasonMalformedAgentID)
	}
}

func TestRecogniseClaudeCode21AcceptsCountTokensPathTooWithoutAnAgentHeader(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/messages/count_tokens", nil)
	req.Header.Set(headerClaudeCodeSessionID, validSessionID)

	_, ok, reason := recogniseClaudeCode21(req)
	if !ok {
		t.Fatalf("count_tokens with a valid session id was refused: %s", reason)
	}
}

func TestIsUUID(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"valid lowercase", "7734c172-6ff1-4112-8a0e-f09fa6b6a480", true},
		{"valid uppercase", "7734C172-6FF1-4112-8A0E-F09FA6B6A480", true},
		{"no hyphens", "7734c1726ff141128a0ef09fa6b6a480", false},
		{"one character short", "7734c172-6ff1-4112-8a0e-f09fa6b6a48", false},
		{"one character long", "7734c172-6ff1-4112-8a0e-f09fa6b6a4800", false},
		// Same length as a valid UUID (36), so this exercises the hyphen
		// check itself rather than the length guard above it: position 8
		// holds 'a' where a hyphen belongs, every other character
		// otherwise unchanged from the valid case.
		{"hyphen position holds a hex digit instead", "7734c172a6ff1-4112-8a0e-f09fa6b6a480", false},
		{"non-hex character", "7734c172-6ff1-4112-8a0e-f09fa6b6a4zz", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isUUID(c.in); got != c.want {
				t.Errorf("isUUID(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestIdentificationContextRoundTrip(t *testing.T) {
	want := Identification{Harness: "claude-code", Version: "2.1", SessionID: "s", AgentID: mainAgentID}
	ctx := WithIdentification(context.Background(), want)

	got, ok := IdentificationFromContext(ctx)
	if !ok {
		t.Fatal("IdentificationFromContext found nothing on a context WithIdentification built")
	}
	if got != want {
		t.Errorf("IdentificationFromContext = %+v, want %+v", got, want)
	}
}

func TestIdentificationFromContextAbsentWhenNeverAttached(t *testing.T) {
	_, ok := IdentificationFromContext(context.Background())
	if ok {
		t.Fatal("found an Identification on a context that never carried one")
	}
}
