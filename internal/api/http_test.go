// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/verify"
)

// TC-API — the HTTP surface.
//
// FD P6: "Read-only means read-only. No mutating action exists anywhere in the
// UI." The UI is not where that is enforced. A read-only API whose transport
// accepts a POST is one handler away from having one, so the refusal is at the
// front door and applies to every path, including paths that do not exist.

func testServer(t *testing.T) (*httptest.Server, *proofScenario) {
	t.Helper()
	owner, _, readerDSN := migrated(t)
	seed(t, owner, 3)
	store, _ := readStore(t, readerDSN)

	s := newProofScenario(t, proofOptions{})
	srv, err := NewServer(ServerConfig{Store: store, Prover: s.prover(t)})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	listening := httptest.NewServer(srv)
	t.Cleanup(listening.Close)
	return listening, s
}

// answer is one HTTP response, already read and closed. The body is read here
// rather than handed back open so that no case can leak a connection.
type answer struct {
	status int
	header http.Header
	body   []byte
}

func do(t *testing.T, method, target, payload string) answer {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	var reader io.Reader
	if payload != "" {
		reader = strings.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		t.Fatalf("building %s %s: %v", method, target, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("closing the body of %s %s: %v", method, target, cerr)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the body of %s %s: %v", method, target, err)
	}
	return answer{status: resp.StatusCode, header: resp.Header, body: body}
}

func get(t *testing.T, base, path string) answer {
	t.Helper()
	return do(t, http.MethodGet, base+path, "")
}

func decodeBody(t *testing.T, a answer, into any) {
	t.Helper()
	if err := json.Unmarshal(a.body, into); err != nil {
		t.Fatalf("the response is not JSON: %v: %s", err, a.body)
	}
}

// API-007 — every mutating method is refused, on every path.
func TestAPI007EveryMutatingMethodIsRefusedOnEveryPath(t *testing.T) {
	srv, _ := testServer(t)

	paths := []string{"/api/v1/runs", "/api/v1/runs/run-000", "/api/v1/overview",
		"/api/v1/proof/deadbeef", "/api/v1/health", "/", "/nothing/here"}
	methods := []string{http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, "PROPFIND"}

	for _, path := range paths {
		for _, method := range methods {
			a := do(t, method, srv.URL+path, `{"anything":true}`)
			if a.status != http.StatusMethodNotAllowed {
				t.Errorf("%s %s returned %d, want 405: FD P6 makes this API read-only "+
					"at the transport, not by the absence of a handler. body: %s",
					method, path, a.status, a.body)
			}
			if allow := a.header.Get("Allow"); !strings.Contains(allow, http.MethodGet) {
				t.Errorf("%s %s refused with Allow: %q; a refusal that does not say "+
					"what IS allowed is not actionable", method, path, allow)
			}
		}
	}
}

// The read surface: every view answers, in JSON, uncacheable.
func TestTheReadRoutesAnswerInJSONAndAreNeverCached(t *testing.T) {
	srv, scenario := testServer(t)

	t.Run("runs", func(t *testing.T) {
		a := get(t, srv.URL, "/api/v1/runs?limit=2")
		if a.status != http.StatusOK {
			t.Fatalf("GET /api/v1/runs: %d", a.status)
		}
		if ct := a.header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("Content-Type %q", ct)
		}
		// FD anti-pattern 1 is "a verified state rendered from cache while the
		// live check errored". Nothing this API serves is cacheable.
		if cc := a.header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
			t.Errorf("Cache-Control %q; a cached proof surface is FD anti-pattern 1 "+
				"waiting to happen", cc)
		}
		var page RunPage
		decodeBody(t, a, &page)
		if len(page.Runs) != 2 || page.Limit != 2 {
			t.Fatalf("limit=2 produced %d runs with Limit=%d", len(page.Runs), page.Limit)
		}
		if page.NextCursor == "" {
			t.Error("three runs were seeded and a page of two carries no next cursor")
		}
		if page.DataAsOf.IsZero() {
			t.Error("the page carries no data-as-of marker (FD §4.4)")
		}
	})

	t.Run("filters ride in the URL", func(t *testing.T) {
		// FD §7: "every view's state (filters, selected run, verification
		// input) lives in the URL".
		a := get(t, srv.URL, "/api/v1/runs?agent_type=release-bot&limit=50")
		var page RunPage
		decodeBody(t, a, &page)
		for _, r := range page.Runs {
			if r.AgentType != "release-bot" {
				t.Errorf("agent_type=release-bot returned a %s run", r.AgentType)
			}
		}
		if len(page.Runs) == 0 {
			t.Error("the filter matched nothing; the case would pass vacuously")
		}
	})

	t.Run("a malformed query is a bad request, not an empty page", func(t *testing.T) {
		for _, q := range []string{"?status=retiredish", "?cursor=not-a-cursor", "?limit=zero"} {
			a := get(t, srv.URL, "/api/v1/runs"+q)
			if a.status != http.StatusBadRequest {
				t.Errorf("GET /api/v1/runs%s returned %d, want 400", q, a.status)
			}
		}
	})

	t.Run("run detail", func(t *testing.T) {
		a := get(t, srv.URL, "/api/v1/runs/run-000")
		if a.status != http.StatusOK {
			t.Fatalf("GET /api/v1/runs/run-000: %d", a.status)
		}
		var detail RunDetail
		decodeBody(t, a, &detail)
		if detail.RunID != "run-000" || len(detail.Timeline) == 0 {
			t.Fatalf("run detail: %+v", detail)
		}
	})

	t.Run("an unknown run is 404", func(t *testing.T) {
		a := get(t, srv.URL, "/api/v1/runs/run-nope")
		if a.status != http.StatusNotFound {
			t.Fatalf("GET an unknown run returned %d, want 404", a.status)
		}
		var e errorEnvelope
		decodeBody(t, a, &e)
		if e.Error.Message == "" {
			t.Error("a 404 with no message; FD §4.6 wants an explicit error state")
		}
	})

	t.Run("overview", func(t *testing.T) {
		a := get(t, srv.URL, "/api/v1/overview")
		if a.status != http.StatusOK {
			t.Fatalf("GET /api/v1/overview: %d", a.status)
		}
		var o Overview
		decodeBody(t, a, &o)
		if o.DataAsOf.IsZero() {
			t.Error("the overview carries no data-as-of marker")
		}
	})

	t.Run("health reports the read-only evidence", func(t *testing.T) {
		a := get(t, srv.URL, "/api/v1/health")
		if a.status != http.StatusOK {
			t.Fatalf("GET /api/v1/health: %d", a.status)
		}
		var h Health
		decodeBody(t, a, &h)
		if len(h.Database.Probes) == 0 {
			t.Fatal("health carries no write probes; \"read-only\" is a measured fact " +
				"or it is a claim in a README")
		}
		if h.Database.Writable() {
			t.Error("health reports a writable credential on a store that opened")
		}
	})

	t.Run("proof", func(t *testing.T) {
		a := get(t, srv.URL, "/api/v1/proof/"+scenario.commit+
			"?repo="+url.QueryEscape(fixtureRepo))
		if a.status != http.StatusOK {
			t.Fatalf("GET the proof: %d: %s", a.status, a.body)
		}
		var p Proof
		decodeBody(t, a, &p)
		if p.Verdict != string(verify.VerdictVerified) {
			t.Fatalf("verdict %q over the wire: %+v", p.Verdict, p.Checks)
		}
		// The material survives the JSON round trip, which is the only form in
		// which a client ever sees it.
		if bad := Contradictions(Rederive(p)); len(bad) != 0 {
			t.Fatalf("the proof as served over HTTP convicts itself: %+v", bad)
		}
		if p.Material.CommitObject == "" || p.Material.CertificatePEM == "" {
			t.Error("the served proof lost its material in transit")
		}
	})

	t.Run("a commit no served repository holds is 404", func(t *testing.T) {
		a := get(t, srv.URL, "/api/v1/proof/"+strings.Repeat("a", 40))
		if a.status != http.StatusNotFound {
			t.Fatalf("GET a proof for an unknown commit returned %d, want 404", a.status)
		}
	})
}
