// SPDX-License-Identifier: Apache-2.0

package client

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ENF-012 (PROPOSED for doc 07) — the machine reports its operator author to
// the core, and says plainly what the core answered (#545).
func TestENF012TheMachineReportsItsOperatorAuthor(t *testing.T) {
	var got OperatorAuthorReport
	answer := http.StatusOK
	body := `{"pinned":true}`
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != OperatorAuthorPath {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		w.WriteHeader(answer)
		if _, err := w.Write([]byte(body)); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(core.Close)

	const name, email = "Fixture Alpha", "12345+alpha@users.noreply.github.com"
	if _, err := reportOperatorAuthor(t.Context(), http.DefaultTransport, core.URL, name, email); err != nil {
		t.Fatalf("pinned: %v", err)
	}
	if got.Name != name || got.Email != email {
		t.Fatalf("the core received %+v", got)
	}

	answer, body = http.StatusConflict, `{"error":"innsegl core: already pinned. run on the core host: innsegl accounts author-reset x"}`
	_, err := reportOperatorAuthor(t.Context(), http.DefaultTransport, core.URL, name, email)
	if !errors.Is(err, ErrOperatorAuthorPinned) || !strings.Contains(err.Error(), "author-reset") {
		t.Fatalf("conflict: %v, want ErrOperatorAuthorPinned carrying the core's message", err)
	}

	answer, body = http.StatusBadRequest, `{"error":"innsegl core: operator author: not a noreply address"}`
	if _, err := reportOperatorAuthor(t.Context(), http.DefaultTransport, core.URL, name, email); err == nil ||
		!strings.Contains(err.Error(), "noreply") {
		t.Fatalf("bad request: %v, want the core's message", err)
	}
}

// ENF-014 (PROPOSED for doc 07) — the machine learns whether its report
// pinned the pair now or found it already pinned (#545). A core that answers
// 200 with no result (one older than this) counts as pinned.
func TestENF014TheReportSaysWhetherThePinIsNew(t *testing.T) {
	body := ""
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(body)); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(core.Close)
	const name, email = "alpha", "12345+alpha@users.noreply.github.com"
	for raw, want := range map[string]PinOutcome{
		`{"pinned":true,"result":"pinned"}`:         PinNew,
		`{"pinned":true,"result":"already-pinned"}`: PinHeld,
		`{"pinned":true}`:                           PinNew,
	} {
		body = raw
		got, err := reportOperatorAuthor(t.Context(), http.DefaultTransport, core.URL, name, email)
		if err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", raw, got, err, want)
		}
	}
}

// ENF-015 (PROPOSED for doc 07) — the machine reads the pin the core holds
// for it, over the same route (#545).
func TestENF015TheMachineReadsItsPinFromTheCore(t *testing.T) {
	answer, body := http.StatusOK, `{"pinned":true,"name":"alpha","email":"12345+alpha@users.noreply.github.com"}`
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != OperatorAuthorPath {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(answer)
		if _, err := w.Write([]byte(body)); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(core.Close)

	name, email, ok, err := readOperatorAuthor(t.Context(), http.DefaultTransport, core.URL)
	if err != nil || !ok || name != "alpha" || email != "12345+alpha@users.noreply.github.com" {
		t.Fatalf("pinned: %q %q %v %v", name, email, ok, err)
	}
	body = `{"pinned":false}`
	if _, _, ok, err := readOperatorAuthor(t.Context(), http.DefaultTransport, core.URL); err != nil || ok {
		t.Fatalf("none pinned: ok=%v err=%v", ok, err)
	}
	answer, body = http.StatusServiceUnavailable, `{"error":"innsegl core: operator author is unavailable; retry"}`
	if _, _, _, err := readOperatorAuthor(t.Context(), http.DefaultTransport, core.URL); err == nil ||
		!strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("unavailable: %v, want the core's message", err)
	}
}

// ENF-014 — the rule the core pins by, checked on the machine before
// asking: a GitHub noreply address, named by its own login.
func TestENF014CheckPinnable(t *testing.T) {
	if err := CheckPinnable("alpha", "12345+alpha@users.noreply.github.com"); err != nil {
		t.Fatalf("a noreply pair: %v", err)
	}
	for _, p := range [][2]string{
		{"Alpha Person", "12345+alpha@users.noreply.github.com"},
		{"alpha", "alpha@example.com"},
	} {
		if err := CheckPinnable(p[0], p[1]); err == nil {
			t.Errorf("%q <%s> is pinnable", p[0], p[1])
		}
	}
}
