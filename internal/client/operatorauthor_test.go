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
	if err := reportOperatorAuthor(t.Context(), http.DefaultTransport, core.URL, name, email); err != nil {
		t.Fatalf("pinned: %v", err)
	}
	if got.Name != name || got.Email != email {
		t.Fatalf("the core received %+v", got)
	}

	answer, body = http.StatusConflict, `{"error":"innsegl core: already pinned. run on the core host: innsegl accounts author-reset x"}`
	err := reportOperatorAuthor(t.Context(), http.DefaultTransport, core.URL, name, email)
	if !errors.Is(err, ErrOperatorAuthorPinned) || !strings.Contains(err.Error(), "author-reset") {
		t.Fatalf("conflict: %v, want ErrOperatorAuthorPinned carrying the core's message", err)
	}

	answer, body = http.StatusBadRequest, `{"error":"innsegl core: operator author: not a noreply address"}`
	if err := reportOperatorAuthor(t.Context(), http.DefaultTransport, core.URL, name, email); err == nil ||
		!strings.Contains(err.Error(), "noreply") {
		t.Fatalf("bad request: %v, want the core's message", err)
	}
}
