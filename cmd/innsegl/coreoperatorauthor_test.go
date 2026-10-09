// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/gateway"
)

// fakeAuthorPins is the core route's store: installation → pinned pair, with
// accounts.Store's own first-use rule.
type fakeAuthorPins map[string][2]string

func (f fakeAuthorPins) PinOperatorAuthor(_ context.Context, id, name, email string) (bool, error) {
	if !accounts.IsNoreplyAddress(email) || name == "" {
		return false, accounts.ErrInvalid
	}
	if id == "revoked" {
		return false, accounts.ErrRevoked
	}
	if pair, ok := f[id]; ok {
		if pair == [2]string{name, email} {
			return false, nil
		}
		return false, accounts.ErrAuthorPinned
	}
	f[id] = [2]string{name, email}
	return true, nil
}

func (f fakeAuthorPins) OperatorAuthor(_ context.Context, id string) (string, string, bool, error) {
	if id == "broken" {
		return "", "", false, errors.New("store down")
	}
	pair, ok := f[id]
	return pair[0], pair[1], ok, nil
}

func postAuthor(t *testing.T, h http.Handler, installation string, body any) (int, string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, coreOperatorAuthorPath, bytes.NewReader(raw))
	if installation != "" {
		req = req.WithContext(gateway.WithInstallation(req.Context(), installation))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// GH-010 (PROPOSED for doc 07) — the core pins the operator author an
// enrolled machine reports, for that machine's installation only (#545).
func TestGH010TheCorePinsTheReportedOperatorAuthor(t *testing.T) {
	const (
		name  = "alpha"
		email = "12345+alpha@users.noreply.github.com"
	)
	pins := fakeAuthorPins{}
	h := operatorAuthorHandler(pins, newServeLog(io.Discard))

	if code, _ := postAuthor(t, h, "", operatorAuthorReport{Name: name, Email: email}); code != http.StatusUnauthorized {
		t.Fatalf("no installation: %d, want 401", code)
	}
	if code, body := postAuthor(t, h, "inst-a", operatorAuthorReport{Name: name, Email: email}); code != http.StatusOK {
		t.Fatalf("first report: %d %s", code, body)
	}
	if pins["inst-a"] != [2]string{name, email} {
		t.Fatalf("pinned %v", pins["inst-a"])
	}
	if code, body := postAuthor(t, h, "inst-a", operatorAuthorReport{Name: name, Email: email}); code != http.StatusOK {
		t.Fatalf("the same report again: %d %s", code, body)
	}
	code, body := postAuthor(t, h, "inst-a", operatorAuthorReport{Name: "beta", Email: "67890+beta@users.noreply.github.com"})
	if code != http.StatusConflict || !strings.Contains(body, "innsegl accounts author-reset inst-a") {
		t.Fatalf("a different report: %d %s, want 409 naming the reset", code, body)
	}
	if strings.Contains(body, name) || strings.Contains(body, "12345+alpha") {
		t.Fatalf("the refusal prints the pinned pair: %s", body)
	}
	if code, _ := postAuthor(t, h, "inst-b", operatorAuthorReport{Name: name, Email: "alpha@example.com"}); code != http.StatusBadRequest {
		t.Fatalf("a non-noreply address: %d, want 400", code)
	}
	if code, _ := postAuthor(t, h, "revoked", operatorAuthorReport{Name: name, Email: email}); code != http.StatusUnauthorized {
		t.Fatalf("a revoked installation: %d, want 401", code)
	}
	req := httptest.NewRequestWithContext(gateway.WithInstallation(t.Context(), "inst-a"), http.MethodPut, coreOperatorAuthorPath, http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT: %d, want 405", rec.Code)
	}
}

// GH-010, end to end: an enrolled machine reports over its own certificate,
// the hosted core pins it in the accounts store, and a different report is
// refused.
func TestGH010AnEnrolledMachinePinsItsOperatorAuthorOnTheHostedCore(t *testing.T) {
	f := newEnFixture(t)
	g := startHostedGateway(t, f)
	c := newEnClient(t)
	_, cert := enrol(t, f, g, c)

	post := func(client *http.Client, r operatorAuthorReport) int {
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+g.addr+coreOperatorAuthorPath, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	alpha := operatorAuthorReport{Name: "alpha", Email: "12345+alpha@users.noreply.github.com"}
	if code := post(g.client(t, nil), alpha); code != http.StatusUnauthorized {
		t.Fatalf("without a certificate: %d, want 401", code)
	}
	if code := post(g.client(t, cert), alpha); code != http.StatusOK {
		t.Fatalf("first report: %d, want 200", code)
	}
	if code := post(g.client(t, cert), operatorAuthorReport{Name: "beta", Email: "67890+beta@users.noreply.github.com"}); code != http.StatusConflict {
		t.Fatalf("a different report: %d, want 409", code)
	}

	// GH-011: over the same certificate the machine reads its own pin.
	get := func(client *http.Client) (int, string) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+g.addr+coreOperatorAuthorPath, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(raw)
	}
	if code, _ := get(g.client(t, nil)); code != http.StatusUnauthorized {
		t.Fatalf("GET without a certificate: %d, want 401", code)
	}
	if code, body := get(g.client(t, cert)); code != http.StatusOK || !strings.Contains(body, alpha.Email) {
		t.Fatalf("GET over the certificate: %d %s, want the pinned pair", code, body)
	}
}

func getAuthor(t *testing.T, h http.Handler, installation string) (int, string) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, coreOperatorAuthorPath, http.NoBody)
	if installation != "" {
		req = req.WithContext(gateway.WithInstallation(req.Context(), installation))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// GH-011 (PROPOSED for doc 07) — the route says whether a report pinned the
// pair now or found it already pinned, and GET answers the calling
// installation's own pin and nothing else (#545).
func TestGH011TheRouteSaysWhatItPinnedAndAnswersThisMachinesPin(t *testing.T) {
	const (
		name  = "alpha"
		email = "12345+alpha@users.noreply.github.com"
	)
	pins := fakeAuthorPins{}
	h := operatorAuthorHandler(pins, newServeLog(io.Discard))

	if code, body := getAuthor(t, h, "inst-a"); code != http.StatusOK || !strings.Contains(body, `"pinned":false`) {
		t.Fatalf("GET before any pin: %d %s, want 200 pinned:false", code, body)
	}
	if code, body := postAuthor(t, h, "inst-a", operatorAuthorReport{Name: name, Email: email}); code != http.StatusOK ||
		!strings.Contains(body, `"result":"pinned"`) {
		t.Fatalf("first report: %d %s, want result pinned", code, body)
	}
	if code, body := postAuthor(t, h, "inst-a", operatorAuthorReport{Name: name, Email: email}); code != http.StatusOK ||
		!strings.Contains(body, `"result":"already-pinned"`) {
		t.Fatalf("the same report again: %d %s, want result already-pinned", code, body)
	}
	code, body := getAuthor(t, h, "inst-a")
	var got struct {
		Pinned bool   `json:"pinned"`
		Name   string `json:"name"`
		Email  string `json:"email"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil || code != http.StatusOK ||
		!got.Pinned || got.Name != name || got.Email != email {
		t.Fatalf("GET after the pin: %d %s", code, body)
	}
	// Another installation never sees inst-a's pair.
	if code, other := getAuthor(t, h, "inst-b"); code != http.StatusOK || strings.Contains(other, email) ||
		!strings.Contains(other, `"pinned":false`) {
		t.Fatalf("GET from another installation: %d %s", code, other)
	}
	if code, _ := getAuthor(t, h, ""); code != http.StatusUnauthorized {
		t.Fatalf("GET with no installation: %d, want 401", code)
	}
	if code, _ := getAuthor(t, h, "broken"); code != http.StatusServiceUnavailable {
		t.Fatalf("GET when the store cannot answer: %d, want 503", code)
	}
	// The refusal names the reset as it is run on a compose core.
	_, body = postAuthor(t, h, "inst-a", operatorAuthorReport{Name: "beta", Email: "67890+beta@users.noreply.github.com"})
	if !strings.Contains(body, "docker exec innsegl-api innsegl accounts author-reset inst-a") {
		t.Fatalf("the refusal does not name the reset command: %s", body)
	}
}
