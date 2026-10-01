// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/client/clienttest"
)

// The client chooses its installation id and names it in the CSR's one URI
// SAN; the core's identity authority mints from that SAN (#460).

func newCore(t *testing.T) *clienttest.Core {
	t.Helper()
	core, err := clienttest.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(core.Close)
	return core
}

func TestCLI015EnrolAsksTheTrustDomainFirstAndNamesItsIDInTheCSR(t *testing.T) {
	core := newCore(t)
	e, err := Enrol(context.Background(), EnrolOptions{CoreURL: core.URL(), Token: clienttest.Token, Name: "n", CA: core.CA})
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	if got := core.Calls(); len(got) < 2 || got[0] != "GET /_core/enrol" || got[1] != "POST /_core/enrol" {
		t.Fatalf("calls = %v, want the trust domain asked for before the enrolment", got)
	}
	if !idShape.MatchString(e.InstallationID) || e.InstallationID != core.EnrolledID() {
		t.Fatalf("id = %q, the core recorded %q", e.InstallationID, core.EnrolledID())
	}
	csr := core.LastCSR()
	want := "spiffe://" + clienttest.TrustDomain + "/client/" + e.InstallationID
	if len(csr.URIs) != 1 || csr.URIs[0].String() != want ||
		len(csr.DNSNames)+len(csr.IPAddresses)+len(csr.EmailAddresses) != 0 {
		t.Fatalf("CSR SANs: uris=%v dns=%v ip=%v email=%v, want exactly [%s]",
			csr.URIs, csr.DNSNames, csr.IPAddresses, csr.EmailAddresses, want)
	}
}

func TestCLI015EnrolRetriesOnceWithANewIDWhenTheIDIsTaken(t *testing.T) {
	core := newCore(t)
	core.SetIDTaken(1)
	e, err := Enrol(context.Background(), EnrolOptions{CoreURL: core.URL(), Token: clienttest.Token, Name: "n", CA: core.CA})
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	if n, _ := core.Counts(); n != 2 {
		t.Fatalf("enrol calls = %d, want 2", n)
	}
	ids := core.RequestedIDs()
	if len(ids) != 2 || ids[0] == ids[1] || ids[1] != e.InstallationID {
		t.Fatalf("requested ids = %v; the retry must use a new id, and that id is the enrolment's", ids)
	}

	twice := newCore(t)
	twice.SetIDTaken(2)
	if _, err := Enrol(context.Background(), EnrolOptions{CoreURL: twice.URL(), Token: clienttest.Token, Name: "n", CA: twice.CA}); err == nil {
		t.Fatal("a second collision was accepted")
	}
	if n, _ := twice.Counts(); n != 2 {
		t.Fatalf("enrol calls = %d, want 2: one retry only", n)
	}
}

func TestCLI015EnrolRefusesAnIDTheCoreDidNotEcho(t *testing.T) {
	core := newCore(t)
	core.SetEchoWrongID(true)
	_, err := Enrol(context.Background(), EnrolOptions{CoreURL: core.URL(), Token: clienttest.Token, Name: "n", CA: core.CA})
	if err == nil {
		t.Fatal("an enrolment answered with another installation id was accepted")
	}
}

func TestCLI015EnrolReportsAMintFailureAsRetryable(t *testing.T) {
	core := newCore(t)
	core.SetUnavailable(true)
	_, err := Enrol(context.Background(), EnrolOptions{CoreURL: core.URL(), Token: clienttest.Token, Name: "n", CA: core.CA})
	if !errors.Is(err, ErrCoreUnavailable) {
		t.Fatalf("err = %v, want ErrCoreUnavailable", err)
	}
}

func TestCLI016RenewCSRKeepsTheSameSAN(t *testing.T) {
	core, paths := enrolled(t)
	srv, _, _ := startClient(t, paths)
	leaf := srv.Leaf()
	srv.Now = func() time.Time { return leaf.NotBefore.Add(13 * time.Hour) }
	if renewed, err := srv.MaybeRenew(context.Background()); err != nil || !renewed {
		t.Fatalf("renew: %v %v", renewed, err)
	}
	csr := core.LastCSR()
	if len(csr.URIs) != 1 || csr.URIs[0].String() != leaf.URIs[0].String() || len(csr.DNSNames) != 0 {
		t.Fatalf("renew CSR URIs = %v, want [%s]", csr.URIs, leaf.URIs[0])
	}
	if srv.Leaf().URIs[0].String() != leaf.URIs[0].String() {
		t.Fatal("the renewed certificate names another installation")
	}
}

// A 401, 429 or 503 on a proxied route is the core's answer to that one
// request and reaches the harness as it was sent; only a renewal's 401
// means the installation is revoked.
func TestCLI016CoreRefusalsPassThroughUnchanged(t *testing.T) {
	core, paths := enrolled(t)
	core.Mux.HandleFunc("/v1/busy", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "7")
		http.Error(w, "busy", http.StatusServiceUnavailable)
	})
	core.Mux.HandleFunc("/v1/slow", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "slow down", http.StatusTooManyRequests)
	})
	core.Mux.HandleFunc("/v1/refused", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"innsegl core: request refused"}`)
	})
	srv, front, _ := startClient(t, paths)
	for path, want := range map[string]int{"/v1/busy": 503, "/v1/slow": 429, "/v1/refused": 401} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, front.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body := readAll(t, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s = %d, want %d", path, resp.StatusCode, want)
		}
		if path == "/v1/busy" && resp.Header.Get("Retry-After") != "7" {
			t.Errorf("Retry-After = %q", resp.Header.Get("Retry-After"))
		}
		if path == "/v1/refused" && string(body) != `{"error":"innsegl core: request refused"}` {
			t.Errorf("body = %q", body)
		}
	}
	if _, err := srv.MaybeRenew(context.Background()); errors.Is(err, ErrRevoked) {
		t.Fatal("a proxied 401 marked the installation revoked")
	}
}
