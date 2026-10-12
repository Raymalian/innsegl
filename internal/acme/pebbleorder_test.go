// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/certcrypto"
)

// The ACME test server must keep answering reads of an order while the order
// is written to. lego reads the order right after finalizing it, while the
// server finalizes it in the background; Pebble releases up to 2.10.1 take
// the order's read lock twice in one read, so a write that queues in between
// (finalization, or the status update every read makes) hangs the order for
// good. That was TLS-004 and TLS-005 timing out on busy runners. Reading one
// order from many goroutines at once while it is finalized makes the
// collision near certain on such a server, and harmless on a fixed one.
func TestTheACMETestServerAnswersOrderReadsWhileFinalizing(t *testing.T) {
	p := startPebble(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := *p.client
	client.Timeout = 15 * time.Second
	core, err := api.New(&client, "innsegl-test", p.directory, "", key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = core.Accounts.New(legoacme.Account{TermsOfServiceAgreed: true,
		Contact: []string{"mailto:operator@innsegl.test"}}); err != nil {
		t.Fatal(err)
	}
	dns := &fakeDNS{api: p.dnsAPI, client: p.client}

	const rounds, readers = 12, 16
	for round := range rounds {
		order, oerr := core.Orders.New([]string{testName})
		if oerr != nil {
			t.Fatal(oerr)
		}
		for _, authzURL := range order.Authorizations {
			authorize(t, core, dns, authzURL)
		}
		ready, rerr := core.Orders.Get(order.Location)
		if rerr != nil || ready.Status != legoacme.StatusReady {
			t.Fatalf("round %d: the order is %q before finalizing: %v", round, ready.Status, rerr)
		}
		certKey, kerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if kerr != nil {
			t.Fatal(kerr)
		}
		csr, cerr := certcrypto.CreateCSR(certKey, certcrypto.CSROptions{Domain: testName, SAN: []string{testName}})
		if cerr != nil {
			t.Fatal(cerr)
		}

		var wg sync.WaitGroup
		errs := make(chan error, readers+1)
		start := make(chan struct{})
		for range readers {
			wg.Go(func() {
				<-start
				for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); {
					got, gerr := core.Orders.Get(order.Location)
					if gerr != nil {
						errs <- fmt.Errorf("read the order: %w", gerr)
						return
					}
					if got.Status == legoacme.StatusValid {
						return
					}
				}
				errs <- fmt.Errorf("the order did not become valid")
			})
		}
		close(start)
		if _, ferr := core.Orders.UpdateForCSR(order.Finalize, csr); ferr != nil {
			errs <- fmt.Errorf("finalize: %w", ferr)
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			t.Errorf("round %d: %v", round, e)
		}
		if t.Failed() {
			t.FailNow()
		}
	}
}

// authorize answers one authorization through DNS-01 and waits for it.
func authorize(t *testing.T, core *api.Core, dns *fakeDNS, authzURL string) {
	t.Helper()
	authz, err := core.Authorizations.Get(authzURL)
	if err != nil {
		t.Fatal(err)
	}
	if authz.Status == legoacme.StatusValid {
		return
	}
	var chal *legoacme.Challenge
	for i := range authz.Challenges {
		if authz.Challenges[i].Type == "dns-01" {
			chal = &authz.Challenges[i]
		}
	}
	if chal == nil {
		t.Fatalf("no dns-01 challenge in %+v", authz)
	}
	keyAuth, err := core.GetKeyAuthorization(chal.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err = dns.Present(testName, chal.Token, keyAuth); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := dns.CleanUp(testName, chal.Token, keyAuth); cerr != nil {
			t.Fatal(cerr)
		}
	}()
	if _, err = core.Challenges.New(chal.URL); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(60 * time.Second); ; {
		if authz, err = core.Authorizations.Get(authzURL); err != nil {
			t.Fatal(err)
		}
		if authz.Status == legoacme.StatusValid {
			return
		}
		if authz.Status != legoacme.StatusPending || time.Now().After(deadline) {
			for _, c := range authz.Challenges {
				t.Logf("%s challenge: %s %v", c.Type, c.Status, c.Err())
			}
			t.Fatalf("the authorization is %q", authz.Status)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
