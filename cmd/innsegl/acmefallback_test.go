// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"
)

// TLS-011: a public certificate that cannot be obtained never keeps the core
// down. Measured in the dev-stack rehearsal: the first order's DNS check
// timed out, the core exited at start and restarted in a loop. Now the core
// serves its own CA's certificate, says why in its status, keeps trying, and
// switches to the public one with no restart once it is obtained.
func TestTLS011AnACMEFailureServesTheOwnCAUntilTheCertificateArrives(t *testing.T) {
	own := fakeServerCerts{cert: &tls.Certificate{}, st: serverCertStatus{Source: serverCertOwnCA}}
	public := fakeServerCerts{cert: &tls.Certificate{}, st: serverCertStatus{Source: serverCertACME}}
	attempts := 0
	sw := newSwitchableCerts(own)
	r := &acmeRenewer{
		certs: sw, log: newServeLog(&bytes.Buffer{}), every: time.Hour,
		obtain: func(context.Context) (acmeSource, error) {
			attempts++
			if attempts < 2 {
				return nil, errors.New("the DNS record did not propagate")
			}
			return fakeACME{public}, nil
		},
	}

	r.check(t.Context())
	if got, err := sw.GetCertificate(nil); err != nil || got != own.cert {
		t.Fatal("a failed order left the listener without the own CA's certificate")
	}
	if st := sw.Status(); st.Source != serverCertOwnCA || !strings.Contains(st.Problem, "did not propagate") {
		t.Fatalf("status after a failed order = %+v, want the own CA and the reason", st)
	}

	r.check(t.Context())
	if got, err := sw.GetCertificate(nil); err != nil || got != public.cert {
		t.Fatal("the obtained certificate was not swapped in")
	}
	if st := sw.Status(); st.Source != serverCertACME || st.Problem != "" {
		t.Fatalf("status after the order = %+v", st)
	}
	r.check(t.Context())
	if attempts != 2 {
		t.Fatalf("ordered %d times; once obtained, the renewer renews rather than orders", attempts)
	}
	if !strings.Contains(describeServerCert(serverCertStatus{Source: serverCertOwnCA, Problem: "x"}), "public certificate not obtained: x") {
		t.Error("the status line does not say the public certificate is missing, and why")
	}
}

// fakeACME is an obtained ACME source with nothing to renew.
type fakeACME struct{ fakeServerCerts }

func (fakeACME) RenewDue(context.Context) (int, error) { return 0, nil }
