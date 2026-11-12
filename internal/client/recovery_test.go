// SPDX-License-Identifier: Apache-2.0
package client

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RCV-001: a new client must retain separate recovery proof across restarts.
func TestRCV001EnrollmentPersistsASeparatePrivateRecoveryCredential(t *testing.T) {
	_, paths := enrolled(t)
	key, err := os.ReadFile(filepath.Join(paths.Dir, "recovery-key"))
	if err != nil {
		t.Fatalf("enrollment did not persist recovery proof: %v", err)
	}
	if len(key) != 64 {
		t.Fatalf("recovery key length %d", len(key))
	}
	info, err := os.Stat(filepath.Join(paths.Dir, "recovery-key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("recovery key mode %v", info.Mode())
	}
	s, err := NewServer(paths, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.MaybeRenew(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// RCV-001: a failed migration must be retried while ordinary renewal works.
func TestRCV001SuccessfulRenewalRetriesLegacyRecoveryEnrollment(t *testing.T) {
	core, paths := enrolled(t)
	if err := os.Remove(paths.RecoveryKey); err != nil {
		t.Fatal(err)
	}
	requests := 0
	core.Mux.HandleFunc(recoveryPath+"enroll", func(w http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	s, err := NewServer(paths, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ensureRecoveryKey(t.Context()); err == nil {
		t.Fatal("outage did not interrupt migration")
	}
	leaf := s.Leaf()
	s.Now = func() time.Time { return leaf.NotBefore.Add(13 * time.Hour) }
	if renewed, err := s.MaybeRenew(t.Context()); err != nil || !renewed {
		t.Fatalf("ordinary renewal: %v %v", renewed, err)
	}
	if requests != 2 {
		t.Fatalf("recovery enrollment attempts = %d, want 2 after successful renewal", requests)
	}
}

// RCV-005: a recovery outage following a certificate refusal is retryable;
// the earlier refusal does not establish that fresh owner proof is required.
func TestRCV005RecoveryOutageDoesNotDemandReplacementToken(t *testing.T) {
	core, paths := enrolled(t)
	core.SetRevoked(true)
	s, err := NewServer(paths, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	s.transport.Proxy = func(r *http.Request) (*url.URL, error) {
		if strings.HasPrefix(r.URL.Path, recoveryPath) {
			return nil, errors.New("VPN connection lost")
		}
		return nil, nil
	}
	leaf := s.Leaf()
	s.Now = func() time.Time { return leaf.NotBefore.Add(13 * time.Hour) }
	if _, err := s.MaybeRenew(t.Context()); err == nil {
		t.Fatal("outage was not reported")
	}
	st := s.recovery.Load()
	if st == nil || st.State != "retrying" || st.NextRetry.IsZero() || st.Action != "" {
		t.Fatalf("transient outage demanded replacement: %+v", st)
	}
}
