// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func certificateRequest(t *testing.T, s *Server, route string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	switch route {
	case "codex":
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/backend-api/codex/responses", strings.NewReader("{}"))
		s.Handler().ServeHTTP(w, r)
	case "provider":
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/messages", strings.NewReader("{}"))
		s.serveProvider(w, r)
	case "cli":
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, CorePassPrefix+"/_core/status", nil)
		r.Header.Set(CorePassInstallationHeader, s.core.InstallationID)
		s.serveCorePass(w, r)
	default:
		t.Fatalf("unknown route %q", route)
	}
	return w
}

// RCV-005, CLI-019: harnesses and CLI callers see the actual recovery state.
func TestRCV005RequestExplainsRecoveryFailureAndRetry(t *testing.T) {
	for _, route := range []string{"codex", "provider", "cli"} {
		t.Run(route, func(t *testing.T) {
			_, paths := enrolled(t)
			s, err := NewServer(paths, &syncWriter{})
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			next := now.Add(time.Minute)
			s.Now = func() time.Time { return now }
			s.revoked.Store(true)
			s.recovery.Store(&RecoveryStatus{
				State: "retrying", Error: "VPN connection lost", NextRetry: next,
			})
			w := certificateRequest(t, s, route)
			body := w.Body.String()
			for _, detail := range []string{"certificate", "VPN connection lost", next.Format(time.RFC3339)} {
				if !strings.Contains(body, detail) {
					t.Errorf("response %d %q omitted %q", w.Code, body, detail)
				}
			}
			if w.Code != http.StatusForbidden || strings.Contains(body, "connect --replace") {
				t.Fatalf("transient recovery failure demanded replacement: %d %s", w.Code, body)
			}
		})
	}
}

// RCV-002/005: a request wakes recovery without waiting for the background
// loop, while subsequent requests respect the published retry delay.
func TestRCV002RequestStartsRecoveryAndHonorsBackoff(t *testing.T) {
	_, paths := enrolled(t)
	s, err := NewServer(paths, &syncWriter{})
	if err != nil {
		t.Fatal(err)
	}
	s.revoked.Store(true)
	attempts := 0
	s.transport.Proxy = func(r *http.Request) (*url.URL, error) {
		if strings.HasPrefix(r.URL.Path, recoveryPath) {
			attempts++
			return nil, errors.New("recovery service offline")
		}
		return nil, nil
	}
	for range 2 {
		w := certificateRequest(t, s, "codex")
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "recovery service offline") {
			t.Errorf("recovery failure not explained: %d %s", w.Code, w.Body)
		}
	}
	if attempts != 1 {
		t.Fatalf("recovery attempts=%d, want one before the retry deadline", attempts)
	}
}

// RCV-002/005, CLI-016: an expired local certificate is handled before any
// model request is forwarded, even without a persisted refusal marker.
func TestRCV002ExpiredCertificateRequestAttemptsRecoveryBeforeForwarding(t *testing.T) {
	core, paths := enrolled(t)
	hits := 0
	core.Mux.HandleFunc("/v1/messages", func(w http.ResponseWriter, _ *http.Request) {
		hits++
		if _, err := w.Write([]byte("forwarded")); err != nil {
			t.Error(err)
		}
	})
	s, err := NewServer(paths, &syncWriter{})
	if err != nil {
		t.Fatal(err)
	}
	expiry := s.Leaf().NotAfter
	s.Now = func() time.Time { return expiry.Add(time.Minute) }
	attempts := 0
	s.transport.Proxy = func(r *http.Request) (*url.URL, error) {
		if strings.HasPrefix(r.URL.Path, recoveryPath) {
			attempts++
			return nil, errors.New("recovery service offline")
		}
		return nil, nil
	}
	w := certificateRequest(t, s, "provider")
	if w.Code != http.StatusForbidden || hits != 0 || attempts != 1 {
		t.Fatalf("expired certificate: status=%d model requests=%d recovery attempts=%d", w.Code, hits, attempts)
	}
	if body := w.Body.String(); !strings.Contains(body, "expired") || !strings.Contains(body, expiry.UTC().Format(time.RFC3339)) {
		t.Fatalf("expiry not explained: %s", body)
	}
}

// RCV-005: request diagnostics must not block behind background renewal.
func TestRCV005RequestReportsRecoveryAlreadyInProgress(t *testing.T) {
	_, paths := enrolled(t)
	s, err := NewServer(paths, &syncWriter{})
	if err != nil {
		t.Fatal(err)
	}
	s.revoked.Store(true)
	s.recovery.Store(&RecoveryStatus{State: "recovering"})
	s.renewMu.Lock()
	defer s.renewMu.Unlock()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- certificateRequest(t, s, "codex") }()
	select {
	case w := <-done:
		if !strings.Contains(w.Body.String(), "in progress") {
			t.Fatalf("concurrent recovery not explained: %s", w.Body)
		}
	case <-time.After(time.Second):
		t.Fatal("request waited for the background renewal lock")
	}
}

// RCV-005: an invalid local clock is not an instruction to replace enrollment.
func TestRCV005RequestExplainsCertificateNotYetValid(t *testing.T) {
	_, paths := enrolled(t)
	s, err := NewServer(paths, &syncWriter{})
	if err != nil {
		t.Fatal(err)
	}
	before := s.Leaf().NotBefore.Add(-time.Minute)
	s.Now = func() time.Time { return before }
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ping", nil))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "not yet valid") || !strings.Contains(w.Body.String(), "clock") {
		t.Fatalf("clock problem not explained: %d %s", w.Code, w.Body)
	}
}

// RCV-005: an authoritative refusal preserves the complete owner action.
func TestRCV005RequestShowsOwnerRecoveryAction(t *testing.T) {
	_, paths := enrolled(t)
	s, err := NewServer(paths, &syncWriter{})
	if err != nil {
		t.Fatal(err)
	}
	s.revoked.Store(true)
	action := RecoveryInstruction(s.core.CoreURL, paths.CA)
	s.recovery.Store(&RecoveryStatus{
		State: "authentication required", Error: ErrCredentialRefused.Error(),
		Action: action, NextRetry: time.Now().Add(time.Minute),
	})
	w := certificateRequest(t, s, "codex")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), action) {
		t.Fatalf("owner action missing: %d %s", w.Code, w.Body)
	}
}
