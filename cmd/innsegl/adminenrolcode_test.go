// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// `innsegl admin-credential enrol-code`: flag handling and exit statuses
// against a stub — the real write against
// a real Postgres is internal/api's own AUTH-002 coverage
// (TestAUTH002EnrolmentWithADenyingFileAndAValidCodeCompletes and its
// siblings), which exercises AuthStore.CreateEnrolmentCode directly; nothing
// here repeats that proof.

type stubEnrolCodeMinter struct {
	code      string
	expiresAt time.Time
	err       error
	calls     []time.Duration
}

func (s *stubEnrolCodeMinter) CreateEnrolmentCode(_ context.Context, ttl time.Duration) (string, time.Time, error) {
	s.calls = append(s.calls, ttl)
	return s.code, s.expiresAt, s.err
}

func stubEnrolCodeOpen(m enrolCodeMinter, openErr error, closed *bool) func(context.Context, string) (enrolCodeMinter, func(), error) {
	return func(context.Context, string) (enrolCodeMinter, func(), error) {
		if openErr != nil {
			return nil, nil, openErr
		}
		return m, func() {
			if closed != nil {
				*closed = true
			}
		}, nil
	}
}

func TestAdminCredentialEnrolCodeRequiresADSN(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runAdminCredentialEnrolCode([]string{}, &stdout, &stderr, enrolCodeDeps{})
	if code != exitUsage {
		t.Fatalf("with no -dsn: exit %d, want %d: %s", code, exitUsage, stderr.String())
	}
	if !strings.Contains(stderr.String(), "-dsn") {
		t.Errorf("the refusal does not name the missing flag: %s", stderr.String())
	}
}

func TestAdminCredentialEnrolCodeRejectsATTLOutOfBounds(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runAdminCredentialEnrolCode(
		[]string{"-dsn", "postgres://x", "-ttl", "2h"}, &stdout, &stderr, enrolCodeDeps{})
	if code != exitUsage {
		t.Fatalf("a -ttl beyond the bound: exit %d, want %d: %s", code, exitUsage, stderr.String())
	}
}

func TestAdminCredentialEnrolCodeRejectsANonPositiveTTL(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runAdminCredentialEnrolCode(
		[]string{"-dsn", "postgres://x", "-ttl", "0s"}, &stdout, &stderr, enrolCodeDeps{})
	if code != exitUsage {
		t.Fatalf("a zero -ttl: exit %d, want %d: %s", code, exitUsage, stderr.String())
	}
}

func TestAdminCredentialEnrolCodeWritesTheCodeToStdoutAndNothingElse(t *testing.T) {
	expires := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	m := &stubEnrolCodeMinter{code: "a-fresh-one-time-code", expiresAt: expires}
	var closed bool
	deps := enrolCodeDeps{open: stubEnrolCodeOpen(m, nil, &closed)}

	var stdout, stderr bytes.Buffer
	code := runAdminCredentialEnrolCode([]string{"-dsn", "postgres://x"}, &stdout, &stderr, deps)
	if code != exitOK {
		t.Fatalf("exit %d, want %d: %s", code, exitOK, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != "a-fresh-one-time-code" {
		t.Fatalf("stdout = %q, want exactly the code and nothing else", stdout.String())
	}
	if strings.Contains(stderr.String(), "a-fresh-one-time-code") {
		t.Error("the code itself leaked onto stderr; only stdout may carry it")
	}
	if !strings.Contains(stderr.String(), "2026-10-01T12:00:00Z") {
		t.Errorf("stderr does not name the expiry: %s", stderr.String())
	}
	if !closed {
		t.Error("the store was never closed")
	}
	if len(m.calls) != 1 || m.calls[0] != enrolCodeDefaultTTL {
		t.Errorf("CreateEnrolmentCode called with %v, want the default TTL once", m.calls)
	}
}

func TestAdminCredentialEnrolCodePassesTheRequestedTTLThrough(t *testing.T) {
	m := &stubEnrolCodeMinter{code: "x", expiresAt: time.Now()}
	deps := enrolCodeDeps{open: stubEnrolCodeOpen(m, nil, nil)}

	var stdout, stderr bytes.Buffer
	code := runAdminCredentialEnrolCode(
		[]string{"-dsn", "postgres://x", "-ttl", "5m"}, &stdout, &stderr, deps)
	if code != exitOK {
		t.Fatalf("exit %d, want %d: %s", code, exitOK, stderr.String())
	}
	if len(m.calls) != 1 || m.calls[0] != 5*time.Minute {
		t.Errorf("calls = %v, want a single 5m call", m.calls)
	}
}

func TestAdminCredentialEnrolCodeReportsAStoreThatCannotBeOpened(t *testing.T) {
	deps := enrolCodeDeps{open: stubEnrolCodeOpen(nil, errors.New("connect: refused"), nil)}

	var stdout, stderr bytes.Buffer
	code := runAdminCredentialEnrolCode([]string{"-dsn", "postgres://x"}, &stdout, &stderr, deps)
	if code != exitCredentialUnusable {
		t.Fatalf("exit %d, want %d: %s", code, exitCredentialUnusable, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout carries something despite the open failing: %q", stdout.String())
	}
}

func TestAdminCredentialEnrolCodeReportsAWriteThatFails(t *testing.T) {
	m := &stubEnrolCodeMinter{err: errors.New("insufficient_privilege")}
	deps := enrolCodeDeps{open: stubEnrolCodeOpen(m, nil, nil)}

	var stdout, stderr bytes.Buffer
	code := runAdminCredentialEnrolCode([]string{"-dsn", "postgres://x"}, &stdout, &stderr, deps)
	if code != exitCredentialUnusable {
		t.Fatalf("exit %d, want %d: %s", code, exitCredentialUnusable, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout carries something despite the write failing: %q", stdout.String())
	}
}

// The dispatch from `innsegl admin-credential enrol-code` itself, not only
// the direct call — proves the verb is actually wired into admincred.go's
// switch.
func TestAdminCredentialDispatchesEnrolCode(t *testing.T) {
	code, _, stderr := runAdminCredential(t, "enrol-code")
	if code != exitUsage {
		t.Fatalf("enrol-code with no -dsn via the top-level dispatch: exit %d, want %d: %s",
			code, exitUsage, stderr)
	}
	if strings.Contains(stderr, "unknown verb") {
		t.Fatalf("enrol-code was not recognised as a verb: %s", stderr)
	}
}
