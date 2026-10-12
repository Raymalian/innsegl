// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"
)

// LED-049 (RM-355, #603), the assertion's own edges: the owner can write the
// ledger, the reader reaches beyond enrolment, and the resolver cannot enrol.
// internal/accounts' LED-049 measures the enroller itself and the
// auth-writer's refusal.
func TestLED049AssertEnrollerScopeRefusesTheOwnerTheReaderAndTheResolver(t *testing.T) {
	m := migratedWithRoles(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if _, err := AssertEnrollerScope(ctx, resolverPool(t, m.ownerDSN)); !errors.Is(err, ErrWritable) {
		t.Errorf("AssertEnrollerScope(owner) = %v, want ErrWritable", err)
	}
	if _, err := AssertEnrollerScope(ctx, resolverPool(t, m.readerDSN)); err == nil {
		t.Error("AssertEnrollerScope accepted the reader")
	}
	if _, err := AssertEnrollerScope(ctx, resolverPool(t, m.resolverDSN)); !errors.Is(err, ErrEnrollerCannotEnrol) {
		t.Errorf("AssertEnrollerScope(resolver) = %v, want ErrEnrollerCannotEnrol", err)
	}
	if _, err := AssertEnrollerScope(ctx, resolverPool(t, m.authDSN)); !errors.Is(err, ErrWritable) {
		t.Errorf("AssertEnrollerScope(auth-writer) = %v, want ErrWritable", err)
	}

	// And the role the shipped grants make is accepted.
	const password = "api-enroller-password"
	if err := EnsureEnrollerRole(ctx, m.ownerDSN, EnrollerRole, password); err != nil {
		t.Fatalf("EnsureEnrollerRole: %v", err)
	}
	u, err := url.Parse(m.authDSN)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(EnrollerRole, password)
	report, err := AssertEnrollerScope(ctx, resolverPool(t, u.String()))
	if err != nil || report.Ledger.Role != EnrollerRole {
		t.Fatalf("AssertEnrollerScope(enroller) = %+v, %v", report, err)
	}
}
