// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

// recordPseudonymous records the deployment's switch to pseudonymous
// repositories, as the core does at its first start in that mode, so a test
// that needs two accounts can have them (ACC-008).
func recordPseudonymous(t *testing.T, e *env) {
	t.Helper()
	c, ctx := ownerConn(t, e.ownerDSN)
	if _, err := c.Exec(ctx,
		`INSERT INTO innsegl.repo_mode (mode, key_id) VALUES ('pseudonymous', 'rk-test0001')
		 ON CONFLICT DO NOTHING`); err != nil {
		t.Fatalf("record the switch: %v", err)
	}
}

// ACC-008 (ADR-0080 decision 5, #484): no account beyond the first while
// repository names are stored literally.
func TestACC008ASecondAccountIsRefusedWhileRepositoriesAreLiteral(t *testing.T) {
	e, s := migrated(t)
	ctx := tctx(t)

	first, err := s.CreateAccount(ctx, CreateAccountParams{Name: "First"})
	if err != nil {
		t.Fatalf("the first account is refused: %v", err)
	}

	_, err = s.CreateAccount(ctx, CreateAccountParams{Name: "Second"})
	if !errors.Is(err, ErrRepositoriesLiteral) {
		t.Fatalf("a second account while literal: err = %v, want %v", err, ErrRepositoriesLiteral)
	}
	if !strings.Contains(err.Error(), "INNSEGL_REPO_MODE") || !strings.Contains(err.Error(), "ADR-0080") {
		t.Errorf("the refusal does not name the setting and the ADR: %v", err)
	}
	if got := auditActions(t, e, first.ID); len(got) != 1 {
		t.Errorf("the refused creation left audit rows: %v", got)
	}

	t.Run("the deployment's own organisation is never refused", func(t *testing.T) {
		seedUser(t, e, "u-op")
		if _, err := s.FoundOperator(ctx); err != nil {
			t.Errorf("FoundOperator beside an existing account: %v", err)
		}
	})

	recordPseudonymous(t, e)
	if _, err := s.CreateAccount(ctx, CreateAccountParams{Name: "Second"}); err != nil {
		t.Errorf("a second account after the switch: %v", err)
	}
}

// Two concurrent first creations on a literal deployment: exactly one wins.
func TestACC008ConcurrentCreationsAdmitOne(t *testing.T) {
	_, s := migrated(t)
	ctx := tctx(t)
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = s.CreateAccount(ctx, CreateAccountParams{Name: "Racer"})
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, ErrRepositoriesLiteral):
			t.Errorf("unexpected error: %v", err)
		}
	}
	if ok != 1 {
		t.Errorf("%d concurrent creations succeeded, want exactly 1", ok)
	}
}
