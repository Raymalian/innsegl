// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const testInstallationID = "0123456789abcdef0123456789abcdef"

func countRows(t *testing.T, e *env, query string, args ...any) int {
	t.Helper()
	c, ctx := ownerConn(t, e.ownerDSN)
	var n int
	if err := c.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// KEY-001 (store half): enrolment consumes the token, creates the
// installation the token describes under the id the client chose, and calls
// issue inside the same transaction.
func TestKEY001EnrolCreatesTheInstallationAndSpendsTheToken(t *testing.T) {
	e, s, a := setup(t)
	tok, meta, err := s.CreateEnrolmentToken(tctx(t), TokenParams{
		AccountID: a.ID, CreatedBy: "u-1", Repos: []string{"github.com/acme/app"}, Kind: KindService})
	if err != nil {
		t.Fatal(err)
	}
	var issued Installation
	inst, err := s.Enrol(tctx(t), EnrolParams{Token: tok, InstallationID: testInstallationID, Name: "laptop"},
		func(_ context.Context, i Installation) error { issued = i; return nil })
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	if inst.ID != testInstallationID || inst.AccountID != a.ID || inst.CreatedBy != "u-1" ||
		inst.Kind != KindService || inst.Status != StatusActive || inst.Name != "laptop" ||
		len(inst.Repos) != 1 || inst.Repos[0] != "github.com/acme/app" {
		t.Fatalf("installation = %+v", inst)
	}
	if issued.ID != inst.ID {
		t.Fatalf("issue saw %+v, want the created installation", issued)
	}
	if n := countRows(t, e, `SELECT count(*) FROM innsegl_auth.enrolment_tokens
		WHERE token_id = $1 AND used_at IS NOT NULL AND installation_id = $2`, meta.TokenID, inst.ID); n != 1 {
		t.Fatalf("token row spent and linked = %d, want 1", n)
	}
	got := strings.Join(auditActions(t, e, a.ID), ",")
	if !strings.HasSuffix(got, "enrolment_token.consumed,installation.created") {
		t.Fatalf("audit = %s", got)
	}

	// Single use.
	if _, err := s.Enrol(tctx(t), EnrolParams{Token: tok, InstallationID: strings.Repeat("a", 32), Name: "again"},
		func(context.Context, Installation) error { return nil }); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("second Enrol: %v, want ErrTokenInvalid", err)
	}
}

// KEY-003 (store half): a failed issue rolls everything back. The token is
// not burned, no installation exists, and no audit row says otherwise.
func TestKEY003FailedIssueLeavesTheTokenUnspentAndNothingCreated(t *testing.T) {
	e, s, a := setup(t)
	tok, _, err := s.CreateEnrolmentToken(tctx(t), TokenParams{AccountID: a.ID, CreatedBy: "u-1", Repos: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	before := len(auditActions(t, e, a.ID))
	boom := errors.New("mint failed")
	if _, err := s.Enrol(tctx(t), EnrolParams{Token: tok, InstallationID: testInstallationID, Name: "x"},
		func(context.Context, Installation) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("Enrol with a failing issue: %v, want the issue's error", err)
	}
	if n := countRows(t, e, `SELECT count(*) FROM innsegl_auth.installations`); n != 0 {
		t.Fatalf("installations after a failed issue = %d, want 0", n)
	}
	if after := len(auditActions(t, e, a.ID)); after != before {
		t.Fatalf("audit rows %d -> %d after a rolled-back enrolment", before, after)
	}
	if _, err := s.Enrol(tctx(t), EnrolParams{Token: tok, InstallationID: testInstallationID, Name: "x"},
		func(context.Context, Installation) error { return nil }); err != nil {
		t.Fatalf("retry with the same token after a failed issue: %v", err)
	}
}

// KEY-002 (store half): every token problem is the one ErrTokenInvalid, and
// argument problems are refused before the token is looked at.
func TestKEY002EnrolRefusals(t *testing.T) {
	e, s, a := setup(t)
	tok, _, err := s.CreateEnrolmentToken(tctx(t), TokenParams{AccountID: a.ID, CreatedBy: "u-1", Repos: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	never := func(context.Context, Installation) error { t.Fatal("issue called on a refused enrolment"); return nil }
	for _, bad := range []string{"", "ie_", "nonsense", tok + "x", "ie_nosuch_" + strings.Repeat("0", 64)} {
		if _, eerr := s.Enrol(tctx(t), EnrolParams{Token: bad, InstallationID: testInstallationID, Name: "x"}, never); !errors.Is(eerr, ErrTokenInvalid) {
			t.Errorf("Enrol(%q): %v, want ErrTokenInvalid", bad, eerr)
		}
	}
	for _, p := range []EnrolParams{
		{Token: tok, InstallationID: "short", Name: "x"},
		{Token: tok, InstallationID: strings.ToUpper(testInstallationID), Name: "x"},
		{Token: tok, InstallationID: testInstallationID, Name: " "},
		{Token: tok, InstallationID: testInstallationID, Name: strings.Repeat("n", 257)},
	} {
		if _, eerr := s.Enrol(tctx(t), p, never); !errors.Is(eerr, ErrInvalid) {
			t.Errorf("Enrol(%+v): %v, want ErrInvalid", p, eerr)
		}
	}
	if n := countRows(t, e, `SELECT count(*) FROM innsegl_auth.enrolment_tokens WHERE used_at IS NOT NULL`); n != 0 {
		t.Fatalf("spent tokens after refusals = %d, want 0", n)
	}

	// An id already in use is refused without spending the token.
	if _, err = s.Enrol(tctx(t), EnrolParams{Token: tok, InstallationID: testInstallationID, Name: "x"},
		func(context.Context, Installation) error { return nil }); err != nil {
		t.Fatal(err)
	}
	tok2, _, err := s.CreateEnrolmentToken(tctx(t), TokenParams{AccountID: a.ID, CreatedBy: "u-1", Repos: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enrol(tctx(t), EnrolParams{Token: tok2, InstallationID: testInstallationID, Name: "y"}, never); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Enrol with an id in use: %v, want ErrInvalid", err)
	}
	if _, err := s.ConsumeEnrolmentToken(tctx(t), tok2); err != nil {
		t.Fatalf("the token after an id collision should be unspent: %v", err)
	}
}

// KEY-005 (store half): renewal stamps last_renewed_at for an active
// installation only, and a failed issue changes nothing.
func TestKEY005RenewOnlyForAnActiveInstallation(t *testing.T) {
	e, s, a := setup(t)
	inst, err := s.CreateInstallation(tctx(t), InstallationParams{AccountID: a.ID, CreatedBy: "u-1", Name: "m", Repos: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("mint failed")
	if _, rerr := s.Renew(tctx(t), inst.ID, func(context.Context, Installation) error { return boom }); !errors.Is(rerr, boom) {
		t.Fatalf("Renew with a failing issue: %v", rerr)
	}
	got, err := s.GetInstallation(tctx(t), inst.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastRenewedAt != nil {
		t.Fatalf("last_renewed_at set by a failed renewal: %v", got.LastRenewedAt)
	}
	renewed, err := s.Renew(tctx(t), inst.ID, func(context.Context, Installation) error { return nil })
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if renewed.LastRenewedAt == nil || renewed.ID != inst.ID {
		t.Fatalf("renewed = %+v", renewed)
	}
	if got := strings.Join(auditActions(t, e, a.ID), ","); !strings.HasSuffix(got, "installation.renewed") {
		t.Fatalf("audit = %s", got)
	}

	never := func(context.Context, Installation) error { t.Fatal("issue called for a refused renewal"); return nil }
	for _, status := range []string{StatusSuspended, StatusRevoked} {
		other, err := s.CreateInstallation(tctx(t), InstallationParams{AccountID: a.ID, CreatedBy: "u-1", Name: status, Repos: []string{"*"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SetInstallationStatus(tctx(t), other.ID, status, "u-1"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Renew(tctx(t), other.ID, never); !errors.Is(err, ErrNotFound) {
			t.Errorf("Renew(%s): %v, want ErrNotFound", status, err)
		}
	}
	if _, err := s.Renew(tctx(t), strings.Repeat("f", 32), never); !errors.Is(err, ErrNotFound) {
		t.Errorf("Renew(unknown): %v, want ErrNotFound", err)
	}
}
