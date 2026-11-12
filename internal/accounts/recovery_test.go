// SPDX-License-Identifier: Apache-2.0
package accounts

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
)

func recoveryFixture(t *testing.T) (*env, *Store, Installation, ed25519.PrivateKey) {
	t.Helper()
	e, s, a := setup(t)
	inst, err := s.CreateInstallation(tctx(t), InstallationParams{AccountID: a.ID, CreatedBy: "u-1", Name: "device", Repos: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterRecovery(tctx(t), inst.ID, public); err != nil {
		t.Fatal(err)
	}
	return e, s, inst, key
}

// RCV-003: removing any binding, replay check or signature check permits
// an unauthorized issue. A failed mint must not burn a verified challenge.
func TestRCV003RecoveryProofBindingsReplayAndRollback(t *testing.T) {
	e, s, inst, key := recoveryFixture(t)
	ctx := tctx(t)
	nonce, err := s.BeginRecovery(ctx, inst.ID, "https://core.example", "signed-csr")
	if err != nil {
		t.Fatal(err)
	}
	sign := func(origin, id, n, csr string) []byte {
		return ed25519.Sign(key, RecoveryMessageForTest(origin, id, n, csr))
	}
	never := func(context.Context, Installation) error { t.Fatal("unauthorized proof reached issuer"); return nil }
	for _, tc := range []struct {
		name, origin, id, nonce, csr string
		signature                    []byte
	}{
		{"origin", "https://other.example", inst.ID, nonce, "signed-csr", sign("https://core.example", inst.ID, nonce, "signed-csr")},
		{"csr", "https://core.example", inst.ID, nonce, "other-csr", sign("https://core.example", inst.ID, nonce, "signed-csr")},
		{"installation", "https://core.example", testInstallationID, nonce, "signed-csr", sign("https://core.example", inst.ID, nonce, "signed-csr")},
		{"nonce", "https://core.example", inst.ID, "0000000000000000000000000000000000000000000000000000000000000000", "signed-csr", sign("https://core.example", inst.ID, nonce, "signed-csr")},
		{"signature", "https://core.example", inst.ID, nonce, "signed-csr", make([]byte, 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.Recover(ctx, tc.id, tc.origin, tc.csr, tc.nonce, tc.signature, never); !errors.Is(err, ErrNotFound) {
				t.Fatalf("got %v", err)
			}
		})
	}
	signature := sign("https://core.example", inst.ID, nonce, "signed-csr")
	boom := errors.New("authority unavailable")
	if err := s.Recover(ctx, inst.ID, "https://core.example", "signed-csr", nonce, signature, func(context.Context, Installation) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("mint failure: %v", err)
	}
	var issued atomic.Int32
	issue := func(context.Context, Installation) error { issued.Add(1); return nil }
	results := make(chan error, 2)
	for range 2 {
		go func() {
			results <- s.Recover(ctx, inst.ID, "https://core.example", "signed-csr", nonce, signature, issue)
		}()
	}
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		} else if !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
	}
	if successes != 1 || issued.Load() != 1 {
		t.Fatalf("concurrent proof issued %d times", issued.Load())
	}
	if n := countRows(t, e, `SELECT count(*) FROM innsegl_auth.audit WHERE action='installation.recovered'`); n != 1 {
		t.Fatalf("audit count %d", n)
	}
}

// Literal encoding exercises the documented wire contract independently.
func RecoveryMessageForTest(origin, id, nonce, csr string) []byte {
	b, err := json.Marshal(struct {
		Version      string `json:"version"`
		Origin       string `json:"origin"`
		Installation string `json:"installation_id"`
		Operation    string `json:"operation"`
		Challenge    string `json:"challenge"`
		CSR          string `json:"csr"`
	}{"innsegl recovery v1", origin, id, "recover", nonce, csr})
	if err != nil {
		panic(err)
	}
	return b
}

func TestRCV004RecoveryChecksLiveAuthorizationAndChallengeExpiry(t *testing.T) {
	for _, problem := range []string{"expired challenge", "suspended", "revoked", "recovery key revoked"} {
		t.Run(problem, func(t *testing.T) {
			e, s, inst, key := recoveryFixture(t)
			ctx := tctx(t)
			nonce, err := s.BeginRecovery(ctx, inst.ID, "https://core.example", "csr")
			if err != nil {
				t.Fatal(err)
			}
			switch problem {
			case "suspended", "revoked":
				if statusErr := s.SetInstallationStatus(ctx, inst.ID, problem, "u-1"); statusErr != nil {
					t.Fatal(statusErr)
				}
			default:
				c, cctx := ownerConn(t, e.ownerDSN)
				q := `UPDATE innsegl_auth.device_recovery_challenges SET expires_at=clock_timestamp()-interval '1 second' WHERE installation_id=$1`
				if problem == "recovery key revoked" {
					q = `UPDATE innsegl_auth.device_recovery SET revoked_at=clock_timestamp() WHERE installation_id=$1`
				}
				if _, updateErr := c.Exec(cctx, q, inst.ID); updateErr != nil {
					t.Fatal(updateErr)
				}
			}
			err = s.Recover(ctx, inst.ID, "https://core.example", "csr", nonce, ed25519.Sign(key, RecoveryMessageForTest("https://core.example", inst.ID, nonce, "csr")), func(context.Context, Installation) error { t.Fatal("inactive/expired proof issued"); return nil })
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestRCV001RecoveryKeyIsPinnedAndIdempotent(t *testing.T) {
	_, s, inst, key := recoveryFixture(t)
	if err := s.RegisterRecovery(tctx(t), inst.ID, key[ed25519.SeedSize:]); err != nil {
		t.Fatal(err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterRecovery(tctx(t), inst.ID, other); !errors.Is(err, ErrNotFound) {
		t.Fatalf("silently replaced proof: %v", err)
	}
	if err := s.RegisterRecovery(tctx(t), inst.ID, []byte("bad")); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}
