// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Coverage for AuthStore's own error-return paths — every one of them wraps
// a pool call and returns, and a pool that is already closed is an honest,
// uniform way to provoke every single one without inventing a different
// fault for each method: pgxpool refuses any operation once Close has run,
// with a real error rather than a hang or a panic, and this file asks every
// exported method for that answer once.

func TestAuthStoreMethodsAfterThePoolIsClosed(t *testing.T) {
	_, _, _, authDSN := migratedWithAuth(t)
	store, err := OpenAuthStore(context.Background(), authDSN)
	if err != nil {
		t.Fatalf("OpenAuthStore: %v", err)
	}
	store.Close()
	ctx := context.Background()

	if err := store.CreateUser(ctx, "u", "Name"); err == nil {
		t.Error("CreateUser on a closed pool returned nil")
	}
	if _, err := store.UserByID(ctx, "u"); err == nil {
		t.Error("UserByID on a closed pool returned nil")
	} else if errors.Is(err, ErrUserNotFound) {
		t.Error("UserByID on a closed pool returned ErrUserNotFound, want a pool error")
	}
	if _, err := store.EnrolmentOpen(ctx); err == nil {
		t.Error("EnrolmentOpen on a closed pool returned nil")
	}
	if _, err := store.AddPasskey(ctx, "u", "", webauthn.Credential{ID: []byte("cred-closed-1"), AttestationFormat: "none"}); err == nil {
		t.Error("AddPasskey on a closed pool returned nil")
	}
	if _, err := store.PasskeysByUser(ctx, "u"); err == nil {
		t.Error("PasskeysByUser on a closed pool returned nil")
	}
	if err := store.UpdatePasskey(ctx, webauthn.Credential{ID: []byte("cred-closed-2"), AttestationFormat: "none"}); err == nil {
		t.Error("UpdatePasskey on a closed pool returned nil")
	} else if errors.Is(err, ErrPasskeyNotFound) {
		t.Error("UpdatePasskey on a closed pool returned ErrPasskeyNotFound, want a pool error")
	}
	if _, _, err := store.CreateSession(ctx, "u", "", time.Hour); err == nil {
		t.Error("CreateSession on a closed pool returned nil")
	}
	if _, _, _, err := store.VerifySession(ctx, "some-token"); err == nil {
		t.Error("VerifySession on a closed pool returned nil")
	}
	if err := store.RevokeSession(ctx, "some-token"); err == nil {
		t.Error("RevokeSession on a closed pool returned nil")
	}
	if err := store.RecordAuthEvent(ctx, AuthEventSignOut, "u", ""); err == nil {
		t.Error("RecordAuthEvent on a closed pool returned nil")
	}
	if _, _, err := store.CreateEnrolmentCode(ctx, time.Minute); err == nil {
		t.Error("CreateEnrolmentCode on a closed pool returned nil")
	}
	if err := store.ConsumeEnrolmentCode(ctx, "some-code"); err == nil {
		t.Error("ConsumeEnrolmentCode on a closed pool returned nil")
	} else if errors.Is(err, ErrEnrolmentCodeUsed) {
		t.Error("ConsumeEnrolmentCode on a closed pool returned ErrEnrolmentCodeUsed, want a pool error")
	}
	if _, err := store.SaveCeremony(ctx, "login", []byte("{}"), "", "", time.Minute); err == nil {
		t.Error("SaveCeremony on a closed pool returned nil")
	}
	if _, err := store.LoadAndConsumeCeremony(ctx, "some-ceremony", "login"); err == nil {
		t.Error("LoadAndConsumeCeremony on a closed pool returned nil")
	} else if errors.Is(err, ErrCeremonyNotFound) {
		t.Error("LoadAndConsumeCeremony on a closed pool returned ErrCeremonyNotFound, want a pool error")
	}

	// #445's own methods, the same closed-pool technique.
	if err := store.UpdateDisplayName(ctx, "u", "Name"); err == nil {
		t.Error("UpdateDisplayName on a closed pool returned nil")
	} else if errors.Is(err, ErrUserNotFound) {
		t.Error("UpdateDisplayName on a closed pool returned ErrUserNotFound, want a pool error")
	}
	if _, err := store.AccountPasskeys(ctx, "u"); err == nil {
		t.Error("AccountPasskeys on a closed pool returned nil")
	}
	if _, err := store.RenamePasskey(ctx, "u", "cred", "new name"); err == nil {
		t.Error("RenamePasskey on a closed pool returned nil")
	} else if errors.Is(err, ErrPasskeyNotFound) {
		t.Error("RenamePasskey on a closed pool returned ErrPasskeyNotFound, want a pool error")
	}
	if err := store.DeletePasskey(ctx, "u", "cred"); err == nil {
		t.Error("DeletePasskey on a closed pool returned nil")
	} else if errors.Is(err, ErrPasskeyNotFound) || errors.Is(err, ErrLastPasskey) {
		t.Error("DeletePasskey on a closed pool returned a not-found/last-passkey sentinel, want a pool error")
	}
	if _, err := store.MintRecoveryCodes(ctx, "u"); err == nil {
		t.Error("MintRecoveryCodes on a closed pool returned nil")
	}
	if _, _, err := store.ConsumeRecoveryCode(ctx, "whatever-code"); err == nil {
		t.Error("ConsumeRecoveryCode on a closed pool returned nil")
	} else if errors.Is(err, ErrRecoveryCodeInvalid) {
		t.Error("ConsumeRecoveryCode on a closed pool returned ErrRecoveryCodeInvalid, want a pool error")
	}
	if _, err := store.RecoveryCodesRemaining(ctx, "u"); err == nil {
		t.Error("RecoveryCodesRemaining on a closed pool returned nil")
	}

	// RevokeSession("") and VerifySession("") both short-circuit before
	// touching the pool at all (an empty token names no session), so a
	// closed pool must not change their answer — proving the branch is the
	// EMPTY-TOKEN check and not an accidental pool success.
	if err := store.RevokeSession(ctx, ""); err != nil {
		t.Errorf("RevokeSession empty token on a closed pool returned %v, want nil", err)
	}
	if _, _, ok, err := store.VerifySession(ctx, ""); err != nil || ok {
		t.Errorf("VerifySession empty token on a closed pool returned ok=%v err=%v, want false and nil", ok, err)
	}
}

// OpenAuthStore's own two refusals: a DSN it cannot even parse, and a
// credential the server reports CAN write the ledger (the owner) — the
// mirror of TestAssertCannotWriteLedgerCatchesAWritingCredential, but
// through the constructor a production caller actually uses.

func TestOpenAuthStoreRefusesADSNItCannotParse(t *testing.T) {
	if _, err := OpenAuthStore(context.Background(), "postgres://%zz"); err == nil {
		t.Error("OpenAuthStore accepted a DSN it could not parse")
	}
}

func TestOpenAuthStoreRefusesTheOwnerCredential(t *testing.T) {
	_, ownerDSN, _, _ := migratedWithAuth(t)
	store, err := OpenAuthStore(context.Background(), ownerDSN)
	if err == nil {
		store.Close()
		t.Fatal("OpenAuthStore accepted the owner credential, which can write the ledger")
	}
	if !errors.Is(err, ErrWritable) {
		t.Errorf("OpenAuthStore refused the owner credential with %v, want an error wrapping ErrWritable", err)
	}
}

// OpenAuthStoreConfig is reached by OpenAuthStore for every case above; this
// is the one path into it OpenAuthStore's own DSN-parsing cannot reach: a
// config that parses but names a port nothing listens on, so the refusal is
// AssertCannotWriteLedger's own connection attempt failing outright rather
// than a writable-credential verdict.
func TestOpenAuthStoreConfigRefusesAnUnreachableServer(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://nobody:nothing@127.0.0.1:1/nonexistent?connect_timeout=1")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if _, err := OpenAuthStoreConfig(context.Background(), cfg); err == nil {
		t.Error("OpenAuthStoreConfig accepted a config naming an unreachable server")
	}
}
