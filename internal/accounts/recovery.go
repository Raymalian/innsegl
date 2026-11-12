// SPDX-License-Identifier: Apache-2.0
package accounts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"innsegl.dev/innsegl/internal/devicerecovery"

	"github.com/jackc/pgx/v5"
)

// RegisterRecovery pins device proof once. The caller must already have
// authenticated with an unexpired installation certificate or fresh token.
// Repeating the same public key is safe; replacing it is not implicit rotation.
func (s *Store) RegisterRecovery(ctx context.Context, id string, public []byte) error {
	if len(public) != ed25519.PublicKeySize {
		return ErrInvalid
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var account string
		if err := tx.QueryRow(ctx, `SELECT account_id FROM innsegl_auth.installations WHERE installation_id=$1 AND status='active' FOR UPDATE`, id).Scan(&account); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		return registerRecoveryTx(ctx, tx, id, account, public)
	})
}

func registerRecoveryTx(ctx context.Context, tx pgx.Tx, id, account string, public []byte) error {
	if len(public) != ed25519.PublicKeySize {
		return ErrInvalid
	}
	tag, err := tx.Exec(ctx, `INSERT INTO innsegl_auth.device_recovery(installation_id,public_key) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, public)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var old []byte
		var active bool
		if err := tx.QueryRow(ctx, `SELECT public_key,revoked_at IS NULL FROM innsegl_auth.device_recovery WHERE installation_id=$1`, id).Scan(&old, &active); err != nil {
			return err
		}
		if !active || !bytes.Equal(old, public) {
			return ErrNotFound
		}
		return nil
	}
	return appendAudit(ctx, tx, AuditEntry{AccountID: account, Action: "installation.recovery_enrolled", Subject: id})
}

// BeginRecovery answers the same random shape even for unknown/inactive devices.
// Only one outstanding challenge can occupy storage per enrolled installation.
func (s *Store) BeginRecovery(ctx context.Context, id, origin, csr string) (string, error) {
	if !installationIDPattern.MatchString(id) || len(origin) == 0 || len(origin) > 512 || len(csr) == 0 || len(csr) > 16384 {
		return "", ErrInvalid
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(raw)
	hash := sha256.Sum256([]byte(nonce))
	_, err := s.pool.Exec(ctx, `INSERT INTO innsegl_auth.device_recovery_challenges(installation_id,challenge_hash,origin,csr,expires_at)
 SELECT d.installation_id,$2,$3,$4,clock_timestamp()+interval '2 minutes' FROM innsegl_auth.device_recovery d
 JOIN innsegl_auth.installations i USING(installation_id) WHERE d.installation_id=$1 AND d.revoked_at IS NULL AND i.status='active'
 ON CONFLICT(installation_id) DO UPDATE SET challenge_hash=EXCLUDED.challenge_hash,origin=EXCLUDED.origin,csr=EXCLUDED.csr,expires_at=EXCLUDED.expires_at,consumed_at=NULL`, id, hash[:], origin, csr)
	return nonce, err
}

// Recover serializes authorization with suspension/revocation and consumes
// proof in the issuance transaction. Failed minting leaves proof retryable.
func (s *Store) Recover(ctx context.Context, id, origin, csr, nonce string, signature []byte, issue IssueFunc) error {
	if !installationIDPattern.MatchString(id) || len(signature) != ed25519.SignatureSize || len(nonce) != 64 || issue == nil {
		return ErrNotFound
	}
	hash := sha256.Sum256([]byte(nonce))
	return s.inTx(ctx, func(tx pgx.Tx) error {
		inst, err := scanInstallation(tx.QueryRow(ctx, `SELECT `+installationColumns+` FROM innsegl_auth.installations WHERE installation_id=$1 AND status='active' FOR UPDATE`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		var public []byte
		err = tx.QueryRow(ctx, `SELECT d.public_key FROM innsegl_auth.device_recovery d JOIN innsegl_auth.device_recovery_challenges c USING(installation_id)
   WHERE d.installation_id=$1 AND d.revoked_at IS NULL AND c.challenge_hash=$2 AND c.origin=$3 AND c.csr=$4 AND c.expires_at>clock_timestamp() AND c.consumed_at IS NULL FOR UPDATE OF d,c`, id, hash[:], origin, csr).Scan(&public)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if !ed25519.Verify(ed25519.PublicKey(public), devicerecovery.Message(origin, id, nonce, csr), signature) {
			return ErrNotFound
		}
		if err := issue(ctx, inst); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE innsegl_auth.device_recovery_challenges SET consumed_at=clock_timestamp() WHERE installation_id=$1`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE innsegl_auth.installations SET last_renewed_at=clock_timestamp() WHERE installation_id=$1`, id); err != nil {
			return err
		}
		if err := appendAudit(ctx, tx, AuditEntry{AccountID: inst.AccountID, Action: "installation.recovered", Subject: id}); err != nil {
			return fmt.Errorf("record recovery: %w", err)
		}
		return nil
	})
}
