// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// A person's own sign-ins (RM-333, #511): every live session of theirs, and
// signing out all but the one in use. Both run as the auth writer, on
// innsegl_auth.sessions alone.

// sessionLabelLen is how much of a session's stored hash its label shows. The
// label tells one sign-in from another on the page; it opens nothing, since
// the hash is not the token and a prefix of it is not even the hash.
const sessionLabelLen = 12

// UserSessionRow is one live session of a user.
type UserSessionRow struct {
	Hash        string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	PasskeyName *string // nil for a recovery-code sign-in
}

// UserSessions lists a user's live (unrevoked, unexpired) sessions, newest
// first, with the name of the passkey each signed in with.
func (a *AuthStore) UserSessions(ctx context.Context, userID string) ([]UserSessionRow, error) {
	rows, err := a.pool.Query(ctx, `
		SELECT s.session_id_hash, s.created_at, s.expires_at,
		       CASE WHEN p.credential_id IS NULL THEN NULL ELSE p.name END
		  FROM innsegl_auth.sessions s
		  LEFT JOIN innsegl_auth.passkeys p ON p.credential_id = s.passkey_id
		 WHERE s.user_id = $1 AND s.revoked_at IS NULL AND s.expires_at > clock_timestamp()
		 ORDER BY s.created_at DESC, s.session_id_hash`, userID)
	if err != nil {
		return nil, fmt.Errorf("api: listing sessions for user %s: %w", userID, err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (UserSessionRow, error) {
		var r UserSessionRow
		err := row.Scan(&r.Hash, &r.CreatedAt, &r.ExpiresAt, &r.PasskeyName)
		return r, err
	})
}

// RevokeOtherSessions signs a user out everywhere except the session keep
// names (a raw token, as the cookie carries it), and answers how many it
// ended.
func (a *AuthStore) RevokeOtherSessions(ctx context.Context, userID, keep string) (int, error) {
	tag, err := a.pool.Exec(ctx, `
		UPDATE innsegl_auth.sessions SET revoked_at = clock_timestamp()
		 WHERE user_id = $1 AND session_id_hash <> $2 AND revoked_at IS NULL
		   AND expires_at > clock_timestamp()`, userID, hashToken(keep))
	if err != nil {
		return 0, fmt.Errorf("api: signing out the other sessions of user %s: %w", userID, err)
	}
	return int(tag.RowsAffected()), nil
}
