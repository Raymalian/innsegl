// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/api"
)

// Invitations by link (RM-302, #481). An owner or admin mints a single-use
// code; whoever holds the link it is carried in accepts, with an account they
// already have or with a new passkey. No email is asked for or stored: the
// link is the invitation.
//
// Only a SHA-256 of the code is stored, as for enrolment tokens. The spend is
// one UPDATE ... WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at
// > now() RETURNING, in the same transaction as the membership it grants, so
// two people cannot both use one link and a refused acceptance spends
// nothing.

// InvitationTTL is how long an invitation link is usable.
const InvitationTTL = 72 * time.Hour

const invitationPrefix = "iv_"

// Invitation states (api's spelling).
const (
	InvitationPending   = api.InvitationPending
	InvitationAccepted  = api.InvitationAccepted
	InvitationWithdrawn = api.InvitationWithdrawn
	InvitationExpired   = api.InvitationExpired
)

// ErrInvitationInvalid is the one answer for a code that is malformed,
// unknown, expired, withdrawn or already used.
var ErrInvitationInvalid = api.ErrInvitationInvalid

var errNoSuchInvitation = fmt.Errorf("%w: no such pending invitation (%w)", ErrNotFound, api.ErrOrgNotFound)

// invitationHash parses a code and answers the hash it is stored under.
func invitationHash(code string) (string, bool) {
	secret, ok := strings.CutPrefix(strings.TrimSpace(code), invitationPrefix)
	if !ok || len(secret) != 64 || strings.Trim(secret, "0123456789abcdef") != "" {
		return "", false
	}
	return hashSecret(secret), true
}

// CreateInvitation mints an invitation to role and answers its code, once.
// Inviting an owner is the owner's privilege; any other role an admin's.
func (s *Store) CreateInvitation(ctx context.Context, accountID, role, actor string) (string, api.OrgInvitation, error) {
	if err := validRole(role); err != nil {
		return "", api.OrgInvitation{}, err
	}
	secret, err := newID(32)
	if err != nil {
		return "", api.OrgInvitation{}, err
	}
	inv := api.OrgInvitation{AccountID: accountID, Role: role, State: InvitationPending, CreatedBy: actor}
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		if aerr := authorise(ctx, tx, accountID, actor, memberAction(role)); aerr != nil {
			return aerr
		}
		if qerr := tx.QueryRow(ctx, `INSERT INTO innsegl_auth.invitations
			  (account_id, role, code_hash, created_by, expires_at)
			VALUES ($1, $2, $3, $4, clock_timestamp() + $5::interval)
			RETURNING invitation_id, created_at, expires_at`,
			accountID, role, hashSecret(secret), nullable(actor),
			fmt.Sprintf("%d seconds", int(InvitationTTL.Seconds()))).
			Scan(&inv.ID, &inv.CreatedAt, &inv.ExpiresAt); qerr != nil {
			return fmt.Errorf("accounts: storing the invitation: %w", qerr)
		}
		return appendAudit(ctx, tx, AuditEntry{Actor: actor, AccountID: accountID, Action: "invitation.created",
			Subject: strconv.FormatInt(inv.ID, 10),
			Detail:  map[string]any{"role": role, "expires_at": inv.ExpiresAt.UTC().Format(time.RFC3339)}})
	})
	if err != nil {
		return "", api.OrgInvitation{}, err
	}
	return invitationPrefix + secret, inv, nil
}

const usableInvitation = `used_at IS NULL AND revoked_at IS NULL AND expires_at > clock_timestamp()`

// PeekInvitation answers what a usable code invites to, and spends nothing.
func (s *Store) PeekInvitation(ctx context.Context, code string) (api.OrgInvitationPeek, error) {
	hash, ok := invitationHash(code)
	if !ok {
		return api.OrgInvitationPeek{}, ErrInvitationInvalid
	}
	var p api.OrgInvitationPeek
	err := s.pool.QueryRow(ctx, `SELECT i.account_id, a.name, i.role, i.expires_at
		  FROM innsegl_auth.invitations i JOIN innsegl_auth.accounts a USING (account_id)
		 WHERE i.code_hash = $1 AND `+usableInvitation, hash).
		Scan(&p.AccountID, &p.AccountName, &p.Role, &p.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return api.OrgInvitationPeek{}, ErrInvitationInvalid
	}
	if err != nil {
		return api.OrgInvitationPeek{}, fmt.Errorf("accounts: reading the invitation: %w", err)
	}
	return p, nil
}

// acceptTx spends the code for userID and adds the membership it grants.
func acceptTx(ctx context.Context, tx pgx.Tx, hash, userID string) (api.OrgMembership, error) {
	var (
		id int64
		m  api.OrgMembership
	)
	err := tx.QueryRow(ctx, `UPDATE innsegl_auth.invitations
		   SET used_at = clock_timestamp(), accepted_by = $2
		 WHERE code_hash = $1 AND `+usableInvitation+`
		 RETURNING invitation_id, account_id, role`, hash, userID).Scan(&id, &m.AccountID, &m.Role)
	if errors.Is(err, pgx.ErrNoRows) {
		return api.OrgMembership{}, ErrInvitationInvalid
	}
	if err != nil {
		return api.OrgMembership{}, fmt.Errorf("accounts: spending the invitation: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT name, operator FROM innsegl_auth.accounts WHERE account_id = $1`,
		m.AccountID).Scan(&m.Name, &m.Operator); err != nil {
		return api.OrgMembership{}, fmt.Errorf("accounts: reading the organisation: %w", err)
	}
	subject := strconv.FormatInt(id, 10)
	if err := appendAudit(ctx, tx, AuditEntry{Actor: userID, AccountID: m.AccountID, Action: "invitation.accepted",
		Subject: subject, Detail: map[string]any{"role": m.Role}}); err != nil {
		return api.OrgMembership{}, err
	}
	if err := insertMemberTx(ctx, tx, m.AccountID, userID, m.Role, userID,
		map[string]any{"invitation_id": id}); err != nil {
		return api.OrgMembership{}, err
	}
	return m, nil
}

// AcceptInvitation spends a code for an existing user. A user who is already
// a live member is ErrAlreadyMember, and the code stays usable.
func (s *Store) AcceptInvitation(ctx context.Context, code, userID string) (api.OrgMembership, error) {
	hash, ok := invitationHash(code)
	if !ok {
		return api.OrgMembership{}, ErrInvitationInvalid
	}
	var m api.OrgMembership
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var aerr error
		m, aerr = acceptTx(ctx, tx, hash, userID)
		return aerr
	})
	return m, err
}

// AcceptInvitationAsNewUser spends a code for the user create inserts, in the
// same transaction: when either fails, neither the user nor the spend
// remains.
func (s *Store) AcceptInvitationAsNewUser(ctx context.Context, code string,
	create func(q Querier) (string, error),
) (api.OrgMembership, error) {
	hash, ok := invitationHash(code)
	if !ok {
		return api.OrgMembership{}, ErrInvitationInvalid
	}
	var m api.OrgMembership
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		userID, cerr := create(tx)
		if cerr != nil {
			return cerr
		}
		var aerr error
		m, aerr = acceptTx(ctx, tx, hash, userID)
		return aerr
	})
	return m, err
}

// RevokeInvitation withdraws a pending invitation. Withdrawing an owner's
// invitation is the owner's privilege.
func (s *Store) RevokeInvitation(ctx context.Context, accountID string, invitationID int64, actor string) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var role string
		err := tx.QueryRow(ctx, `SELECT role FROM innsegl_auth.invitations
			WHERE invitation_id = $1 AND account_id = $2 AND used_at IS NULL AND revoked_at IS NULL
			FOR UPDATE`, invitationID, accountID).Scan(&role)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNoSuchInvitation
		}
		if err != nil {
			return fmt.Errorf("accounts: reading the invitation: %w", err)
		}
		if aerr := authorise(ctx, tx, accountID, actor, memberAction(role)); aerr != nil {
			return aerr
		}
		if _, xerr := tx.Exec(ctx, `UPDATE innsegl_auth.invitations SET revoked_at = clock_timestamp()
			WHERE invitation_id = $1`, invitationID); xerr != nil {
			return fmt.Errorf("accounts: withdrawing the invitation: %w", xerr)
		}
		return appendAudit(ctx, tx, AuditEntry{Actor: actor, AccountID: accountID, Action: "invitation.withdrawn",
			Subject: strconv.FormatInt(invitationID, 10), Detail: map[string]any{"role": role}})
	})
}

// WithdrawInvitation is RevokeInvitation for the dashboard's members page.
func (s *Store) WithdrawInvitation(ctx context.Context, accountID string, invitationID int64, actor string) error {
	return s.RevokeInvitation(ctx, accountID, invitationID, actor)
}

// Invitations answers an account's invitations, newest first, with the
// state each is in now.
func (s *Store) Invitations(ctx context.Context, accountID string) ([]api.OrgInvitation, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT invitation_id, account_id, role,
		       CASE WHEN used_at IS NOT NULL THEN 'accepted'
		            WHEN revoked_at IS NOT NULL THEN 'withdrawn'
		            WHEN expires_at <= clock_timestamp() THEN 'expired'
		            ELSE 'pending' END,
		       coalesce(created_by, ''), coalesce(accepted_by, ''), created_at, expires_at
		  FROM innsegl_auth.invitations
		 WHERE account_id = $1
		 ORDER BY created_at DESC, invitation_id DESC`, accountID)
	if err != nil {
		return nil, fmt.Errorf("accounts: listing invitations: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.OrgInvitation, error) {
		var i api.OrgInvitation
		err := row.Scan(&i.ID, &i.AccountID, &i.Role, &i.State, &i.CreatedBy, &i.AcceptedBy, &i.CreatedAt, &i.ExpiresAt)
		return i, err
	})
}
