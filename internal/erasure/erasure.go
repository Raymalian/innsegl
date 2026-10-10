// SPDX-License-Identifier: Apache-2.0

// Package erasure removes the names a pseudonymous chain resolves through
// (ADR-0080 decision 3), and an organisation's account data with them
// (#482). It deletes rows of innsegl.pseudonyms and of the accounts spine,
// and records that it did in innsegl_auth.audit by pseudonym and id, never
// by name. The chain, the sealed segments and the anchors are not touched,
// and cannot be (LED-046, ACC-010).
//
// It is a package of its own because the ledger appends and nothing else
// (I4): no exported ledger method deletes. Erasure needs DELETE on the alias
// table, which only the database owner holds; the append role is granted
// SELECT and INSERT, and the auth-writer role nothing on it.
package erasure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/event"
)

// DB is what erasure needs of a connection: a transaction. A pgx pool and a
// pgx connection are both one.
type DB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// AuditAction is the innsegl_auth.audit action an erasure records.
const AuditAction = "repository.erased"

// OrganisationAuditAction is the audit action an organisation's erasure
// records, under the erased organisation's id.
const OrganisationAuditAction = "account.erased"

// Repository deletes every alias of a repository, under every key id, and
// every alias of its branches, records the erasure in the audit table by the
// pseudonyms it removed, and answers them. A second call removes nothing,
// records nothing and is not an error. actor names who asked; it may be "".
func Repository(ctx context.Context, db DB, repo, actor string) (erased []string, err error) {
	if verr := event.ValidateRepo(repo); verr != nil {
		return nil, verr
	}
	err = inTx(ctx, db, func(tx pgx.Tx) error {
		var rerr error
		erased, rerr = repositoryTx(ctx, tx, repo, "", actor)
		return rerr
	})
	if err != nil {
		return nil, fmt.Errorf("erasing the aliases of %s: %w", repo, err)
	}
	return erased, nil
}

func inTx(ctx context.Context, db DB, fn func(tx pgx.Tx) error) (err error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if rerr := tx.Rollback(ctx); err == nil && rerr != nil && !errors.Is(rerr, pgx.ErrTxClosed) {
			err = rerr
		}
	}()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func audit(ctx context.Context, tx pgx.Tx, actor, accountID, action, subject string, detail map[string]any) error {
	raw, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO innsegl_auth.audit (actor, account_id, action, subject, detail) VALUES ($1, $2, $3, $4, $5)`,
		nullable(actor), nullable(accountID), action, subject, raw); err != nil {
		return fmt.Errorf("recording the erasure: %w", err)
	}
	return nil
}

// repositoryTx is Repository inside the caller's transaction. accountID,
// when set, is the organisation whose erasure this is part of.
func repositoryTx(ctx context.Context, tx pgx.Tx, repo, accountID, actor string) ([]string, error) {
	rows, err := tx.Query(ctx, `
		WITH repos AS (
		    SELECT value FROM innsegl.pseudonyms WHERE kind = 'repo' AND literal = $1)
		DELETE FROM innsegl.pseudonyms
		 WHERE value IN (SELECT value FROM repos)
		    OR (kind = 'branch' AND repo_value IN (SELECT value FROM repos))
		RETURNING value`, repo)
	if err != nil {
		return nil, err
	}
	erased, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	if len(erased) == 0 {
		return nil, nil
	}
	slices.Sort(erased)
	if err := audit(ctx, tx, actor, accountID, AuditAction, "", map[string]any{"pseudonyms": erased}); err != nil {
		return nil, err
	}
	return erased, nil
}

// Errors Organisation answers.
var (
	// ErrNoSuchOrganisation: no account has that id (or it was erased).
	ErrNoSuchOrganisation = errors.New("erasure: no such organisation")
	// ErrOperatorOrganisation: the deployment's own organisation is never
	// erased; the core recreates it on its next start.
	ErrOperatorOrganisation = errors.New("erasure: the deployment's own organisation cannot be erased")
	// ErrNotOwner: the named actor is not a live owner of the organisation.
	ErrNotOwner = errors.New("erasure: only an owner of the organisation may erase it")
)

// OrganisationResult is what erasing an organisation removed.
type OrganisationResult struct {
	// Repositories whose names were erased: those the organisation held a
	// grant on, live or ended, that no other organisation holds now. The
	// caller removes their mirrors.
	Repositories []string
	// Kept: repositories it once held that another organisation holds now.
	// Their names stay; they are that organisation's.
	Kept []string
	// Pseudonyms whose aliases were deleted.
	Pseudonyms []string
	// Rows deleted, and sessions revoked.
	Members, Installations, Invitations, Grants, Tokens, SessionsRevoked int
}

// Organisation erases an organisation (#482, ADR-0080 decision 3): in one
// transaction, the aliases of every repository only it held, the sessions of
// its live members, and its account rows — enrolment tokens, invitations,
// memberships, repository grants, installations and the account itself. The
// chain is not touched. Users stay: a person is not an organisation, and may
// belong to another.
//
// actor, when set, must hold a live role that mayErase admits (the caller
// passes api.RoleMay for api.PrivilegeEraseOrganisation: this package cannot
// import api, whose tests import it); an empty actor is the operator's core
// command line. The audit trail keeps its rows (it refuses deletion) and
// gains one naming the organisation's id and counts, never a name.
//
// It runs as the database owner: no service role can delete an alias.
func Organisation(ctx context.Context, db DB, accountID, actor string, mayErase func(role string) bool) (OrganisationResult, error) {
	var res OrganisationResult
	err := inTx(ctx, db, func(tx pgx.Tx) error {
		var operator bool
		err := tx.QueryRow(ctx, `SELECT operator FROM innsegl_auth.accounts WHERE account_id = $1 FOR UPDATE`,
			accountID).Scan(&operator)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoSuchOrganisation
		}
		if err != nil {
			return err
		}
		if operator {
			return ErrOperatorOrganisation
		}
		if actor != "" {
			var role string
			rerr := tx.QueryRow(ctx, `SELECT role FROM innsegl_auth.memberships
				WHERE account_id = $1 AND user_id = $2 AND until IS NULL`, accountID, actor).Scan(&role)
			if errors.Is(rerr, pgx.ErrNoRows) || (rerr == nil && (mayErase == nil || !mayErase(role))) {
				return ErrNotOwner
			}
			if rerr != nil {
				return rerr
			}
		}

		rows, err := tx.Query(ctx, `
			SELECT DISTINCT g.repo,
			       EXISTS (SELECT 1 FROM innsegl_auth.repo_grants o
			                WHERE o.repo = g.repo AND o.until IS NULL AND o.account_id <> $1)
			  FROM innsegl_auth.repo_grants g
			 WHERE g.account_id = $1
			 ORDER BY g.repo`, accountID)
		if err != nil {
			return err
		}
		type held struct {
			repo  string
			other bool
		}
		repos, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (held, error) {
			var h held
			return h, r.Scan(&h.repo, &h.other)
		})
		if err != nil {
			return err
		}
		res.Repositories, res.Kept, res.Pseudonyms = []string{}, []string{}, []string{}
		for _, h := range repos {
			if h.other {
				res.Kept = append(res.Kept, h.repo)
				continue
			}
			res.Repositories = append(res.Repositories, h.repo)
			erased, rerr := repositoryTx(ctx, tx, h.repo, accountID, actor)
			if rerr != nil {
				return fmt.Errorf("erasing the aliases of a repository: %w", rerr)
			}
			res.Pseudonyms = append(res.Pseudonyms, erased...)
		}

		tag, err := tx.Exec(ctx, `UPDATE innsegl_auth.sessions SET revoked_at = clock_timestamp()
			WHERE revoked_at IS NULL AND user_id IN (
			    SELECT user_id FROM innsegl_auth.memberships WHERE account_id = $1 AND until IS NULL)`, accountID)
		if err != nil {
			return err
		}
		res.SessionsRevoked = int(tag.RowsAffected())
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM innsegl_auth.memberships
			WHERE account_id = $1 AND until IS NULL`, accountID).Scan(&res.Members); err != nil {
			return err
		}

		// A passkey confirmation still pending for the organisation holds the
		// request it confirms, repositories included: it goes with it.
		if _, err := tx.Exec(ctx, `DELETE FROM innsegl_auth.webauthn_ceremonies
			WHERE session_data->'request'->>'organisation_id' = $1`, accountID); err != nil {
			return fmt.Errorf("deleting the organisation's pending confirmations: %w", err)
		}

		for _, d := range []struct {
			table string
			n     *int
		}{
			{"enrolment_tokens", &res.Tokens},
			{"invitations", &res.Invitations},
			{"memberships", nil},
			{"repo_grants", &res.Grants},
			{"installations", &res.Installations},
			{"accounts", nil},
		} {
			tag, derr := tx.Exec(ctx, `DELETE FROM innsegl_auth.`+d.table+` WHERE account_id = $1`, accountID)
			if derr != nil {
				return fmt.Errorf("deleting the organisation's %s: %w", d.table, derr)
			}
			if d.n != nil {
				*d.n = int(tag.RowsAffected())
			}
		}
		return audit(ctx, tx, actor, accountID, OrganisationAuditAction, accountID, map[string]any{
			"repositories_erased": len(res.Repositories), "repositories_kept": len(res.Kept),
			"pseudonyms": res.Pseudonyms, "members": res.Members, "installations": res.Installations,
			"invitations": res.Invitations, "grants": res.Grants, "enrolment_tokens": res.Tokens,
			"sessions_revoked": res.SessionsRevoked,
		})
	})
	if err != nil {
		return OrganisationResult{}, fmt.Errorf("erasing organisation %s: %w", accountID, err)
	}
	return res, nil
}
