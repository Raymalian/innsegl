// SPDX-License-Identifier: Apache-2.0

// Package erasure removes the names a pseudonymous chain resolves through
// (ADR-0080 decision 3). It deletes rows of innsegl.pseudonyms, and records
// that it did in innsegl_auth.audit by pseudonym, never by name. The chain,
// the sealed segments and the anchors are not touched, and cannot be
// (LED-046).
//
// It is a package of its own because the ledger appends and nothing else
// (I4): no exported ledger method deletes. Erasure needs DELETE on the alias
// table, which only the database owner holds; the append role is granted
// SELECT and INSERT.
package erasure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

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

// Repository deletes every alias of a repository, under every key id, and
// every alias of its branches, records the erasure in the audit table by the
// pseudonyms it removed, and answers them. A second call removes nothing,
// records nothing and is not an error. actor names who asked; it may be "".
func Repository(ctx context.Context, db DB, repo, actor string) (erased []string, err error) {
	if verr := event.ValidateRepo(repo); verr != nil {
		return nil, verr
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("erasing the aliases of %s: %w", repo, err)
	}
	defer func() {
		if rerr := tx.Rollback(ctx); err == nil && rerr != nil && !errors.Is(rerr, pgx.ErrTxClosed) {
			err = fmt.Errorf("erasing the aliases of %s: %w", repo, rerr)
		}
	}()

	rows, err := tx.Query(ctx, `
		WITH repos AS (
		    SELECT value FROM innsegl.pseudonyms WHERE kind = 'repo' AND literal = $1)
		DELETE FROM innsegl.pseudonyms
		 WHERE value IN (SELECT value FROM repos)
		    OR (kind = 'branch' AND repo_value IN (SELECT value FROM repos))
		RETURNING value`, repo)
	if err != nil {
		return nil, fmt.Errorf("erasing the aliases of %s: %w", repo, err)
	}
	erased, err = pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("erasing the aliases of %s: %w", repo, err)
	}
	if len(erased) == 0 {
		return nil, nil
	}
	detail, err := json.Marshal(map[string]any{"pseudonyms": erased})
	if err != nil {
		return nil, fmt.Errorf("erasing the aliases of %s: %w", repo, err)
	}
	var who *string
	if actor != "" {
		who = &actor
	}
	if _, xerr := tx.Exec(ctx,
		`INSERT INTO innsegl_auth.audit (actor, action, subject, detail) VALUES ($1, $2, '', $3)`,
		who, AuditAction, detail); xerr != nil {
		return nil, fmt.Errorf("recording the erasure of %s: %w", repo, xerr)
	}
	if cerr := tx.Commit(ctx); cerr != nil {
		return nil, fmt.Errorf("erasing the aliases of %s: %w", repo, cerr)
	}
	return erased, nil
}
