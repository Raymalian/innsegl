// SPDX-License-Identifier: Apache-2.0

// Package erasure removes the names a pseudonymous chain resolves through
// (ADR-0080 decision 3). It deletes rows of innsegl.pseudonyms and nothing
// else: the chain, the sealed segments and the anchors are not touched, and
// cannot be (LED-046).
//
// It is a package of its own because the ledger appends and nothing else
// (I4): no exported ledger method deletes. Erasure needs DELETE on the alias
// table, which only the database owner holds; the append role is granted
// SELECT and INSERT.
package erasure

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"

	"innsegl.dev/innsegl/internal/event"
)

// Execer is the one database call erasure makes: a pgx pool, connection or
// transaction.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Repository deletes every alias of a repository, under every key id, and
// every alias of its branches, and reports how many rows it deleted. A
// second call deletes nothing and is not an error.
func Repository(ctx context.Context, db Execer, repo string) (int64, error) {
	if err := event.ValidateRepo(repo); err != nil {
		return 0, err
	}
	tag, err := db.Exec(ctx, `
		WITH repos AS (
		    SELECT value FROM innsegl.pseudonyms WHERE kind = 'repo' AND literal = $1)
		DELETE FROM innsegl.pseudonyms
		 WHERE value IN (SELECT value FROM repos)
		    OR (kind = 'branch' AND repo_value IN (SELECT value FROM repos))`, repo)
	if err != nil {
		return 0, fmt.Errorf("erasing the aliases of %s: %w", repo, err)
	}
	return tag.RowsAffected(), nil
}
