// SPDX-License-Identifier: Apache-2.0

package erasure

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"innsegl.dev/innsegl/internal/event"
)

type fakeDB struct {
	sql  string
	args []any
	tag  pgconn.CommandTag
	err  error
}

func (f *fakeDB) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.sql, f.args = sql, args
	return f.tag, f.err
}

// LED-046's refusal paths; the deletion itself is proved on a real chain in
// internal/ledger.
func TestLED046ErasureRefusalsAndTheStatementItRuns(t *testing.T) {
	ctx := context.Background()

	t.Run("a value that is not a repository is refused before the database", func(t *testing.T) {
		db := &fakeDB{}
		if _, err := Repository(ctx, db, "pn:rk-0a1b2c3d:"+strings.Repeat("a", 32)); !errors.Is(err, event.ErrInvalidRepo) {
			t.Errorf("err = %v, want %v: erasure takes the literal a person names", err, event.ErrInvalidRepo)
		}
		if db.sql != "" {
			t.Error("the database was asked")
		}
	})

	t.Run("the deletion counts rows and is scoped to the repository", func(t *testing.T) {
		db := &fakeDB{tag: pgconn.NewCommandTag("DELETE 3")}
		n, err := Repository(ctx, db, "example.test/acme/api")
		if err != nil || n != 3 {
			t.Fatalf("Repository = %d, %v", n, err)
		}
		if !strings.Contains(db.sql, "DELETE FROM innsegl.pseudonyms") || len(db.args) != 1 ||
			db.args[0] != "example.test/acme/api" {
			t.Errorf("ran %q with %v", db.sql, db.args)
		}
	})

	t.Run("a database failure names the repository", func(t *testing.T) {
		db := &fakeDB{err: errors.New("permission denied for table pseudonyms")}
		if _, err := Repository(ctx, db, "example.test/acme/api"); err == nil ||
			!strings.Contains(err.Error(), "example.test/acme/api") {
			t.Errorf("err = %v", err)
		}
	})
}
