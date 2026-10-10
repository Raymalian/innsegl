// SPDX-License-Identifier: Apache-2.0

package erasure

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/event"
)

type failingDB struct{ asked bool }

func (f *failingDB) Begin(context.Context) (pgx.Tx, error) {
	f.asked = true
	return nil, errors.New("permission denied for table pseudonyms")
}

// LED-046's refusal paths; the deletion itself, and its audit row, are
// proved on a real database in internal/ledger.
func TestLED046ErasureRefusals(t *testing.T) {
	ctx := context.Background()

	t.Run("a value that is not a repository is refused before the database", func(t *testing.T) {
		db := &failingDB{}
		if _, err := Repository(ctx, db, "pn:rk-0a1b2c3d:"+strings.Repeat("a", 32), ""); !errors.Is(err, event.ErrInvalidRepo) {
			t.Errorf("err = %v, want %v: erasure takes the literal a person names", err, event.ErrInvalidRepo)
		}
		if db.asked {
			t.Error("the database was asked")
		}
	})

	t.Run("a database failure names the repository", func(t *testing.T) {
		if _, err := Repository(ctx, &failingDB{}, "example.test/acme/api", ""); err == nil ||
			!strings.Contains(err.Error(), "example.test/acme/api") {
			t.Errorf("err = %v", err)
		}
	})
}
