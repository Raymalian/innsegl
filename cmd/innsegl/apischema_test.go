// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/api"
	"innsegl.dev/innsegl/migrations"
)

// ACC-016 (#480, #481): the API never serves against an older schema than its
// own code needs. `make update` recreates innsegl-api and innsegl-mcp
// together, and the core applies migrations at its start; until it has, the
// new API waits instead of answering member routes from tables that lack
// their columns.

func TestACC016TheAPIWaitsForTheSchemaItsCodeNeeds(t *testing.T) {
	want := newestMigration(t)
	var answers = []string{"0016", "0016", want}
	calls := 0
	read := func(context.Context) (string, error) {
		a := answers[min(calls, len(answers)-1)]
		calls++
		return a, nil
	}
	var logged bytes.Buffer
	if err := waitForSchema(t.Context(), read, want, newServeLog(&logged), time.Millisecond); err != nil {
		t.Fatalf("waitForSchema: %v", err)
	}
	if calls != 3 {
		t.Errorf("read the schema %d times, want 3: it must keep asking until the core has migrated", calls)
	}
	if !strings.Contains(logged.String(), want) {
		t.Errorf("the log does not say which migration it waits for:\n%s", logged.String())
	}

	t.Run("already there: no wait, no log", func(t *testing.T) {
		var quiet bytes.Buffer
		if err := waitForSchema(t.Context(), func(context.Context) (string, error) { return want, nil },
			want, newServeLog(&quiet), time.Hour); err != nil || quiet.Len() != 0 {
			t.Errorf("err %v, log %q", err, quiet.String())
		}
	})
	t.Run("a newer schema is fine", func(t *testing.T) {
		if err := waitForSchema(t.Context(), func(context.Context) (string, error) { return "9999", nil },
			want, newServeLog(&bytes.Buffer{}), time.Hour); err != nil {
			t.Error(err)
		}
	})
	t.Run("stopped while waiting", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := waitForSchema(ctx, func(context.Context) (string, error) { return "0001", nil },
			want, newServeLog(&bytes.Buffer{}), time.Hour); !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	})
	t.Run("a read that fails is retried, not fatal", func(t *testing.T) {
		n := 0
		if err := waitForSchema(t.Context(), func(context.Context) (string, error) {
			n++
			if n == 1 {
				return "", errors.New("connection refused")
			}
			return want, nil
		}, want, newServeLog(&bytes.Buffer{}), time.Millisecond); err != nil || n != 2 {
			t.Errorf("err %v after %d reads", err, n)
		}
	})
}

// The reader credential the API holds can read the applied version, and it
// is the newest this binary carries once the ledger is migrated.
func TestACC016TheReaderSeesTheAppliedSchema(t *testing.T) {
	_, readerDSN, _ := freshLedgerDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	store, err := api.Open(ctx, readerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	got, err := store.SchemaVersion(ctx)
	if err != nil || got != newestMigration(t) {
		t.Fatalf("SchemaVersion = %q %v, want %s", got, err, newestMigration(t))
	}
}

func newestMigration(t *testing.T) string {
	t.Helper()
	all, err := migrations.All()
	if err != nil {
		t.Fatal(err)
	}
	return all[len(all)-1].Version
}
