// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/ledger"
)

// A real ledger for the half of SPI-004 that is about the ledger.
//
// Doc 07's SPI-004 expects two things of retirement: "Immediate credential
// refusal; ledger events for the run remain readable". The second is I4 — "No
// record is ever deleted or mutated ... Retirement deletes the SPIRE entry,
// never ledger content" — and it is not demonstrable against a slice in memory.
// So this file stands up a Postgres and uses the real internal/ledger store,
// the same way internal/ledger/pgharness_test.go does for its own cases.
//
// This package does not write to the ledger in production: pairing an entry
// with its `run_registered` event atomically is the MCP's (IP §6.5, E4). The
// test writes the events itself, retires the run through this package, and then
// re-reads them — which is exactly the claim I4 makes and the only way to see
// that retirement left them alone.

const defaultPostgresImage = "postgres:16"

var (
	pgOnce      sync.Once
	pgContainer string
	pgPort      string
	pgSkip      string
	pgDBSeq     int
	pgDBSeqMu   sync.Mutex
)

const (
	pgUser     = "innsegl"
	pgPassword = "innsegl-test"
	pgDatabase = "innsegl"
)

func pgDSN(port, database string) string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		pgUser, pgPassword, port, database)
}

func startPostgres(ctx context.Context) (id, port string, err error) {
	image := envOr("INNSEGL_TEST_POSTGRES_IMAGE", defaultPostgresImage)
	port, err = freeHostPort(ctx)
	if err != nil {
		return "", "", err
	}
	id, err = docker(ctx, "run", "--detach",
		"--publish", "127.0.0.1:"+port+":5432",
		"--env", "POSTGRES_USER="+pgUser,
		"--env", "POSTGRES_PASSWORD="+pgPassword,
		"--env", "POSTGRES_DB="+pgDatabase,
		image,
	)
	if err != nil {
		return "", "", err
	}
	deadline := time.Now().Add(90 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		conn, cerr := pgx.Connect(attempt, pgDSN(port, pgDatabase))
		if cerr == nil {
			cerr = conn.Ping(attempt)
			_ = conn.Close(attempt)
		}
		cancel()
		if cerr == nil {
			return id, port, nil
		}
		last = cerr
		time.Sleep(250 * time.Millisecond)
	}
	if _, rmErr := docker(context.Background(), "rm", "--force", "--volumes", id); rmErr != nil {
		last = errors.Join(last, rmErr)
	}
	return "", "", fmt.Errorf("postgres never became ready: %w", last)
}

// requireLedger returns a migrated ledger store on a database of its own, or
// skips the calling test naming what went unproven.
func requireLedger(t *testing.T) *ledger.Store {
	t.Helper()
	pgOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		if err := dockerUsable(ctx); err != nil {
			pgSkip = err.Error()
			return
		}
		id, port, err := startPostgres(ctx)
		if err != nil {
			pgSkip = err.Error()
			return
		}
		pgContainer, pgPort = id, port
	})
	if pgContainer == "" {
		t.Skipf("skipping the ledger half of this case: no real Postgres (%s). "+
			"I4 is not demonstrated without one.", pgSkip)
	}

	pgDBSeqMu.Lock()
	pgDBSeq++
	name := fmt.Sprintf("spi_%d_%d", os.Getpid()%100000, pgDBSeq)
	pgDBSeqMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, pgDSN(pgPort, pgDatabase))
	if err != nil {
		t.Fatalf("connect to %s: %v", pgDatabase, err)
	}
	// ADR-0005 scopes a chain to a database, so a database per test is a chain
	// per test.
	_, err = admin.Exec(ctx, `CREATE DATABASE "`+name+`"`)
	closeErr := admin.Close(ctx)
	if err != nil {
		t.Fatalf("create database %s: %v", name, err)
	}
	if closeErr != nil {
		t.Fatalf("close admin connection: %v", closeErr)
	}

	store, err := ledger.Open(ctx, pgDSN(pgPort, name))
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(store.Close)
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("ledger.Migrate: %v", err)
	}
	return store
}

// stopPostgres is called from TestMain's teardown.
func stopPostgres() {
	if pgContainer == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := docker(ctx, "rm", "--force", "--volumes", pgContainer); err != nil {
		fmt.Fprintf(os.Stderr, "warning: removing postgres container: %v\n", err)
	}
}
