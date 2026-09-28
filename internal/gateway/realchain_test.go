// SPDX-License-Identifier: Apache-2.0

package gateway

// realchain_test.go — RM-235 (#380): a fixture over the REAL chain (a real,
// throwaway Postgres, migrated exactly as production is, with a REAL
// *ledger.Store as register_agent's and retire_agent's own ledger, and a
// real internal/rundir.Directory reading it back) rather than registrar_test.go's
// gwFixture, which uses a fake ledger (gwLedger) that is not the chain --
// registrar_test.go's own file header says why that is right for what IT
// proves (MCPRegistrar's translation) and wrong for what THIS issue's
// supervisor note asks: GID-011 "against the REAL chain". SPIRE stays a
// fake (gwIdentities, registrar_test.go): what SPIRE itself does is already
// proven against a real containerised SPIRE elsewhere (RM-015), and this
// fixture's own claim is about the chain, not about SPIRE.

import (
	"context"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/rundir"
)

const (
	realChainAgentType = "gw-realchain-test"
	realChainRepo      = "github.com/acme/realchain-test"
	realChainBranch    = "main"
	realChainTask      = "rm235"
)

// realChainFixture wires register_agent and retire_agent onto a REAL
// *ledger.Store (a fresh, migrated, throwaway Postgres database) and a fake
// SPIRE, and gives the caller everything #380's real-chain tests need on
// top of that: the store itself (to read events back), a rundir.Directory
// (the same read production wires as mcp.CredentialRuns), a
// PostgresMappingStore on the SAME database (ADR-0060 decision 3: one
// database), and a Registrar reaching the configured tools in process.
type realChainFixture struct {
	dsn     string
	store   *ledger.Store
	ids     *gwIdentities
	dir     *rundir.Directory
	mapping *PostgresMappingStore
}

func newRealChainFixture(t *testing.T) *realChainFixture {
	t.Helper()
	pgc := requireGWPG(t)
	dsn := gwFreshDSN(t, pgc)
	gwMigrate(t, dsn)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	store, err := ledger.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(store.Close)

	idem := mcp.NewIdempotencyStore(gwPool(t, dsn))
	ids := newGWIdentities()
	dir, err := rundir.New(rundir.Config{Events: store})
	if err != nil {
		t.Fatalf("rundir.New: %v", err)
	}
	literal, err := identity.New(identity.ModeLiteral, "")
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}

	restoreReg, err := mcp.ConfigureRegisterAgent(mcp.RegisterAgentConfig{
		Identities:  ids,
		Runs:        dir,
		Ledger:      store,
		Idempotency: idem,
		ParentID:    gwParentID,
		Pseudonyms:  literal,
	})
	if err != nil {
		t.Fatalf("ConfigureRegisterAgent: %v", err)
	}
	t.Cleanup(restoreReg)

	restoreRet, err := mcp.ConfigureRetireAgent(mcp.RetireAgentConfig{
		Runs: dir, Entries: ids, Ledger: store,
	})
	if err != nil {
		t.Fatalf("ConfigureRetireAgent: %v", err)
	}
	t.Cleanup(restoreRet)

	mapping, err := OpenPostgresMappingStore(ctx, dsn)
	if err != nil {
		t.Fatalf("OpenPostgresMappingStore: %v", err)
	}
	t.Cleanup(mapping.Close)

	return &realChainFixture{dsn: dsn, store: store, ids: ids, dir: dir, mapping: mapping}
}

func realChainWorkspace() Workspace {
	return Workspace{Repo: realChainRepo, Branch: realChainBranch, Task: realChainTask}
}

// eventsFor reads runID's own events straight off the real chain.
func (f *realChainFixture) eventsFor(t *testing.T, runID string) []event.Fields {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	recs, err := f.store.EventsForRun(ctx, runID)
	if err != nil {
		t.Fatalf("EventsForRun(%q): %v", runID, err)
	}
	return recs
}
