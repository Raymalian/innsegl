// SPDX-License-Identifier: Apache-2.0

package rundir

import (
	"context"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/spire"
)

// RM-151 (#254) — the restore horizon is measured from the wrong lapse.
//
// This case is written to FAIL. RM-152 (#255) is what makes it pass.
//
// ---------------------------------------------------------------------------
// MCP-078 — the horizon is measured from the lapse being restored.
//
//	A run whose FIRST lapse is older than $INNSEGL_ABANDON_AFTER, but whose
//	most recent lapse is an hour old and which worked in between
//	→ restored, and a credential issued
//	→ IP §6.7, ADR-0020
//
// # The defect
//
// `CredentialRun.ExpiredAt` is documented — internal/mcp/runs.go — as "the
// EARLIEST `run_expired`", and this directory computes it that way: every
// later expiry loses to the first one seen. `get_credential`'s fourth gate
// (internal/mcp/get_credential.go) then measures the abandonment horizon from
// that instant. So a run that lapsed on its first day, resumed, and then worked
// for longer than the horizon is refused restore on its NEXT lapse, however
// recently it was alive.
//
// Earliest is right for `RetiredAt` and the two must not be confused. ADR-0020
// §5: retirement is FINAL, two concurrent first retirements can both land, and
// every caller must be told one instant for ever. Expiry is a withdrawal that
// the next call reverses — a run has as many of them as it has quiet spells,
// they are not two reports of one fact, and the only one the horizon can mean
// is the one being restored from.
//
// # Why this is not asserted against the directory alone
//
// Reading `ExpiredAt` back and comparing it to a horizon in the test would put
// the gate's arithmetic in the test, and a fixture that computes the answer
// cannot fail for the production code's reason. So this drives the SHIPPED
// directory, over a chain it really reads, underneath the SHIPPED
// `get_credential` served over its own transport, and asserts the outcome an
// agent gets: restored, or refused.
//
// # How it is kept from passing vacuously
//
// The run's newest fact is a `credential_issued` between the two lapses, so
// "quiet since day one" is not a reading of this chain that anything could
// make. The restorer counts its calls: a pass in which nothing was restored
// and a credential was minted anyway would be a different defect, and is
// asserted apart from the refusal.
// ---------------------------------------------------------------------------

const (
	// The horizon this deployment configures, and the four instants the chain
	// records, as doc 02 §4 timestamps.
	horizonTestAbandonAfter = 30 * 24 * time.Hour

	horizonRegisteredTS = "2026-08-01T09:00:00.000Z"
	// The first lapse: thirty-nine days before the call below, and therefore
	// outside the horizon.
	horizonFirstLapseTS = "2026-08-01T10:00:00.000Z"
	// The run resumed and worked, five weeks after that first lapse.
	horizonWorkedTS = "2026-09-08T09:00:00.000Z"
	// The lapse it is being restored from: an hour before the call.
	horizonSecondLapseTS = "2026-09-09T11:00:00.000Z"
	horizonNowTS         = "2026-09-09T12:00:00.000Z"
)

func TestMCP078HorizonIsMeasuredFromTheLapseBeingRestored(t *testing.T) {
	now := mustParse(t, horizonNowTS)

	// The chain as the deployment would hold it: registered, lapsed, resumed
	// and worked, lapsed again.
	chain := []event.Fields{
		registered(1, horizonRegisteredTS),
		expired(2, horizonFirstLapseTS),
		credentialIssued(3, horizonWorkedTS),
		expired(4, horizonSecondLapseTS),
	}
	directory := newDirectory(t, chain)

	entries := &horizonEntries{absent: true}
	restorer := &horizonRestorer{entries: entries}
	minter := &horizonMinter{now: now}
	sink := &horizonLedger{}

	session := horizonServe(t, mcp.CredentialConfig{
		Runs:         directory,
		Entries:      entries,
		Restorer:     restorer,
		Minter:       minter,
		Ledger:       sink,
		AbandonAfter: horizonTestAbandonAfter,
		Now:          func() time.Time { return now },
	})

	res, err := session.CallTool(t.Context(), &sdk.CallToolParams{
		Name:      string(mcp.ToolGetCredential),
		Arguments: map[string]any{"run_id": testRunID, "audience": mcp.AudienceSigstore},
	})
	if err != nil {
		t.Fatalf("tools/call get_credential: %v", err)
	}

	if res.IsError {
		t.Errorf("a run that lapsed at %s, worked at %s and lapsed again at %s — one hour "+
			"before the call — was refused restore at %s under a %s horizon: %v\n"+
			"The horizon is being measured from the EARLIEST run_expired, so a run that "+
			"survived one quiet spell is abandoned by the clock rather than by silence. "+
			"The only lapse it can mean is the one being restored from",
			horizonFirstLapseTS, horizonWorkedTS, horizonSecondLapseTS, horizonNowTS,
			horizonTestAbandonAfter, res.StructuredContent)
	}
	if got := restorer.count(); got != 1 {
		t.Errorf("the restorer ran %d times, want 1: the entry SPIRE had withdrawn was "+
			"never re-created", got)
	}
	if got := minter.count(); got != 1 {
		t.Errorf("the minter ran %d times, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// The chain record this file adds, and the four dependencies get_credential
// needs besides the directory.
//
// The directory is REAL — it is this package's subject and the thing whose
// answer is in question. Everything else is the smallest stand-in that lets
// the shipped gate run: SPIRE, a minter and an append sink are not what this
// case is about, and a container per case would say nothing more about which
// lapse a horizon is measured from.
// ---------------------------------------------------------------------------

// credentialIssued is a `credential_issued` record as get_credential leaves
// one: doc 02 §3's "a JWT/X.509-SVID was released to the run".
func credentialIssued(position int64, ts string) event.Fields {
	return event.Fields{
		event.FieldSchemaVersion:    event.SchemaVersion,
		event.FieldEventID:          "01930000-0000-7000-8000-00000000003" + fmt.Sprint(position),
		event.FieldChainPosition:    position,
		event.FieldEventType:        event.EventTypeCredentialIssued,
		event.FieldTS:               ts,
		event.FieldRunID:            testRunID,
		event.FieldSpiffeID:         testSPIFFEID,
		event.FieldSource:           event.SourceMCP,
		event.FieldAudience:         mcp.AudienceSigstore,
		event.FieldCredentialExpiry: "2026-09-08T09:05:00.000Z",
	}
}

// horizonEntries is SPIRE's answer to "does this run still have an entry?".
// It starts absent — the reaper withdrew the authorisation — and the restorer
// makes it present, which is what makes the tool's second ask decide.
type horizonEntries struct {
	mu     sync.Mutex
	absent bool
}

func (e *horizonEntries) RequireActiveRun(_ context.Context, run spire.RunRef) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.absent {
		return nil
	}
	return &spire.Error{
		Class: spire.ClassRunNotFound, Op: "require_active_run", RunID: run.RunID,
		Message: "SPIRE holds no registration entry", Retryable: false,
	}
}

func (e *horizonEntries) restore() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.absent = false
}

// horizonRestorer stands in for the wiring layer's runRestorer: it re-creates
// the entry, exactly as re-registering the run would.
type horizonRestorer struct {
	mu      sync.Mutex
	calls   int
	entries *horizonEntries
}

func (r *horizonRestorer) RestoreRun(_ context.Context, _ spire.RunRef) error {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	r.entries.restore()
	return nil
}

func (r *horizonRestorer) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

type horizonMinter struct {
	mu    sync.Mutex
	calls int
	now   time.Time
}

func (m *horizonMinter) MintJWTSVID(_ context.Context, spiffeID, audience string) (mcp.MintedCredential, error) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
	return mcp.MintedCredential{
		Token:     "jwt-svid-for-" + spiffeID,
		SPIFFEID:  spiffeID,
		Audience:  audience,
		ExpiresAt: m.now.Add(5 * time.Minute),
	}, nil
}

func (m *horizonMinter) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// horizonLedger takes the `credential_issued` append I3 requires before a
// token is released.
type horizonLedger struct {
	mu      sync.Mutex
	appends []event.Fields
}

func (l *horizonLedger) Append(_ context.Context, body event.Fields) (event.Fields, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec := body.Clone()
	rec[event.FieldEventID] = "01930000-0000-7000-8000-000000000099"
	l.appends = append(l.appends, rec)
	return rec, nil
}

// horizonServe binds get_credential alone — Config.Tools selects the surface —
// and serves it over the HTTP transport the MCP really uses, so the gate under
// test is reached the way a caller reaches it.
func horizonServe(t *testing.T, cfg mcp.CredentialConfig) *sdk.ClientSession {
	t.Helper()
	if err := mcp.ConfigureGetCredential(cfg); err != nil {
		t.Fatalf("ConfigureGetCredential: %v", err)
	}
	srv, err := mcp.New(mcp.Config{
		Version: "v0.0.0-test",
		Tools:   []mcp.ToolName{mcp.ToolGetCredential},
	})
	if err != nil {
		t.Fatalf("mcp.New: %v", err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	client := sdk.NewClient(&sdk.Implementation{Name: "innsegl-rundir-test", Version: "v0"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: httpSrv.URL}, nil)
	if err != nil {
		t.Fatalf("connecting to %s: %v", httpSrv.URL, err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}
