// SPDX-License-Identifier: Apache-2.0

package ledger

// RM-093 (#145) found, and #148 confirmed by independent reproduction, that
// Append could duplicate an event: a COMMIT can fully complete on Postgres
// while the CLIENT's read of the acknowledgment fails — a severed connection
// is, on the wire, indistinguishable from the SIGKILL case RM-069 (#90)
// names — and pgx's own SafeToRetry still reports that failure as safe to
// retry. Append's retry loop trusted that report alone. For a KEYED event
// that is harmless: the retried attempt's readByKey finds the row the first
// attempt already committed and returns it (LED-008) rather than inserting
// again. For an UNKEYED event — credential_issued and run_retired are the two
// that exist today — there is no such fallback, so the retry inserted a
// second, real row for one call: ADR-0004's "one issuance, one auditable
// fact", violated by the ledger's own retry, not by anything above it.
//
// LED-012 and LED-013 are this file's two claims, and they are DRIVEN, not
// waited for: a TCP proxy sits between a real ledger.Store and the real
// Postgres container this package already brings up for every other LED
// test. It lets the FIRST "commit" a connection sends through to Postgres
// reach the server, confirms — from the server's own reply bytes — that
// Postgres answered CommandComplete("COMMIT") + ReadyForQuery before doing
// anything else, and only THEN severs the client-facing socket without
// forwarding that reply. That is the ambiguity itself, produced on command
// rather than raced for across a whole SIGKILL campaign: the commit is
// PROVABLY durable, and the caller PROVABLY never found out.
//
//   - LED-012 (this file) is the regression: one Append call of an unkeyed
//     event, its commit's acknowledgment withheld, must leave exactly one row
//     and must not report success while a duplicate sits on the chain.
//   - LED-013 (this file) establishes rather than assumes that the keyed path
//     the retry is still allowed to take is actually safe: exactly one row,
//     and the record Append returns is the SAME row — same event_id, same
//     chain_position — as the one durably on the chain, not a mismatched
//     read.
import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// ---------------------------------------------------------------------------
// LED-012 — an unkeyed event's commit, acknowledgment withheld, appends once.
// ---------------------------------------------------------------------------

func TestLED012AppendNeverDuplicatesAnUnkeyedEventOnAnAmbiguousCommit(t *testing.T) {
	c := requirePG(t)
	dsn := freshDSN(t, c)

	// Migrate DIRECTLY, unproxied: Migrate's own DDL legitimately sends
	// "commit" (transaction-wrapped statements), and the proxy's sabotage is
	// a ONE-SHOT armed for the Append call under test, not for setup.
	migrateDirect(t, dsn)

	store, proxyStop := openThroughAmbiguousCommitProxy(t, c, dsn)
	defer proxyStop()

	runID := "run-led012-unkeyed-ambiguous-commit-0001"
	ctx := testCtx(t, 20*time.Second)
	record, appendErr := store.Append(ctx, unkeyedCredentialIssuedBody(runID))

	// The row count is read on a fresh, un-proxied connection to the SAME
	// database — independent of whatever Append itself believes happened.
	admin := rawConn(t, dsn)
	var n int
	if err := admin.QueryRow(context.Background(),
		`SELECT count(*) FROM innsegl.events WHERE event_type = 'credential_issued' AND run_id = $1`,
		runID).Scan(&n); err != nil {
		t.Fatalf("count rows for %q: %v", runID, err)
	}
	t.Logf("LED-012: Append returned record=%v err=%v; Postgres independently holds %d "+
		"credential_issued row(s) for %q", record != nil, appendErr, n, runID)

	if n > 1 {
		t.Fatalf("LED-012: ONE Append call whose commit's acknowledgment was withheld left %d "+
			"rows on the chain for run %q. Each issuance is one auditable fact and no more "+
			"(ADR-0004); an unkeyed event has no idempotency dedupe to fall back on, so Append "+
			"retrying this ambiguous failure is what produced the second row.", n, runID)
	}
	if n == 1 && appendErr == nil {
		// A row landed AND Append reported success on the sabotaged attempt
		// itself, without any retry having been needed to reach it — the
		// proxy did not actually produce the ambiguity this test exists to
		// name. Distinguished from the true positive above so a broken proxy
		// reads as "this test proved nothing" rather than "the fix works".
		t.Fatalf("LED-012: Append returned success with no error on the FIRST (sabotaged) " +
			"attempt; the acknowledgment-withholding proxy did not actually withhold anything, " +
			"so this run measured nothing about the ambiguity it targets")
	}
}

// ---------------------------------------------------------------------------
// LED-013 — a keyed event's retry converges on the row that is actually
// there, not merely on "some" row.
// ---------------------------------------------------------------------------

func TestLED013AKeyedEventsRetryReturnsTheSameRowThatIsOnTheChain(t *testing.T) {
	c := requirePG(t)
	dsn := freshDSN(t, c)
	migrateDirect(t, dsn)

	store, proxyStop := openThroughAmbiguousCommitProxy(t, c, dsn)
	defer proxyStop()

	body := storeBody(913) // KEYED: idempotency_key "idem-00913", event_type tool_call.
	key, ok := body[event.FieldIdempotencyKey].(string)
	if !ok || key == "" {
		t.Fatalf("storeBody(913) carries no readable %s: %+v", event.FieldIdempotencyKey, body)
	}

	ctx := testCtx(t, 20*time.Second)
	record, err := store.Append(ctx, body)
	if err != nil {
		t.Fatalf("LED-013: Append of a KEYED event whose first commit's acknowledgment was "+
			"withheld returned an error instead of converging on retry: %v", err)
	}

	returnedEventID, idOK := record[event.FieldEventID].(string)
	returnedPosition, posOK := record[event.FieldChainPosition].(int64)
	if !idOK || returnedEventID == "" || !posOK || returnedPosition == 0 {
		t.Fatalf("LED-013: Append's returned record carries no readable event_id/chain_position: %+v", record)
	}

	admin := rawConn(t, dsn)
	rows, qerr := admin.Query(context.Background(),
		`SELECT event_id, chain_position FROM innsegl.events WHERE idempotency_key = $1`, key)
	if qerr != nil {
		t.Fatalf("query rows for key %q: %v", key, qerr)
	}
	defer rows.Close()

	type row struct {
		eventID  string
		position int64
	}
	var found []row
	for rows.Next() {
		var r row
		if serr := rows.Scan(&r.eventID, &r.position); serr != nil {
			t.Fatalf("scan row: %v", serr)
		}
		found = append(found, r)
	}
	if rerr := rows.Err(); rerr != nil {
		t.Fatalf("iterate rows: %v", rerr)
	}

	if len(found) != 1 {
		t.Fatalf("LED-013: idempotency_key %q names %d row(s) on the chain, want exactly 1 "+
			"(LED-008); found=%+v", key, len(found), found)
	}
	if found[0].eventID != returnedEventID || found[0].position != returnedPosition {
		t.Fatalf("LED-013: Append returned event_id=%s chain_position=%d, but the row actually "+
			"on the chain under key %q is event_id=%s chain_position=%d — the retry's readByKey "+
			"answered with something other than the row that is really there",
			returnedEventID, returnedPosition, key, found[0].eventID, found[0].position)
	}
	t.Logf("LED-013: one row, event_id=%s chain_position=%d, and Append's returned record "+
		"names exactly that row", found[0].eventID, found[0].position)
}

// ---------------------------------------------------------------------------
// Shared fixtures.
// ---------------------------------------------------------------------------

// unkeyedCredentialIssuedBody is a minimal, valid credential_issued body —
// ADR-0004: no idempotency_key, ever, on this event type.
func unkeyedCredentialIssuedBody(runID string) event.Fields {
	return event.Fields{
		event.FieldSchemaVersion:    event.SchemaVersion,
		event.FieldEventType:        event.EventTypeCredentialIssued,
		event.FieldSource:           event.SourceMCP,
		event.FieldRunID:            runID,
		event.FieldSpiffeID:         "spiffe://innsegl.dev/agent/led012/led012/" + runID,
		event.FieldAudience:         "sigstore",
		event.FieldCredentialExpiry: event.NewTimestamp(time.Now().Add(time.Minute)).String(),
	}
}

// migrateDirect runs Migrate over a plain, unproxied connection to dsn.
func migrateDirect(t *testing.T, dsn string) {
	t.Helper()
	ctx := testCtx(t, 60*time.Second)
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open (direct, for migration): %v", err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
}

// openThroughAmbiguousCommitProxy opens a Store whose connection to dsn's
// database runs through startAmbiguousCommitProxy, so the FIRST commit that
// store's own connections send is the one whose acknowledgment gets withheld.
func openThroughAmbiguousCommitProxy(t *testing.T, c *pgContainer, dsn string) (store *Store, stop func()) {
	t.Helper()
	// c.dsn(name) is "postgres://user:pass@127.0.0.1:<c.port>/name?...", and
	// dsn is exactly that for the database freshDSN created — so replacing
	// the real port with the proxy's is the whole of retargeting it.
	proxyAddr, proxyStop, err := startAmbiguousCommitProxy(t, "127.0.0.1:"+c.port)
	if err != nil {
		t.Fatalf("start ambiguous-commit proxy: %v", err)
	}
	_, proxyPort, serr := net.SplitHostPort(proxyAddr)
	if serr != nil {
		proxyStop()
		t.Fatalf("split proxy address %q: %v", proxyAddr, serr)
	}
	proxiedDSN := strings.Replace(dsn, "127.0.0.1:"+c.port, "127.0.0.1:"+proxyPort, 1)

	ctx := testCtx(t, 30*time.Second)
	store, err = Open(ctx, proxiedDSN)
	if err != nil {
		proxyStop()
		t.Fatalf("Open (via proxy): %v", err)
	}
	t.Cleanup(store.Close)
	return store, proxyStop
}

// startAmbiguousCommitProxy listens locally and forwards every connection to
// upstream, except for one thing: the FIRST time any connection sends the
// exact simple-query text "commit" (null-terminated in the wire message —
// distinguishing it from, say, "read committed" inside a preceding BEGIN
// ISOLATION LEVEL statement), that commit is let through, and the proxy
// WAITS for and confirms Postgres's reply to it before withholding that
// reply from the client and severing the connection. Every commit after the
// first, on any connection, passes through untouched — including a retry's,
// which must not itself be sabotaged, or nothing would distinguish "the
// retry produced a duplicate" from "the retry could not complete at all".
//
// The server->client direction has exactly ONE reader per connection (never
// a second goroutine racing it), which is what makes the withhold decision
// race-free: the per-connection flag is set by the client->server goroutine
// synchronously with writing "commit" to the server, strictly before the
// server can possibly have finished processing and replying to it, so the
// very next chunk read off server — checked AFTER the read returns, never
// before — is the commit's own response, and is the one withheld.
func startAmbiguousCommitProxy(t *testing.T, upstream string) (addr string, stop func(), err error) {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	var claimed atomic.Bool // global, one-shot: only the first commit anywhere is sabotaged.
	go func() {
		for {
			client, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go ambiguousCommitProxyConn(client, upstream, &claimed)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }, nil
}

func ambiguousCommitProxyConn(client net.Conn, upstream string, claimed *atomic.Bool) {
	defer client.Close()
	var d net.Dialer
	server, err := d.DialContext(context.Background(), "tcp", upstream)
	if err != nil {
		return
	}
	defer server.Close()

	var mine atomic.Bool // true iff THIS connection's commit is the sabotaged one.
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, rerr := client.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				if strings.Contains(strings.ToLower(string(chunk)), "commit\x00") &&
					claimed.CompareAndSwap(false, true) {
					if _, werr := server.Write(chunk); werr != nil {
						return
					}
					mine.Store(true)
					continue
				}
				if _, werr := server.Write(chunk); werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	buf := make([]byte, 32*1024)
	for {
		n, rerr := server.Read(buf)
		if n > 0 {
			if mine.Load() {
				return // client.Close() runs via defer; the reply is never forwarded.
			}
			if _, werr := client.Write(buf[:n]); werr != nil {
				return
			}
		}
		if rerr != nil {
			return
		}
	}
}
