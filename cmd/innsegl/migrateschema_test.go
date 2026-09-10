// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// LED-035 and LED-036 (proposed for doc 07; doc 07 is not modified here) —
// RM-119, #191.
//
// doc 08 §3(c) is one of four things a MAJOR release owes, and the only one
// that lands in the ledger rather than in the repository: "a signed migration
// attestation event appended to the ledger, marking the exact chain position
// of the cutover".
//
// doc 02 §3 says what it holds — `from_schema_version`, `to_schema_version`,
// `cutover_position` — and what it means: "Events at or after cutover_position
// are to_schema_version; everything before stays valid under its own (I4)."
// Without it a verifier reading a chain that spans a bump has to INFER where
// the versions change, from the events themselves, which is exactly the kind of
// inference an attested chain exists to remove.

// TestLED035TheAttestationNamesThePositionItOccupies.
//
// `cutover_position` is the position of the first event carrying the new
// version, and the attestation is that event — it is appended before anything
// else writes v2, so the position it names is its own. Any other arrangement
// needs the operator to know a position before it exists.
func TestLED035TheAttestationNamesThePositionItOccupies(t *testing.T) {
	dsn, _ := freshLedgerDB(t)
	ctx := t.Context()
	store := openLedgerForTest(t, dsn)

	head, err := store.Head(ctx)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}

	var out, errOut bytes.Buffer
	if code := runMigrateSchemaCommand([]string{"-dsn", dsn}, &out, &errOut); code != exitOK {
		t.Fatalf("migrate-schema = %d, want %d\n%s", code, exitOK, errOut.String())
	}

	events, err := store.Events(ctx, head.Position+1, head.Position+1)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("the chain grew by %d events, want 1", len(events))
	}
	att := events[0]

	if got := att[event.FieldEventType]; got != event.EventTypeSchemaMigrated {
		t.Fatalf("appended a %v, want a %s", got, event.EventTypeSchemaMigrated)
	}
	if got := att[event.FieldSource]; got != event.SourceSystem {
		t.Errorf("source = %v, want %s (doc 02 §3)", got, event.SourceSystem)
	}
	if got := att[event.FieldToSchemaVersion]; got != event.SchemaVersion {
		t.Errorf("to_schema_version = %v, want %q", got, event.SchemaVersion)
	}
	position, ok := att[event.FieldChainPosition].(int64)
	if !ok {
		t.Fatalf("chain_position is %T, not an integer", att[event.FieldChainPosition])
	}
	cutover, ok := att[event.FieldCutoverPosition].(int64)
	if !ok {
		t.Fatalf("cutover_position is %T, not an integer", att[event.FieldCutoverPosition])
	}
	if cutover != position {
		t.Errorf("the attestation sits at position %d and names %d as the cutover; "+
			"it is the first event carrying schema %s, so the position it names is "+
			"its own or it names nothing", position, cutover, event.SchemaVersion)
	}
	if _, hasRun := att[event.FieldRunID]; hasRun {
		t.Error("the attestation names a run; a schema bump is a property of the " +
			"chain, not of anything an agent did (doc 02 §3)")
	}
}

// TestLED036TheAttestationCanOnlyBeWrittenOnce is the epic's exit criterion:
// "The chain holds one schema_migrated naming the exact position where the
// change took effect, and it can only ever be written once."
//
// Enforced by the ledger and not by this command: the attestation carries a
// deterministic idempotency_key, and `idempotency_key` is UNIQUE in
// innsegl.events. So a second run — a retried deployment step, a second
// operator, two replicas of a job — cannot append a second attestation even if
// this command's own check were removed. That is the same reasoning ADR-0004
// gives for making retirement idempotent in the database rather than in the
// caller: a check and an append are two steps, and a crash fits between them.
func TestLED036TheAttestationCanOnlyBeWrittenOnce(t *testing.T) {
	dsn, _ := freshLedgerDB(t)
	ctx := t.Context()
	store := openLedgerForTest(t, dsn)

	var out, errOut bytes.Buffer
	if code := runMigrateSchemaCommand([]string{"-dsn", dsn}, &out, &errOut); code != exitOK {
		t.Fatalf("the first migrate-schema failed: %d\n%s", code, errOut.String())
	}
	after, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}

	out.Reset()
	errOut.Reset()
	code := runMigrateSchemaCommand([]string{"-dsn", dsn}, &out, &errOut)
	if code != exitOK {
		t.Fatalf("a repeated migrate-schema = %d, want %d: a cutover already attested "+
			"is the desired state, and reporting it as a failure would make a "+
			"retried deployment step look like a broken one\n%s",
			code, exitOK, errOut.String())
	}
	if !strings.Contains(out.String()+errOut.String(), "already") {
		t.Errorf("said nothing about the attestation already existing:\n%s%s",
			out.String(), errOut.String())
	}

	again, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if again != after {
		t.Errorf("the chain grew from %d to %d events on a repeat; a second "+
			"attestation would give the chain two answers about where the cutover was",
			after, again)
	}
}

// openLedgerForTest opens a store on an already-migrated database.
func openLedgerForTest(t *testing.T, dsn string) *ledger.Store {
	t.Helper()
	store, err := ledger.Open(t.Context(), dsn)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(store.Close)
	return store
}
