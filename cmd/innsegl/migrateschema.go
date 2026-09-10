// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// `innsegl migrate-schema` — doc 08 §3(c)'s migration attestation (RM-119,
// #191).
//
// # What a major schema release owes, and which part this is
//
// doc 08 §3 lists four things a MAJOR release must ship together: (a) a new
// schema_version accepted alongside all previous ones forever, (b) updated
// golden fixtures with the old set retained, (c) a signed migration attestation
// appended to the ledger marking the exact chain position of the cutover, and
// (d) a superseding ADR. (a), (b) and (d) live in the repository and are
// checked by tests and by scripts/protected-surfaces.sh. (c) lives in the
// LEDGER, one per deployment, and no amount of testing this repository can
// produce it — an operator has to append it to their own chain, which is what
// this command is.
//
// # Why the attestation is the first event of the new version
//
// doc 02 §3: "Events at or after cutover_position are to_schema_version;
// everything before stays valid under its own." So `cutover_position` is the
// position of the first event carrying the new version, and the only way to
// name that position without guessing it is to BE it. Run this before the
// upgraded writers start, and the position it names is its own.
//
// A verifier then needs no heuristic: it reads one event and knows where the
// versions change. Without it, "which version was this chain writing at
// position 900412" is answered by inspecting position 900412 — which is
// exactly the sort of inference an attested chain exists to remove.
//
// # Records are never migrated in place
//
// doc 08: "Old events remain valid under their own schema_version eternally;
// 'upgrade' means new events use the new version, never that old bytes
// change." This command reads the head, writes ONE event, and touches nothing
// else. It is not a data migration and there is no data migration; the schema
// bump is a fact about the future of the chain, and I4 makes it impossible for
// it to be anything else.

// migrateSchemaKey is the attestation's idempotency key, and it is what makes
// the cutover exactly-once.
//
// Deterministic from the version pair, so a retried deployment step, a second
// operator, or two replicas of a job all compute the same key — and
// `idempotency_key` is UNIQUE in innsegl.events, so the second append resolves
// to the first event rather than writing another. The check below is a
// courtesy that produces a good message; the constraint is what makes it true,
// for the reason ADR-0004 gives about retirement: a check and an append are two
// steps and a crash fits between them.
func migrateSchemaKey(from, to string) string {
	return "schema:migrated:" + from + "->" + to
}

// migrateSchemaCommand is the subcommand body wired into cli.go's dispatch.
func migrateSchemaCommand(args []string, stdout, stderr io.Writer) int {
	return runMigrateSchemaCommand(args, stdout, stderr)
}

func runMigrateSchemaCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("innsegl migrate-schema", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		dsn = fs.String("dsn", os.Getenv(envLedgerDSN),
			"ledger connection string — prefer the environment variable ($"+envLedgerDSN+")")
		from = fs.String("from", "1",
			"the schema_version this chain was writing before the cutover")
	)

	fs.Usage = func() {
		fprintf(stderr, "innsegl migrate-schema - attest a major schema cutover (doc 08 §3(c))\n\n")
		fprintf(stderr, "Usage:\n  innsegl migrate-schema [flags]\n\n")
		fprintf(stderr, "Appends ONE %s event naming the position where this chain begins\n",
			event.EventTypeSchemaMigrated)
		fprintf(stderr, "carrying schema_version %q. Run it BEFORE starting the upgraded\n",
			event.SchemaVersion)
		fprintf(stderr, "writers: the position it names is its own, so anything appended\n")
		fprintf(stderr, "first would make it name the wrong one.\n\n")
		fprintf(stderr, "Nothing is migrated. Old events stay valid under their own\n")
		fprintf(stderr, "schema_version forever (doc 08, I4); this records where the\n")
		fprintf(stderr, "boundary is so a verifier does not have to infer it.\n\n")
		fprintf(stderr, "Running it twice is safe and appends nothing the second time.\n\n")
		fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		fprintf(stderr, "innsegl migrate-schema: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return exitUsage
	}
	if *dsn == "" {
		fprintf(stderr, "innsegl migrate-schema: -dsn (or $%s) is required\n", envLedgerDSN)
		return exitUsage
	}
	if *from == event.SchemaVersion {
		fprintf(stderr, "innsegl migrate-schema: -from %q is the version this build emits; "+
			"an attestation from a version to itself records no cutover\n", *from)
		return exitUsage
	}

	ctx := context.Background()

	// Open, never Migrate. This command is not the schema's owner: a cutover
	// attested into a database this command had just created would attest a
	// chain nobody is writing to.
	store, err := ledger.Open(ctx, *dsn)
	if err != nil {
		fprintf(stderr, "innsegl migrate-schema: open the ledger: %v\n", err)
		return exitReapInconclusive
	}
	defer store.Close()

	key := migrateSchemaKey(*from, event.SchemaVersion)
	if existing, found, ferr := store.EventByIdempotencyKey(ctx, key); ferr != nil {
		fprintf(stderr, "innsegl migrate-schema: reading the attestation: %v\n", ferr)
		return exitReapInconclusive
	} else if found {
		fprintf(stdout, "innsegl migrate-schema: schema %s -> %s is already attested at "+
			"position %v (event %v); nothing appended\n",
			*from, event.SchemaVersion,
			existing[event.FieldCutoverPosition], existing[event.FieldEventID])
		return exitOK
	}

	// THE CUTOVER IS FOUND, NOT ASSUMED.
	//
	// It used to be head + 1, which is right only when this runs before a
	// single upgraded writer starts. On 2026-09-10 this deployment was rebuilt
	// first and eight schema 2 events landed before anyone reached for the
	// attestation; head + 1 would then have recorded a boundary with events of
	// the new version on the wrong side of it, in a chain that cannot be
	// edited. doc 02 §3 defines cutover_position as "the position where events
	// begin carrying the new version" — a fact about the chain, so the chain
	// is asked.
	cutover, mixed, err := ledger.SchemaSpan(ctx, store.Pool(), event.SchemaVersion)
	if err != nil {
		fprintf(stderr, "innsegl migrate-schema: finding the cutover: %v\n", err)
		return exitReapInconclusive
	}
	if mixed {
		fprintf(stderr, "innsegl migrate-schema: REFUSED — this chain interleaves "+
			"schema %s with an earlier version after position %d, so no single "+
			"position separates them and any cutover_position would be wrong. "+
			"Stop the writers still emitting the old version, then run this again.\n",
			event.SchemaVersion, cutover)
		return exitReapIncomplete
	}
	if cutover == 0 {
		// Nothing of the new version yet: this is the documented order, run
		// before the upgraded writers, and the attestation is itself the first
		// event to carry it.
		head, herr := store.Head(ctx)
		if herr != nil {
			fprintf(stderr, "innsegl migrate-schema: reading the head: %v\n", herr)
			return exitReapInconclusive
		}
		cutover = head.Position + 1
	}

	record, err := store.Append(ctx, event.Fields{
		event.FieldSchemaVersion:     event.SchemaVersion,
		event.FieldEventType:         event.EventTypeSchemaMigrated,
		event.FieldSource:            event.SourceSystem,
		event.FieldIdempotencyKey:    key,
		event.FieldFromSchemaVersion: *from,
		event.FieldToSchemaVersion:   event.SchemaVersion,
		event.FieldCutoverPosition:   cutover,
	})
	if err != nil {
		fprintf(stderr, "innsegl migrate-schema: appending the attestation: %v\n", err)
		return exitReapInconclusive
	}

	// The position it NAMES must be the position it GOT. They differ only if
	// something appended between the head read and this write, and then the
	// attestation is wrong by one — a fact an operator has to see, because I4
	// means it cannot be deleted and only a superseding attestation can
	// correct it.
	landed, ok := record[event.FieldChainPosition].(int64)
	if !ok {
		fprintf(stderr, "innsegl migrate-schema: the ledger stored the attestation "+
			"without an integer chain_position (%T); it cannot be confirmed to name "+
			"a position at all\n", record[event.FieldChainPosition])
		return exitReapIncomplete
	}
	// The attestation may land after the cutover it names -- that is the case
	// where the writers were upgraded first -- but never BEFORE it, which
	// would claim a boundary that had not happened yet.
	if landed < cutover {
		fprintf(stderr, "innsegl migrate-schema: INCONSISTENT - the attestation names "+
			"position %d as the cutover and landed at %d, which is before it. I4 "+
			"forbids removing it; append a superseding one with the writers "+
			"stopped.\n", cutover, landed)
		return exitReapIncomplete
	}

	fprintf(stdout, "innsegl migrate-schema: schema %s -> %s attested: the cutover is "+
		"position %d, recorded by event %v at position %d\n",
		*from, event.SchemaVersion, cutover, record[event.FieldEventID], landed)
	fprintf(stdout, "  Events before %d stay valid under schema %s, forever (doc 08, I4).\n",
		cutover, *from)
	return exitOK
}
