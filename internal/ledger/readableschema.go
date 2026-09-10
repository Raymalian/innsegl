// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"innsegl.dev/innsegl/internal/event"
)

// AssertReadableSchema refuses a chain that has been migrated past this build.
//
// # Why a verifier asks this once rather than per event
//
// doc 02 §1 has a verifier TOLERATE unknown members when an event's
// schema_version is newer than its own, and that is right per event: the
// alternative is that every deployed verifier breaks on the day a new version
// ships, which would make shipping one impossible.
//
// It is not right at startup. A verifier serving verdicts over a chain that
// has moved past it cannot fully check any event after the cutover — it does
// not know what the new version requires, so "every required member is
// present" is a claim it is in no position to make — and it would go on making
// that claim, silently and with the same confidence as any other. The E9 epic
// puts it as an exit criterion: "a verifier refuses to start if it cannot read
// both."
//
// The chain answers the question itself. doc 08 §3(c) requires a
// `schema_migrated` attestation naming the cutover, so a verifier reads the
// attestations once at startup and knows, rather than inferring version
// boundaries from the events as it goes.
//
// # What it does NOT do
//
// It does not refuse an OLDER version, ever. Reading version 1 is the whole of
// doc 08's "accepted alongside all previous ones, without exception", and a
// chain that has been migrated is by construction a chain full of older
// events. Only a version this build has never heard of is a refusal.
func (s *Store) AssertReadableSchema(ctx context.Context) error {
	return AssertReadableSchema(ctx, s.pool)
}

// AssertReadableSchema is the method's body, over any pool.
//
// Exported over a pool rather than kept to the Store because the READ-ONLY
// query API (internal/api) has a pool and no *Store, and it is the verifier
// that most needs the check -- it is the surface a third party asks for a
// verdict. Duplicating the query there would be three easy lines and one
// decision that could drift; the decision is event.CanRead's, and it is made
// once.
func AssertReadableSchema(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx,
		`SELECT canonical FROM innsegl.events
		  WHERE event_type = $1
		  ORDER BY chain_position`, event.EventTypeSchemaMigrated)
	if err != nil {
		return classify("assert_readable_schema", err)
	}
	defer rows.Close()

	for rows.Next() {
		var canonical []byte
		if serr := rows.Scan(&canonical); serr != nil {
			return classify("assert_readable_schema", serr)
		}
		record, derr := decode(canonical)
		if derr != nil {
			return derr
		}

		to, ok := record[event.FieldToSchemaVersion].(string)
		if !ok {
			return &StoreError{
				Class: ClassInvariantViolation, Op: "assert_readable_schema", Retryable: false,
				Err: fmt.Errorf("a %s event names no to_schema_version",
					event.EventTypeSchemaMigrated),
			}
		}
		readable, rerr := event.CanRead(to)
		if rerr != nil {
			return &StoreError{
				Class: ClassInvariantViolation, Op: "assert_readable_schema", Retryable: false,
				Err: fmt.Errorf("a %s event names %q as its target: %w",
					event.EventTypeSchemaMigrated, to, rerr),
			}
		}
		if !readable {
			return &StoreError{
				Class: ClassInvariantViolation, Op: "assert_readable_schema", Retryable: false,
				Err: fmt.Errorf(
					"this chain was migrated to schema_version %q at position %v, and this "+
						"build reads up to %q. Every event at or after the cutover carries "+
						"members it cannot check, so it would answer questions about them "+
						"without being able to. Upgrade the binary; the chain is not at fault "+
						"and nothing about it needs changing",
					to, record[event.FieldCutoverPosition], event.SchemaVersion),
			}
		}
	}
	return rows.Err()
}
