// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"innsegl.dev/innsegl/internal/event"
)

// RunsForPatchID returns every run that recorded a given change (ADR-0047,
// RM-121, #193).
//
// # Why the key is the change and never the run
//
// This is the read behind verifying a rewritten commit: the verifier holds a
// commit whose signature a rebase destroyed, computes the change it makes, and
// asks who recorded it. Keying the lookup on the run the COMMIT CLAIMS would
// let the claim choose the evidence it is checked against — ask for run X's
// records, find one, conclude run X made this. Keyed on the change, the ledger
// answers who actually made it and the verifier compares.
//
// # Both `commit_intent` and `commit_recorded`
//
// The intent records the change before the signature exists and the recorded
// event after; a chain that crashed between them (IP §6.5's A → B window) holds
// only the first. A verifier that read only `commit_recorded` would report "the
// content changed" for a change that was signed and whose phase C the
// reconciler has not yet repaired, which is a wrong answer about a real
// signature.
//
// # The shape of the answer
//
// Every match, never one. A patch id identifies a change and not its maker, so
// the same change made twice by two agents has one id. Returning a single row
// would mean picking one of them and calling it the author.
func (s *Store) RunsForPatchID(ctx context.Context, patchID string) ([]ContentRecord, error) {
	return RunsForPatchID(ctx, s.pool, patchID)
}

// RunsForPatchID is the method's body over any pool.
//
// Exported over a pool for AssertReadableSchema's reason: the READ-ONLY query
// API (internal/api) is the surface that serves verdicts to strangers, and it
// holds a pool and no *Store. One query, one place it can be wrong.
func RunsForPatchID(ctx context.Context, pool *pgxpool.Pool, patchID string) ([]ContentRecord, error) {
	if patchID == "" {
		return nil, &StoreError{
			Class: ClassInvariantViolation, Op: "runs_for_patch_id", Retryable: false,
			Err: fmt.Errorf("an empty patch id names no change; every event that carries " +
				"none would match, which answers a question nobody asked"),
		}
	}

	rows, err := pool.Query(ctx,
		`SELECT canonical FROM innsegl.events
		  WHERE event_type = ANY($1)
		  ORDER BY chain_position`,
		[]string{event.EventTypeCommitIntent, event.EventTypeCommitRecorded})
	if err != nil {
		return nil, classify("runs_for_patch_id", err)
	}
	defer rows.Close()

	var out []ContentRecord
	seen := map[string]bool{}
	for rows.Next() {
		var canonical []byte
		if serr := rows.Scan(&canonical); serr != nil {
			return nil, classify("runs_for_patch_id", serr)
		}
		record, derr := decode(canonical)
		if derr != nil {
			return nil, derr
		}
		if got, isString := record[event.FieldPatchID].(string); !isString || got != patchID {
			continue
		}
		runID, isString := record[event.FieldRunID].(string)
		if !isString {
			continue
		}
		if runID == "" || seen[runID] {
			// One row per run. A run's intent and its recorded event name the
			// same change, and a verifier asking "did this run make this
			// change" is answered once.
			continue
		}
		seen[runID] = true

		// Both are strings by the time an event is in the chain -- the schema
		// is closed and validated at append -- so a wrong type here means the
		// stored bytes are not what they claim, and an empty string in the
		// answer is the honest report of that.
		eventID, _ := record[event.FieldEventID].(string) //nolint:errcheck // see above
		sha, _ := record[event.FieldCommitSHA].(string)   //nolint:errcheck // see above
		out = append(out, ContentRecord{
			RunID:     runID,
			PatchID:   patchID,
			CommitSHA: sha,
			EventID:   eventID,
		})
	}
	return out, rows.Err()
}

// ContentRecord is one run's record of one change.
//
// Declared here rather than imported from internal/verify, and the dependency
// runs the other way for a reason this package cares about: internal/verify
// holds no database and must keep holding none (VER-001 verifies with the
// ledger unreachable). It defines the interface it needs; this satisfies it.
type ContentRecord struct {
	RunID     string
	PatchID   string
	CommitSHA string
	EventID   string
}

// HoldsAnyPatchID reports whether this chain has ever recorded a change
// identity.
//
// # Why a gate asks this before it asks anything else
//
// `patch_id` arrives with schema 2 (ADR-0047). A deployment that has not been
// upgraded writes `commit_recorded` without one, and every commit it signed is
// therefore outside the content scheme — not because the content changed, but
// because nothing ever recorded what the content was.
//
// Measured on this deployment on 2026-09-10: 126 `commit_recorded` events, none
// carrying a patch id. A content check run against that chain would report every
// one of those commits as unattributable, which is a false accusation about 126
// genuine signatures. Asking once, up front, turns that into a single sentence
// about the deployment.
//
// LIMIT 1 on an index-free predicate is deliberate: the answer is "has this ever
// happened", so the first row that carries one ends the scan.
func HoldsAnyPatchID(ctx context.Context, pool *pgxpool.Pool) (bool, error) {
	var recorded bool
	err := pool.QueryRow(ctx,
		`SELECT EXISTS (
		     SELECT 1 FROM innsegl.events
		      WHERE event_type = ANY($1)
		        AND convert_from(canonical, 'UTF8')::jsonb ? 'patch_id'
		      LIMIT 1)`,
		[]string{event.EventTypeCommitIntent, event.EventTypeCommitRecorded}).Scan(&recorded)
	if err != nil {
		return false, classify("holds_any_patch_id", err)
	}
	return recorded, nil
}

// SchemaSpan reports where a schema version's events begin and whether any
// event at or after that position carries a different one.
//
// # Why the cutover is FOUND rather than assumed
//
// `innsegl migrate-schema` used to compute the cutover as head + 1 and require
// the attestation to land exactly there, which is only correct when it runs
// before a single upgraded writer starts. On 2026-09-10 the deployment was
// rebuilt first and eight schema 2 events landed before anyone thought about
// the attestation. head + 1 would then have recorded a boundary with events of
// the new version on the wrong side of it — a false statement in a chain that
// cannot be edited.
//
// doc 02 §3 defines `cutover_position` as "the position where events begin
// carrying the new version". That is a fact about the chain, and the chain can
// be asked.
//
// `mixed` is the guard: if anything at or after `first` carries a different
// version, then no single position separates the two and the attestation would
// be wrong however it was computed. An operator has to see that rather than
// have a number chosen for them.
func SchemaSpan(ctx context.Context, pool *pgxpool.Pool, version string) (first int64, mixed bool, err error) {
	if version == "" {
		return 0, false, &StoreError{
			Class: ClassInvariantViolation, Op: "schema_span", Retryable: false,
			Err: fmt.Errorf("an empty schema_version names no version"),
		}
	}

	var found *int64
	if qerr := pool.QueryRow(ctx,
		`SELECT min(chain_position) FROM innsegl.events
		  WHERE convert_from(canonical, 'UTF8')::jsonb->>'schema_version' = $1`,
		version).Scan(&found); qerr != nil {
		return 0, false, classify("schema_span", qerr)
	}
	if found == nil {
		return 0, false, nil
	}

	var others int64
	if qerr := pool.QueryRow(ctx,
		`SELECT count(*) FROM innsegl.events
		  WHERE chain_position >= $1
		    AND convert_from(canonical, 'UTF8')::jsonb->>'schema_version' <> $2`,
		*found, version).Scan(&others); qerr != nil {
		return 0, false, classify("schema_span", qerr)
	}
	return *found, others > 0, nil
}

// Pool exposes the connection pool for the reads this package offers over one.
//
// Narrow on purpose: the pool-taking functions here exist because the read-only
// query API holds a pool and no *Store, and a caller that already has a *Store
// should not have to build a second one to reach them.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }
