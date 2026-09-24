// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"

	"innsegl.dev/innsegl/internal/event"
)

// Adoption is one run_adopted event (ADR-0051), and whether the commit it was
// for was recorded.
type Adoption struct {
	// EventID is the run_adopted event.
	EventID string
	// RunID is the adopting run.
	RunID string
	// PayloadDigest is the digest of the claim, stored as a body under RunID.
	PayloadDigest string
	// Committed is whether a commit_recorded completes an intent naming this
	// adoption. An adoption whose commit never landed is not spent.
	Committed bool
}

// AdoptionsOf returns every adoption of one dead run, by any run, in chain
// order: the read behind ADR-0051 decision 6, that an adoption is spent by its
// commit.
//
// It walks the chain once, for RunsForPatchID's reason: the link is three
// events long (run_adopted, then the intent naming it, then the recorded event
// naming the intent) and each is appended after the one it names, so a single
// pass in chain order resolves all of it.
func (s *Store) AdoptionsOf(ctx context.Context, adoptedRun string) ([]Adoption, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT canonical FROM innsegl.events
		  WHERE event_type = ANY($1)
		  ORDER BY chain_position`,
		[]string{event.EventTypeRunAdopted, event.EventTypeCommitIntent, event.EventTypeCommitRecorded})
	if err != nil {
		return nil, classify("adoptions_of", err)
	}
	defer rows.Close()

	var out []Adoption
	index := map[string]int{}    // run_adopted event id -> position in out
	intentOf := map[string]int{} // commit_intent event id -> position in out
	for rows.Next() {
		var canonical []byte
		if serr := rows.Scan(&canonical); serr != nil {
			return nil, classify("adoptions_of", serr)
		}
		record, derr := decode(canonical)
		if derr != nil {
			return nil, derr
		}
		// Strings by the time an event is in the chain: the schema is closed
		// and validated at append.
		id, _ := record[event.FieldEventID].(string) //nolint:errcheck // see above
		switch record[event.FieldEventType] {
		case event.EventTypeRunAdopted:
			if dead, _ := record[event.FieldAdoptedRunID].(string); dead != adoptedRun { //nolint:errcheck // see above
				continue
			}
			runID, _ := record[event.FieldRunID].(string)          //nolint:errcheck // see above
			digest, _ := record[event.FieldPayloadDigest].(string) //nolint:errcheck // see above
			index[id] = len(out)
			out = append(out, Adoption{EventID: id, RunID: runID, PayloadDigest: digest})
		case event.EventTypeCommitIntent:
			adoption, _ := record[event.FieldAdoptionEventID].(string) //nolint:errcheck // see above
			if i, ok := index[adoption]; ok {
				intentOf[id] = i
			}
		case event.EventTypeCommitRecorded:
			intent, _ := record[event.FieldIntentEventID].(string) //nolint:errcheck // see above
			if i, ok := intentOf[intent]; ok {
				out[i].Committed = true
			}
		}
	}
	if rerr := rows.Err(); rerr != nil {
		return nil, classify("adoptions_of", rerr)
	}
	return out, nil
}
