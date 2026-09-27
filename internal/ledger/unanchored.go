// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"

	"innsegl.dev/innsegl/internal/event"
)

// UnanchoredSeals returns every segment_sealed event that carries no anchor
// and has no later anchored segment_sealed for the same first_position, in
// chain order. It is the sealer's backlog (RM-204, #327): the sealer's
// backward walk stops at the latest seal, so a segment sealed before that and
// never anchored is found here or nowhere.
//
// One statement over the event_type index. The anchoring members are read out
// of the stored canonical bytes, the same way ResolveDriftAlerts reads
// subject_event_id; the appender role already holds SELECT on
// innsegl.events.
func (s *Store) UnanchoredSeals(ctx context.Context) ([]event.Fields, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT s.canonical
		  FROM innsegl.events s
		 WHERE s.event_type = 'segment_sealed'
		   AND NOT (convert_from(s.canonical, 'UTF8')::jsonb ? 'anchor_rekor_entry_uuid')
		   AND NOT EXISTS (
		       SELECT 1
		         FROM innsegl.events a
		        WHERE a.event_type = 'segment_sealed'
		          AND a.chain_position > s.chain_position
		          AND convert_from(a.canonical, 'UTF8')::jsonb ? 'anchor_rekor_entry_uuid'
		          AND convert_from(a.canonical, 'UTF8')::jsonb->'first_position'
		              = convert_from(s.canonical, 'UTF8')::jsonb->'first_position')
		 ORDER BY s.chain_position`)
	if err != nil {
		return nil, classify("unanchored seals", err)
	}
	defer rows.Close()

	out := []event.Fields{}
	for rows.Next() {
		var canonical []byte
		if err := rows.Scan(&canonical); err != nil {
			return nil, classify("unanchored seals", err)
		}
		record, err := decode(canonical)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	if err := rows.Err(); err != nil {
		return nil, classify("unanchored seals", err)
	}
	return out, nil
}
