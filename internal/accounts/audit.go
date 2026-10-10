// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// The audit trail's read (RM-303, #482). Every write in this package appends
// its rows in the transaction that makes the change (appendAudit); the table
// refuses UPDATE, DELETE and TRUNCATE to every role (migration 0010).

// AuditRecord is one row of innsegl_auth.audit as it reads back.
type AuditRecord struct {
	ID        int64
	At        time.Time
	Actor     string // empty: the system or the operator's CLI
	AccountID string
	Action    string
	Subject   string
	Detail    map[string]any
}

// AuditLog answers the trail newest first: one account's, or every row when
// accountID is empty. limit <= 0 is no limit.
func (s *Store) AuditLog(ctx context.Context, accountID string, limit int) ([]AuditRecord, error) {
	var lim *int
	if limit > 0 {
		lim = &limit
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, at, coalesce(actor, ''), coalesce(account_id, ''), action, subject, detail
		  FROM innsegl_auth.audit
		 WHERE $1 = '' OR account_id = $1
		 ORDER BY id DESC
		 LIMIT $2`, accountID, lim)
	if err != nil {
		return nil, fmt.Errorf("accounts: reading the audit trail: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (AuditRecord, error) {
		var (
			r   AuditRecord
			raw []byte
		)
		if err := row.Scan(&r.ID, &r.At, &r.Actor, &r.AccountID, &r.Action, &r.Subject, &raw); err != nil {
			return r, err
		}
		if err := json.Unmarshal(raw, &r.Detail); err != nil {
			return r, fmt.Errorf("accounts: audit row %d detail: %w", r.ID, err)
		}
		return r, nil
	})
}
