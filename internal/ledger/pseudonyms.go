// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/identity"
)

// Repository pseudonyms on the append path, and the reads that resolve them
// (ADR-0080).
//
// # One place hides, every reader resolves
//
// Every writer hands the ledger the literal repository and branch it was
// given, exactly as before schema 5. The ledger is the one place that decides
// what the chain records: under a pseudonymous store it replaces each literal
// with its pseudonym and writes the alias that resolves it, in the append's
// own transaction. A writer cannot forget to hide a name, because no writer
// hides one.
//
// A value that is already a pseudonym passes through untouched: the
// reconciler copies an intent's repo onto its repair, and that value may have
// been made under an older key.
//
// Readers resolve: innsegl.resolve_alias in SQL, ResolveNames and
// ResolveRecord in Go. Erasure is not here: the ledger appends and nothing
// else (I4), so deleting an alias is internal/erasure's, run as the owner. Neither needs the key. An erased pseudonym resolves to
// itself, which every reader shows as an erased name rather than a blank.

// UseRepositories sets what this store writes for repo and branch. nil, or a
// literal Repositories, writes the literal. It is set once, before the first
// append; a store is shared by every writer in a process.
func (s *Store) UseRepositories(r *identity.Repositories) { s.repos.Store(r) }

// alias is one innsegl.pseudonyms row an append must write.
type alias struct {
	value, kind, literal, repoValue, keyID string
}

// pseudonymise rewrites p's repo and branch under a pseudonymous store and
// collects the aliases its transaction must write.
func (s *Store) pseudonymise(p *pending) error {
	r := s.repos.Load()
	if r == nil || r.Mode() != identity.ModePseudonymous {
		return nil
	}
	repo, hasRepo := p.body[event.FieldRepo].(string)
	branch, hasBranch := p.body[event.FieldBranch].(string)
	reject := func(err error) error {
		return &StoreError{Class: ClassInvariantViolation, Op: "append", Retryable: false, Err: err}
	}

	// The repository first: the branch is keyed by its literal, and its alias
	// names the repository's pseudonym.
	var repoPN string
	if hasRepo && !event.IsPseudonym(repo) {
		pn, err := r.Repo(repo)
		if err != nil {
			return reject(err)
		}
		repoPN = pn
		p.aliases = append(p.aliases, alias{value: pn, kind: "repo", literal: repo, keyID: r.KeyID()})
		p.body[event.FieldRepo] = pn
	}
	if hasBranch && !event.IsPseudonym(branch) {
		if repoPN == "" {
			// A branch is keyed by its repository's literal, which this
			// append does not have.
			return reject(fmt.Errorf("a literal branch %q beside no literal repository cannot be "+
				"pseudonymised (ADR-0080 decision 1)", branch))
		}
		pn, err := r.Branch(repo, branch)
		if err != nil {
			return reject(err)
		}
		if pn != branch {
			p.aliases = append(p.aliases, alias{value: pn, kind: "branch", literal: branch,
				repoValue: repoPN, keyID: r.KeyID()})
			p.body[event.FieldBranch] = pn
		}
	}
	return nil
}

// insertAliases writes an append's aliases inside its transaction. A value
// already present is left as it is; one erased earlier is written again,
// because erasure removes a past name and does not ban future use.
func insertAliases(ctx context.Context, tx pgx.Tx, aliases []alias) error {
	for _, a := range aliases {
		var repoValue *string
		if a.repoValue != "" {
			repoValue = &a.repoValue
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO innsegl.pseudonyms (value, kind, literal, repo_value, key_id)
			 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (value) DO NOTHING`,
			a.value, a.kind, a.literal, repoValue, a.keyID); err != nil {
			return classify("append", err)
		}
	}
	return nil
}

// ResolveNames answers each pseudonym's literal, and maps every other value
// (a literal, or a pseudonym whose alias was erased) to itself.
func (s *Store) ResolveNames(ctx context.Context, values ...string) (map[string]string, error) {
	out := make(map[string]string, len(values))
	var ask []string
	for _, v := range values {
		out[v] = v
		if event.IsPseudonym(v) {
			ask = append(ask, v)
		}
	}
	if len(ask) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT value, literal FROM innsegl.pseudonyms WHERE value = ANY($1)`, ask)
	if err != nil {
		return nil, classify("resolve_names", err)
	}
	defer rows.Close()
	for rows.Next() {
		var v, l string
		if err := rows.Scan(&v, &l); err != nil {
			return nil, classify("resolve_names", err)
		}
		out[v] = l
	}
	if err := rows.Err(); err != nil {
		return nil, classify("resolve_names", err)
	}
	return out, nil
}

// ResolveRecord returns a copy of f with repo and branch replaced by what
// names resolves them to. It is for READING: the result is not the chain's
// bytes and is never hashed, verified or appended.
func ResolveRecord(f event.Fields, names map[string]string) event.Fields {
	out := f.Clone()
	for _, m := range []string{event.FieldRepo, event.FieldBranch} {
		if v, ok := out[m].(string); ok {
			if l, found := names[v]; found {
				out[m] = l
			}
		}
	}
	return out
}

// Resolved is ResolveNames and ResolveRecord for one record.
func (s *Store) Resolved(ctx context.Context, f event.Fields) (event.Fields, error) {
	var values []string
	for _, m := range []string{event.FieldRepo, event.FieldBranch} {
		if v, ok := f[m].(string); ok {
			values = append(values, v)
		}
	}
	names, err := s.ResolveNames(ctx, values...)
	if err != nil {
		return nil, err
	}
	return ResolveRecord(f, names), nil
}

// RecordPseudonymous records the deployment's switch to pseudonymous
// repositories. The first call writes the one row; every later one, a
// restart or a new key, leaves it as it is.
func (s *Store) RecordPseudonymous(ctx context.Context, keyID string) error {
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO innsegl.repo_mode (mode, key_id) VALUES ('pseudonymous', $1)
		 ON CONFLICT (singleton) DO NOTHING`, keyID); err != nil {
		return classify("record_repo_mode", err)
	}
	return nil
}

// RecordedPseudonymous reports whether the switch has been recorded.
func (s *Store) RecordedPseudonymous(ctx context.Context) (bool, error) {
	var on bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM innsegl.repo_mode)`).Scan(&on)
	if err != nil {
		return false, classify("read_repo_mode", err)
	}
	return on, nil
}

// ErrRepoModeOneWay is returned when a literal core starts on a ledger that
// has recorded the switch to pseudonymous.
var ErrRepoModeOneWay = errors.New("this deployment switched to pseudonymous repositories, and the switch is one-way")

// Resolving is a Store whose run-scoped and keyed reads answer resolved
// names. It is what a reader that COMPARES a repository is given -- adoption
// (ADR-0079), the commit path's replay -- so a value it compares is the name
// a caller states, not a pseudonym. Appends and every other read are the
// Store's own. Nothing that verifies, hashes or re-appends a record may read
// through it.
type Resolving struct{ *Store }

// EventsForRun is Store.EventsForRun with repo and branch resolved.
func (r Resolving) EventsForRun(ctx context.Context, runID string) ([]event.Fields, error) {
	evs, err := r.Store.EventsForRun(ctx, runID)
	if err != nil {
		return nil, err
	}
	var values []string
	for _, f := range evs {
		for _, m := range []string{event.FieldRepo, event.FieldBranch} {
			if v, ok := f[m].(string); ok {
				values = append(values, v)
			}
		}
	}
	names, err := r.ResolveNames(ctx, values...)
	if err != nil {
		return nil, err
	}
	for i, f := range evs {
		evs[i] = ResolveRecord(f, names)
	}
	return evs, nil
}

// EventByIdempotencyKey is Store.EventByIdempotencyKey with repo and branch
// resolved.
func (r Resolving) EventByIdempotencyKey(ctx context.Context, key string) (event.Fields, bool, error) {
	f, found, err := r.Store.EventByIdempotencyKey(ctx, key)
	if err != nil || !found {
		return f, found, err
	}
	resolved, err := r.Resolved(ctx, f)
	if err != nil {
		return nil, false, err
	}
	return resolved, true, nil
}
