// SPDX-License-Identifier: Apache-2.0

// Package accounts is the data spine for a multi-organisation deployment
// (#456): accounts (organisations), memberships, installations (client
// machines and CI runners), single-use enrolment tokens, repository grants
// and an append-only audit trail. Migration 0010 creates the tables, in
// schema innsegl_auth beside the sign-in tables they reference.
//
// The store connects as the auth-writer role (internal/api.AuthWriterRole).
// Every write appends an audit row in the same transaction, so a change with
// no record of it cannot commit.
package accounts

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"innsegl.dev/innsegl/internal/api"
)

// Roles a member can hold.
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// Installation kinds.
const (
	KindWorkstation = "workstation"
	KindService     = "service"
)

// Installation statuses.
const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
	StatusRevoked   = "revoked"
)

// AllRepos is the single repos entry that means every repository the
// account holds a live grant on.
const AllRepos = "*"

// TokenTTL is how long an enrolment token lives.
const TokenTTL = 15 * time.Minute

const tokenPrefix = "ie"

// Errors callers switch on.
var (
	// ErrInvalid is any argument the store refuses before touching the
	// database.
	ErrInvalid = errors.New("accounts: invalid argument")
	// ErrNotFound: no such installation, or no live grant to end.
	ErrNotFound = errors.New("accounts: not found")
	// ErrTokenInvalid is the one answer for a token that is malformed,
	// unknown, forged, expired or already used. Distinguishing them would be
	// an oracle.
	ErrTokenInvalid = errors.New("accounts: that enrolment token is not usable")
	// ErrAlreadyMember: the user already holds a live membership.
	ErrAlreadyMember = errors.New("accounts: the user is already a member of this account")
	// ErrRepoHeld: another account holds a live grant on the repository.
	ErrRepoHeld = errors.New("accounts: another account holds this repository")
	// ErrRevoked: a revoked installation cannot change status again.
	ErrRevoked = errors.New("accounts: the installation is revoked and cannot be changed")
)

// Store reads and writes the accounts spine.
type Store struct {
	pool *pgxpool.Pool
	own  bool
}

// New wraps a pool the caller owns and closes.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Open connects with the auth-writer DSN and REFUSES a credential that can
// write the ledger schema, exactly as api.OpenAuthStore does.
func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("accounts: opening the pool: %w", err)
	}
	report, err := api.AssertCannotWriteLedger(ctx, pool)
	if err != nil {
		pool.Close()
		return nil, err
	}
	if report.Writable() {
		pool.Close()
		return nil, fmt.Errorf("accounts: the credential can write the ledger schema: %w", api.ErrWritable)
	}
	return &Store{pool: pool, own: true}, nil
}

// Close releases a pool Open created.
func (s *Store) Close() {
	if s.own {
		s.pool.Close()
	}
}

func newID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("accounts: no randomness available: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

// AuditEntry is one row of innsegl_auth.audit.
type AuditEntry struct {
	Actor     string // user id; empty for the system or the operator's CLI
	AccountID string // empty when the action belongs to no account
	Action    string
	Subject   string
	Detail    map[string]any
}

type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func appendAudit(ctx context.Context, x execer, e AuditEntry) error {
	if strings.TrimSpace(e.Action) == "" {
		return fmt.Errorf("%w: an audit entry needs an action", ErrInvalid)
	}
	detail := e.Detail
	if detail == nil {
		detail = map[string]any{}
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("%w: audit detail: %w", ErrInvalid, err)
	}
	if _, err := x.Exec(ctx,
		`INSERT INTO innsegl_auth.audit (actor, account_id, action, subject, detail)
		 VALUES ($1, $2, $3, $4, $5)`,
		nullable(e.Actor), nullable(e.AccountID), e.Action, e.Subject, raw); err != nil {
		return fmt.Errorf("accounts: appending the audit row: %w", err)
	}
	return nil
}

// Audit appends one row on its own. The store's own writes use it inside
// their transaction.
func (s *Store) Audit(ctx context.Context, e AuditEntry) error {
	return appendAudit(ctx, s.pool, e)
}

// inTx runs fn in a transaction and commits it.
func (s *Store) inTx(ctx context.Context, fn func(tx pgx.Tx) error) (err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("accounts: begin: %w", err)
	}
	defer func() {
		if rerr := tx.Rollback(ctx); err == nil && rerr != nil && !errors.Is(rerr, pgx.ErrTxClosed) {
			err = rerr
		}
	}()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("accounts: commit: %w", err)
	}
	return nil
}

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// ---------------------------------------------------------------------------
// Accounts and memberships
// ---------------------------------------------------------------------------

// Account is one organisation.
type Account struct {
	ID        string
	Name      string
	Shard     string
	Operator  bool
	CreatedAt time.Time
}

// CreateAccountParams: Operator marks the deployment's own organisation.
type CreateAccountParams struct {
	Name     string
	Shard    string
	Operator bool
	Actor    string
}

// CreateAccount inserts an account.
func (s *Store) CreateAccount(ctx context.Context, p CreateAccountParams) (Account, error) {
	name := strings.TrimSpace(p.Name)
	if name == "" || len(name) > 256 {
		return Account{}, fmt.Errorf("%w: an account needs a name of 1 to 256 bytes", ErrInvalid)
	}
	id, err := newID(16)
	if err != nil {
		return Account{}, err
	}
	a := Account{ID: id, Name: name, Shard: p.Shard, Operator: p.Operator}
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		if qerr := tx.QueryRow(ctx,
			`INSERT INTO innsegl_auth.accounts (account_id, name, shard, operator)
			 VALUES ($1, $2, $3, $4) RETURNING created_at`,
			a.ID, a.Name, a.Shard, a.Operator).Scan(&a.CreatedAt); qerr != nil {
			return fmt.Errorf("accounts: creating the account: %w", qerr)
		}
		return appendAudit(ctx, tx, AuditEntry{Actor: p.Actor, AccountID: a.ID, Action: "account.created",
			Subject: a.ID, Detail: map[string]any{"name": a.Name, "operator": a.Operator}})
	})
	if err != nil {
		return Account{}, err
	}
	return a, nil
}

// AddMember gives a user a live membership. A second live membership for the
// same pair is ErrAlreadyMember.
func (s *Store) AddMember(ctx context.Context, accountID, userID, role, actor string) error {
	switch role {
	case RoleOwner, RoleAdmin, RoleMember:
	default:
		return fmt.Errorf("%w: role %q is not owner, admin or member", ErrInvalid, role)
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO innsegl_auth.memberships (user_id, account_id, role) VALUES ($1, $2, $3)`,
			userID, accountID, role); err != nil {
			if pgCode(err) == "23505" {
				return ErrAlreadyMember
			}
			return fmt.Errorf("accounts: adding the member: %w", err)
		}
		return appendAudit(ctx, tx, AuditEntry{Actor: actor, AccountID: accountID, Action: "membership.added",
			Subject: userID, Detail: map[string]any{"role": role}})
	})
}

// ---------------------------------------------------------------------------
// Repositories
// ---------------------------------------------------------------------------

var repoPattern = regexp.MustCompile(`^[^\s/]+/[^\s/]+/[^\s/]+$`)

func validRepo(r string) bool { return len(r) <= 512 && repoPattern.MatchString(r) }

// normaliseRepos checks a repos list: the single entry "*", or host/org/name
// entries. Duplicates are dropped, order is kept.
func normaliseRepos(repos []string) ([]string, error) {
	if len(repos) == 0 {
		return nil, fmt.Errorf("%w: repos is empty; use * for every granted repository", ErrInvalid)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(repos))
	for _, r := range repos {
		if r == AllRepos && len(repos) > 1 {
			return nil, fmt.Errorf("%w: * must be the only repos entry", ErrInvalid)
		}
		if r != AllRepos && !validRepo(r) {
			return nil, fmt.Errorf("%w: %q is not host/org/name", ErrInvalid, r)
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out, nil
}

func normaliseKind(k string) (string, error) {
	switch k {
	case "":
		return KindWorkstation, nil
	case KindWorkstation, KindService:
		return k, nil
	}
	return "", fmt.Errorf("%w: kind %q is not workstation or service", ErrInvalid, k)
}

// GrantRepo gives an account a live grant on a repository. Another account's
// live grant is ErrRepoHeld, enforced by the database's partial unique index;
// granting what the account already holds is a no-op.
func (s *Store) GrantRepo(ctx context.Context, accountID, repo, actor string) error {
	if !validRepo(repo) {
		return fmt.Errorf("%w: %q is not host/org/name", ErrInvalid, repo)
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var holder string
		err := tx.QueryRow(ctx,
			`SELECT account_id FROM innsegl_auth.repo_grants WHERE repo = $1 AND until IS NULL`, repo).Scan(&holder)
		switch {
		case err == nil && holder == accountID:
			return nil
		case err == nil:
			return ErrRepoHeld
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("accounts: reading the grant: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO innsegl_auth.repo_grants (account_id, repo) VALUES ($1, $2)`, accountID, repo); err != nil {
			if pgCode(err) == "23505" {
				return ErrRepoHeld
			}
			return fmt.Errorf("accounts: granting the repository: %w", err)
		}
		return appendAudit(ctx, tx, AuditEntry{Actor: actor, AccountID: accountID, Action: "repo_grant.created",
			Subject: repo})
	})
}

// EndRepoGrant ends the account's live grant on a repository. No live grant
// is ErrNotFound.
func (s *Store) EndRepoGrant(ctx context.Context, accountID, repo, actor string) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE innsegl_auth.repo_grants SET until = clock_timestamp()
			  WHERE account_id = $1 AND repo = $2 AND until IS NULL`, accountID, repo)
		if err != nil {
			return fmt.Errorf("accounts: ending the grant: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return appendAudit(ctx, tx, AuditEntry{Actor: actor, AccountID: accountID, Action: "repo_grant.ended",
			Subject: repo})
	})
}

// ---------------------------------------------------------------------------
// Enrolment tokens
// ---------------------------------------------------------------------------

// TokenParams describes a token to mint. Kind defaults to workstation.
type TokenParams struct {
	AccountID string
	CreatedBy string
	Repos     []string
	Kind      string
}

// TokenMeta is what remains visible about a token after the plaintext is
// handed over.
type TokenMeta struct {
	TokenID   string
	ExpiresAt time.Time
}

// CreateEnrolmentToken mints a single-use token, valid for TokenTTL, and
// returns its plaintext. The plaintext is returned once and never stored: the
// row holds a token id and a SHA-256 of the secret.
func (s *Store) CreateEnrolmentToken(ctx context.Context, p TokenParams) (string, TokenMeta, error) {
	repos, err := normaliseRepos(p.Repos)
	if err != nil {
		return "", TokenMeta{}, err
	}
	kind, err := normaliseKind(p.Kind)
	if err != nil {
		return "", TokenMeta{}, err
	}
	tokenID, err := newID(8)
	if err != nil {
		return "", TokenMeta{}, err
	}
	secret, err := newID(32)
	if err != nil {
		return "", TokenMeta{}, err
	}
	meta := TokenMeta{TokenID: tokenID}
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		if qerr := tx.QueryRow(ctx,
			`INSERT INTO innsegl_auth.enrolment_tokens
			   (token_id, secret_hash, account_id, created_by, repos, kind, expires_at)
			 VALUES ($1, $2, $3, $4, $5, $6, clock_timestamp() + $7::interval) RETURNING expires_at`,
			tokenID, hashSecret(secret), p.AccountID, p.CreatedBy, repos, kind,
			fmt.Sprintf("%d seconds", int(TokenTTL.Seconds()))).Scan(&meta.ExpiresAt); qerr != nil {
			return fmt.Errorf("accounts: storing the enrolment token: %w", qerr)
		}
		return appendAudit(ctx, tx, AuditEntry{Actor: p.CreatedBy, AccountID: p.AccountID,
			Action: "enrolment_token.created", Subject: tokenID,
			Detail: map[string]any{"repos": repos, "kind": kind}})
	})
	if err != nil {
		return "", TokenMeta{}, err
	}
	return tokenPrefix + "_" + tokenID + "_" + secret, meta, nil
}

// Enrolment is what a consumed token authorises.
type Enrolment struct {
	TokenID   string
	AccountID string
	CreatedBy string
	Repos     []string
	Kind      string
}

// ConsumeEnrolmentToken spends a token exactly once. Every failure (malformed,
// unknown, wrong secret, expired, already used) is ErrTokenInvalid.
//
// The secret's hash is compared in constant time, and the spend is one
// UPDATE ... WHERE used_at IS NULL AND expires_at > now() RETURNING, so two
// concurrent consumers cannot both win.
func (s *Store) ConsumeEnrolmentToken(ctx context.Context, token string) (Enrolment, error) {
	tokenID, stored, err := s.lookupToken(ctx, token)
	if err != nil {
		return Enrolment{}, err
	}
	var en Enrolment
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		var cerr error
		en, cerr = consumeTokenTx(ctx, tx, tokenID, stored)
		return cerr
	})
	if err != nil {
		return Enrolment{}, err
	}
	return en, nil
}

// lookupToken parses a token and checks its secret against the stored hash in
// constant time. It answers the token id and the stored hash for the spend,
// or ErrTokenInvalid.
func (s *Store) lookupToken(ctx context.Context, token string) (tokenID, stored string, err error) {
	parts := strings.Split(token, "_")
	if len(parts) != 3 || parts[0] != tokenPrefix || parts[1] == "" || parts[2] == "" {
		return "", "", ErrTokenInvalid
	}
	tokenID, presented := parts[1], hashSecret(parts[2])

	err = s.pool.QueryRow(ctx,
		`SELECT secret_hash FROM innsegl_auth.enrolment_tokens WHERE token_id = $1`, tokenID).Scan(&stored)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// Compare against a fixed value so unknown ids cost the same.
		_ = subtle.ConstantTimeCompare([]byte(presented), []byte(strings.Repeat("0", 64)))
		return "", "", ErrTokenInvalid
	case err != nil:
		return "", "", fmt.Errorf("accounts: reading the enrolment token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(presented), []byte(stored)) != 1 {
		return "", "", ErrTokenInvalid
	}
	return tokenID, stored, nil
}

// consumeTokenTx is the spend itself, inside the caller's transaction.
func consumeTokenTx(ctx context.Context, tx pgx.Tx, tokenID, stored string) (Enrolment, error) {
	en := Enrolment{TokenID: tokenID}
	qerr := tx.QueryRow(ctx,
		`UPDATE innsegl_auth.enrolment_tokens SET used_at = clock_timestamp()
		  WHERE token_id = $1 AND secret_hash = $2 AND used_at IS NULL AND expires_at > clock_timestamp()
		  RETURNING account_id, created_by, repos, kind`, tokenID, stored).
		Scan(&en.AccountID, &en.CreatedBy, &en.Repos, &en.Kind)
	if errors.Is(qerr, pgx.ErrNoRows) {
		return Enrolment{}, ErrTokenInvalid
	}
	if qerr != nil {
		return Enrolment{}, fmt.Errorf("accounts: consuming the enrolment token: %w", qerr)
	}
	if err := appendAudit(ctx, tx, AuditEntry{Actor: en.CreatedBy, AccountID: en.AccountID,
		Action: "enrolment_token.consumed", Subject: tokenID}); err != nil {
		return Enrolment{}, err
	}
	return en, nil
}

// ---------------------------------------------------------------------------
// Installations
// ---------------------------------------------------------------------------

// Installation is one client machine or CI runner.
type Installation struct {
	ID            string
	AccountID     string
	CreatedBy     string
	Name          string
	Kind          string
	Repos         []string
	Status        string
	CreatedAt     time.Time
	LastRenewedAt *time.Time
	RevokedAt     *time.Time
}

// InstallationParams describes an installation to create. TokenID, when set,
// is the consumed token that enrolled it; the token row then names it.
type InstallationParams struct {
	AccountID string
	CreatedBy string
	Name      string
	Kind      string
	Repos     []string
	TokenID   string
}

const installationColumns = `installation_id, account_id, created_by, name, kind, repos, status,
	created_at, last_renewed_at, revoked_at`

func scanInstallation(row pgx.Row) (Installation, error) {
	var i Installation
	err := row.Scan(&i.ID, &i.AccountID, &i.CreatedBy, &i.Name, &i.Kind, &i.Repos, &i.Status,
		&i.CreatedAt, &i.LastRenewedAt, &i.RevokedAt)
	return i, err
}

// CreateInstallation inserts an active installation with a fresh 32-hex id.
func (s *Store) CreateInstallation(ctx context.Context, p InstallationParams) (Installation, error) {
	name := strings.TrimSpace(p.Name)
	if name == "" || len(name) > 256 {
		return Installation{}, fmt.Errorf("%w: an installation needs a name of 1 to 256 bytes", ErrInvalid)
	}
	repos, err := normaliseRepos(p.Repos)
	if err != nil {
		return Installation{}, err
	}
	kind, err := normaliseKind(p.Kind)
	if err != nil {
		return Installation{}, err
	}
	id, err := newID(16)
	if err != nil {
		return Installation{}, err
	}
	var out Installation
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		var ierr error
		out, ierr = insertInstallationTx(ctx, tx, id, p.AccountID, p.CreatedBy, name, kind, repos, p.TokenID)
		return ierr
	})
	if err != nil {
		return Installation{}, err
	}
	return out, nil
}

// insertInstallationTx inserts an installation whose arguments are already
// normalised, links the token that enrolled it (when tokenID is set) and
// appends the audit row, inside the caller's transaction. An id already in
// use is ErrInvalid.
func insertInstallationTx(ctx context.Context, tx pgx.Tx, id, accountID, createdBy, name, kind string,
	repos []string, tokenID string,
) (Installation, error) {
	out, qerr := scanInstallation(tx.QueryRow(ctx,
		`INSERT INTO innsegl_auth.installations (installation_id, account_id, created_by, name, kind, repos)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING `+installationColumns,
		id, accountID, createdBy, name, kind, repos))
	if qerr != nil {
		if pgCode(qerr) == "23505" {
			return Installation{}, fmt.Errorf("%w: installation id %q is already in use", ErrInvalid, id)
		}
		return Installation{}, fmt.Errorf("accounts: creating the installation: %w", qerr)
	}
	if tokenID != "" {
		tag, lerr := tx.Exec(ctx,
			`UPDATE innsegl_auth.enrolment_tokens SET installation_id = $2
			  WHERE token_id = $1 AND used_at IS NOT NULL AND installation_id IS NULL AND account_id = $3`,
			tokenID, id, accountID)
		if lerr != nil {
			return Installation{}, fmt.Errorf("accounts: linking the token: %w", lerr)
		}
		if tag.RowsAffected() == 0 {
			return Installation{}, fmt.Errorf("%w: token %q was not consumed for this account, or already names an installation",
				ErrInvalid, tokenID)
		}
	}
	if err := appendAudit(ctx, tx, AuditEntry{Actor: createdBy, AccountID: accountID,
		Action: "installation.created", Subject: id,
		Detail: map[string]any{"name": name, "kind": kind, "repos": repos}}); err != nil {
		return Installation{}, err
	}
	return out, nil
}

// GetInstallation returns one installation, or ErrNotFound.
func (s *Store) GetInstallation(ctx context.Context, id string) (Installation, error) {
	i, err := scanInstallation(s.pool.QueryRow(ctx,
		`SELECT `+installationColumns+` FROM innsegl_auth.installations WHERE installation_id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Installation{}, ErrNotFound
	}
	if err != nil {
		return Installation{}, fmt.Errorf("accounts: reading the installation: %w", err)
	}
	return i, nil
}

// ListInstallations returns an account's installations, oldest first.
func (s *Store) ListInstallations(ctx context.Context, accountID string) ([]Installation, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+installationColumns+` FROM innsegl_auth.installations
		  WHERE account_id = $1 ORDER BY created_at, installation_id`, accountID)
	if err != nil {
		return nil, fmt.Errorf("accounts: listing installations: %w", err)
	}
	defer rows.Close()
	var out []Installation
	for rows.Next() {
		i, err := scanInstallation(rows)
		if err != nil {
			return nil, fmt.Errorf("accounts: reading an installation: %w", err)
		}
		out = append(out, i)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("accounts: listing installations: %w", err)
	}
	return out, nil
}

// SetInstallationStatus moves an installation between active and suspended,
// or revokes it. Revoked is final.
func (s *Store) SetInstallationStatus(ctx context.Context, id, status, actor string) error {
	switch status {
	case StatusActive, StatusSuspended, StatusRevoked:
	default:
		return fmt.Errorf("%w: status %q is not active, suspended or revoked", ErrInvalid, status)
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var account, current string
		err := tx.QueryRow(ctx,
			`SELECT account_id, status FROM innsegl_auth.installations WHERE installation_id = $1 FOR UPDATE`,
			id).Scan(&account, &current)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("accounts: reading the installation: %w", err)
		}
		if current == StatusRevoked {
			return ErrRevoked
		}
		if _, err := tx.Exec(ctx,
			`UPDATE innsegl_auth.installations
			    SET status = $2,
			        revoked_at = CASE WHEN $2 = 'revoked' THEN clock_timestamp() ELSE revoked_at END
			  WHERE installation_id = $1`, id, status); err != nil {
			return fmt.Errorf("accounts: updating the installation: %w", err)
		}
		return appendAudit(ctx, tx, AuditEntry{Actor: actor, AccountID: account,
			Action: "installation." + status, Subject: id, Detail: map[string]any{"from": current}})
	})
}

// InScope reports whether an installation may act on a repository: the
// installation is active, and the repository is in its repos (or its repos is
// "*") AND the installation's account holds a live grant on it. An unknown
// installation is out of scope, not an error.
func (s *Store) InScope(ctx context.Context, installationID, repo string) (bool, error) {
	if repo == "" || repo == AllRepos {
		return false, nil
	}
	var ok bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (
		   SELECT 1
		     FROM innsegl_auth.installations i
		     JOIN innsegl_auth.repo_grants g
		       ON g.account_id = i.account_id AND g.until IS NULL
		    WHERE i.installation_id = $1
		      AND i.status = 'active'
		      AND g.repo = $2
		      AND ($2 = ANY (i.repos) OR i.repos = ARRAY['*']::text[]))`,
		installationID, repo).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("accounts: checking scope: %w", err)
	}
	return ok, nil
}
