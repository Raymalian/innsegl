// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/go-webauthn/webauthn/webauthn"
)

// AuthStore is the read/write surface over innsegl_auth — RM-260/RM-261's
// users, passkeys, sessions, auth events, one-time enrolment codes and
// pending WebAuthn ceremonies (ADR-0062). It is deliberately a SEPARATE type
// from Store, which holds the ledger's read-only role: the two hold different
// credentials, connect as different Postgres roles, and Open for each proves
// a different thing about what its own credential may do.
type AuthStore struct {
	pool              *pgxpool.Pool
	cannotWriteLedger ReadOnlyReport
}

// Errors AuthStore's callers switch on, named rather than left as
// pgx.ErrNoRows so a caller does not have to import pgx to check one.
var (
	ErrUserNotFound      = errors.New("api: no such user")
	ErrPasskeyNotFound   = errors.New("api: no such passkey")
	ErrSessionNotFound   = errors.New("api: no such session")
	ErrCeremonyNotFound  = errors.New("api: no such ceremony, or it already expired")
	ErrEnrolmentCodeUsed = errors.New("api: that enrolment code has already been used, has expired, or was never issued")
	// ErrLastPasskey is DeletePasskey's refusal (#445): removing a user's
	// only passkey would lock the account out, with no sign-in method left
	// to reach the account page that could add another.
	ErrLastPasskey = errors.New("api: this is the only passkey on the account; removing it would lock the account out")
	// ErrRecoveryCodeInvalid is ConsumeRecoveryCode's refusal: the code is
	// wrong, already used, or was never minted — one answer for all three,
	// the same posture ErrEnrolmentCodeUsed already takes for its own code.
	ErrRecoveryCodeInvalid = errors.New("api: that recovery code is not usable: it may be wrong or already used")
)

// OpenAuthStore connects and REFUSES a credential that can write the ledger
// schema — the mirror image of Store's Open, which refuses a credential that
// can write anything AT ALL. There is no flag to skip this, for Open's own
// reason: a property asserted once at start-up is a property of the
// deployment, not a claim about the source code.
func OpenAuthStore(ctx context.Context, dsn string) (*AuthStore, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("api: parsing the auth DSN: %w", err)
	}
	return OpenAuthStoreConfig(ctx, cfg)
}

// OpenAuthStoreConfig is OpenAuthStore with the pool configured by the
// caller.
func OpenAuthStoreConfig(ctx context.Context, cfg *pgxpool.Config) (*AuthStore, error) {
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("api: opening the auth pool: %w", err)
	}
	report, err := AssertCannotWriteLedger(ctx, pool)
	if err != nil {
		pool.Close()
		return nil, err
	}
	return &AuthStore{pool: pool, cannotWriteLedger: report}, nil
}

// Close releases the pool.
func (a *AuthStore) Close() { a.pool.Close() }

// CannotWriteLedger is the evidence OpenAuthStore gathered — served
// alongside Store.ReadOnly() on the health surface, ADR-0062's "verified by
// a startup probe the same way AssertReadOnly already is".
func (a *AuthStore) CannotWriteLedger() ReadOnlyReport { return a.cannotWriteLedger }

// ---------------------------------------------------------------------------
// Identifiers. Generated, never derived, never guessable.
// ---------------------------------------------------------------------------

// newRandomID returns n cryptographically random bytes, hex-encoded.
func newRandomID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("api: no randomness available: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// hashToken is the one-way function every bearer value in innsegl_auth
// (session tokens, enrolment codes) is stored under. A leaked backup of this
// schema then names no live credential, the same property session_id_hash's
// own column comment states.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

// NewUserID mints a user_id: 16 random bytes, hex-encoded — stable, never
// derived from the display name (ADR-0062).
func NewUserID() (string, error) { return newRandomID(16) }

// CreateUser inserts a user row. userID is minted by the caller (NewUserID)
// so the enrolment handler can hand the same id to BeginRegistration before
// the row exists — go-webauthn's own ceremony needs a WebAuthnID before
// FinishRegistration, and the row is only written once the ceremony
// completes (CompleteEnrolment), keeping a never-finished registration from
// leaving a user with no passkey.
func (a *AuthStore) CreateUser(ctx context.Context, userID, displayName string) error {
	return createUserIn(ctx, a.pool, userID, displayName)
}

// createUserIn is CreateUser on q: the pool, or a transaction another store
// lends (an invited person's user, created with their membership, #481).
func createUserIn(ctx context.Context, q Querier, userID, displayName string) error {
	_, err := q.Exec(ctx,
		`INSERT INTO innsegl_auth.users (user_id, display_name) VALUES ($1, $2)`,
		userID, displayName)
	if err != nil {
		return fmt.Errorf("api: creating user %s: %w", userID, err)
	}
	return nil
}

// AuthUser is one row of innsegl_auth.users.
type AuthUser struct {
	UserID      string
	DisplayName string
	CreatedAt   time.Time
}

// UserByID reads one user, or ErrUserNotFound.
func (a *AuthStore) UserByID(ctx context.Context, userID string) (AuthUser, error) {
	var u AuthUser
	err := a.pool.QueryRow(ctx,
		`SELECT user_id, display_name, created_at FROM innsegl_auth.users WHERE user_id = $1`,
		userID).Scan(&u.UserID, &u.DisplayName, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthUser{}, ErrUserNotFound
	}
	if err != nil {
		return AuthUser{}, fmt.Errorf("api: reading user %s: %w", userID, err)
	}
	return u, nil
}

// UpdateDisplayName is PATCH /api/v1/account's own write (#445): the one
// field an account holds that a person can change about themselves.
func (a *AuthStore) UpdateDisplayName(ctx context.Context, userID, displayName string) error {
	tag, err := a.pool.Exec(ctx,
		`UPDATE innsegl_auth.users SET display_name = $2 WHERE user_id = $1`,
		userID, displayName)
	if err != nil {
		return fmt.Errorf("api: updating the display name for user %s: %w", userID, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// EnrolmentOpen reports whether first-user enrolment is open: true whenever
// no passkey exists anywhere in this deployment. A stale, passkey-less user
// row from an abandoned ceremony does not close it; CreateUser mints a
// fresh user_id each time this reopens rather than reusing one.
//
// ADR-0062's ORIGINAL text had recovery reuse this same door ("Recovery ...
// re-runs first-user enrolment"); the 2026-10-01 amendment (#445) replaced
// that with recovery codes instead — ConsumeRecoveryCode, reached through
// POST /api/v1/auth/recover, never through here. In practice this door only
// ever opens once: DeletePasskey refuses to remove a user's last passkey
// (ErrLastPasskey), so once the first one is added the passkey count can
// never fall back to zero through anything this package does.
func (a *AuthStore) EnrolmentOpen(ctx context.Context) (bool, error) {
	var anyPasskey bool
	if err := a.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM innsegl_auth.passkeys)`).Scan(&anyPasskey); err != nil {
		return false, fmt.Errorf("api: checking whether enrolment is open: %w", err)
	}
	return !anyPasskey, nil
}

// ---------------------------------------------------------------------------
// Passkeys
// ---------------------------------------------------------------------------

// credentialIDString is the one encoding a WebAuthn credential id is ever
// stored or looked up under: base64url-less base32, matching
// migration 0008's own column comment ("the same string the client sent,
// nothing to decode to compare") — shared so AddPasskey, UpdatePasskey and
// every #445 caller that builds or compares a credential_id cannot drift
// apart on the encoding.
func credentialIDString(id []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(id)
}

// AddPasskey inserts one credential, storing the library's own
// webauthn.Credential whole as JSON (see migration 0008's column comment for
// why) plus the attestation format ADR-0062 asks to have recorded on its own
// row, and — migration 0009 (#445) — the name the person gave it: "" for the
// one minted by first-user enrolment (ADR-0062 amendment: the setup page
// asks for an account name, not a passkey name), whatever the person typed
// for every passkey added afterwards through POST
// /api/v1/account/passkeys/finish. It returns the row's own created_at
// rather than approximating it client-side, the same "ask the server"
// discipline the rest of this file holds to.
func (a *AuthStore) AddPasskey(ctx context.Context, userID, name string, cred webauthn.Credential) (createdAt time.Time, err error) {
	return addPasskeyIn(ctx, a.pool, userID, name, cred)
}

// addPasskeyIn is AddPasskey on q, as createUserIn is CreateUser.
func addPasskeyIn(ctx context.Context, q Querier, userID, name string, cred webauthn.Credential) (createdAt time.Time, err error) {
	body, err := json.Marshal(cred)
	if err != nil {
		return time.Time{}, fmt.Errorf("api: encoding the passkey credential: %w", err)
	}
	credentialID := credentialIDString(cred.ID)
	err = q.QueryRow(ctx,
		`INSERT INTO innsegl_auth.passkeys (credential_id, user_id, credential, attestation_format, name)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING created_at`,
		credentialID, userID, body, cred.AttestationFormat, name).Scan(&createdAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("api: adding a passkey for user %s: %w", userID, err)
	}
	return createdAt, nil
}

// AccountPasskeyRow is one row of GET /api/v1/account's own passkey listing
// — everything internal/api/account.go's AccountPasskey needs except
// Current, which is a per-SESSION fact (which passkey issued it) and not a
// property of the passkey row itself, so the handler fills it in rather
// than this method.
type AccountPasskeyRow struct {
	ID         string
	Name       string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// AccountPasskeys lists every passkey a user holds, oldest first — ADR-0062
// amendment: "An account page lists every passkey (name, when added, when
// last used)".
func (a *AuthStore) AccountPasskeys(ctx context.Context, userID string) ([]AccountPasskeyRow, error) {
	rows, err := a.pool.Query(ctx,
		`SELECT credential_id, name, created_at, last_used_at FROM innsegl_auth.passkeys
		 WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("api: listing account passkeys for user %s: %w", userID, err)
	}
	defer rows.Close()

	var out []AccountPasskeyRow
	for rows.Next() {
		var row AccountPasskeyRow
		if serr := rows.Scan(&row.ID, &row.Name, &row.CreatedAt, &row.LastUsedAt); serr != nil {
			return nil, fmt.Errorf("api: reading an account passkey for user %s: %w", userID, serr)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("api: listing account passkeys for user %s: %w", userID, err)
	}
	return out, nil
}

// RenamePasskey sets a passkey's own label, scoped to the owning user so a
// credential id that belongs to someone else answers ErrPasskeyNotFound —
// the same "not yours reads exactly like doesn't exist" posture
// DeletePasskey holds to, and for the same reason (#445: "a passkey of
// another user → 404").
func (a *AuthStore) RenamePasskey(ctx context.Context, userID, credentialID, name string) (AccountPasskeyRow, error) {
	var row AccountPasskeyRow
	err := a.pool.QueryRow(ctx,
		`UPDATE innsegl_auth.passkeys SET name = $3
		 WHERE credential_id = $1 AND user_id = $2
		 RETURNING credential_id, name, created_at, last_used_at`,
		credentialID, userID, name).Scan(&row.ID, &row.Name, &row.CreatedAt, &row.LastUsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return AccountPasskeyRow{}, ErrPasskeyNotFound
	}
	if err != nil {
		return AccountPasskeyRow{}, fmt.Errorf("api: renaming a passkey: %w", err)
	}
	return row, nil
}

// DeletePasskey removes one passkey, refusing to leave the account with
// none (ErrLastPasskey) and refusing a credential id that belongs to
// someone else exactly as RenamePasskey does (ErrPasskeyNotFound).
//
// Both checks run inside one transaction that locks the user's own passkey
// rows (SELECT ... FOR UPDATE) first, so two concurrent deletes of a user's
// last two passkeys cannot both read "not the last one" and both proceed —
// the same server-enforced-atomically posture ConsumeEnrolmentCode already
// holds for its own single-use guarantee.
//
// Every session that signed in with this passkey is revoked as part of the
// same transaction (ADR-0062 amendment: "Deleting a passkey ends sessions
// that signed in with it") — BEFORE the row is deleted, because
// sessions.passkey_id's own ON DELETE SET NULL would otherwise just
// detach a still-live session from the passkey it used rather than end it.
func (a *AuthStore) DeletePasskey(ctx context.Context, userID, credentialID string) error {
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("api: beginning a transaction to remove a passkey: %w", err)
	}
	defer func() { discardError(tx.Rollback(ctx)) }()

	rows, err := tx.Query(ctx,
		`SELECT credential_id FROM innsegl_auth.passkeys WHERE user_id = $1 FOR UPDATE`, userID)
	if err != nil {
		return fmt.Errorf("api: locking passkeys for user %s: %w", userID, err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if serr := rows.Scan(&id); serr != nil {
			rows.Close()
			return fmt.Errorf("api: reading a locked passkey for user %s: %w", userID, serr)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("api: locking passkeys for user %s: %w", userID, err)
	}

	found := false
	for _, id := range ids {
		if id == credentialID {
			found = true
			break
		}
	}
	if !found {
		return ErrPasskeyNotFound
	}
	if len(ids) <= 1 {
		return ErrLastPasskey
	}

	if _, err := tx.Exec(ctx,
		`UPDATE innsegl_auth.sessions SET revoked_at = clock_timestamp()
		 WHERE passkey_id = $1 AND revoked_at IS NULL`,
		credentialID); err != nil {
		return fmt.Errorf("api: revoking sessions for a removed passkey: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM innsegl_auth.passkeys WHERE credential_id = $1 AND user_id = $2`,
		credentialID, userID); err != nil {
		return fmt.Errorf("api: removing a passkey: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("api: committing a passkey removal: %w", err)
	}
	return nil
}

// scanPasskeyUser reads one row of innsegl_auth.passkeys into (userID,
// credential); shared by PasskeysByUser and PasskeyByCredentialID so the two
// cannot drift in which columns they read.
func scanPasskeyUser(row pgx.Row) (userID string, cred webauthn.Credential, err error) {
	var body []byte
	var attestationFormat string
	if serr := row.Scan(&userID, &body, &attestationFormat); serr != nil {
		return "", webauthn.Credential{}, serr
	}
	if jerr := json.Unmarshal(body, &cred); jerr != nil {
		return "", webauthn.Credential{}, fmt.Errorf("api: decoding a stored passkey: %w", jerr)
	}
	return userID, cred, nil
}

// PasskeysByUser returns every credential a user holds — the whole of
// webauthn.User.WebAuthnCredentials()'s answer, for BeginRegistration's
// exclusion list and for FinishLogin's non-discoverable path.
func (a *AuthStore) PasskeysByUser(ctx context.Context, userID string) ([]webauthn.Credential, error) {
	rows, err := a.pool.Query(ctx,
		`SELECT user_id, credential, attestation_format FROM innsegl_auth.passkeys WHERE user_id = $1
		 ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("api: listing passkeys for user %s: %w", userID, err)
	}
	defer rows.Close()

	var out []webauthn.Credential
	for rows.Next() {
		_, cred, serr := scanPasskeyUser(rows)
		if serr != nil {
			return nil, fmt.Errorf("api: reading a passkey for user %s: %w", userID, serr)
		}
		out = append(out, cred)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("api: listing passkeys for user %s: %w", userID, err)
	}
	return out, nil
}

// UpdatePasskey persists the credential go-webauthn returned from a
// completed login — its updated SignCount and CloneWarning, per the
// library's own "must be written back on every successful FinishLogin"
// storage contract — and stamps last_used_at.
func (a *AuthStore) UpdatePasskey(ctx context.Context, cred webauthn.Credential) error {
	body, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("api: encoding the passkey credential: %w", err)
	}
	credentialID := credentialIDString(cred.ID)
	tag, err := a.pool.Exec(ctx,
		`UPDATE innsegl_auth.passkeys SET credential = $2, last_used_at = clock_timestamp()
		 WHERE credential_id = $1`,
		credentialID, body)
	if err != nil {
		return fmt.Errorf("api: updating a passkey: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrPasskeyNotFound
	}
	return nil
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

// CreateSession mints a new bearer token, stores its hash, and returns the
// raw token — the only time the raw value ever exists outside the browser's
// cookie jar. passkeyID names which passkey this session was ISSUED for
// (migration 0009, #445) — empty for a session a recovery code opened,
// which names no passkey at all (ADR-0062 amendment).
func (a *AuthStore) CreateSession(ctx context.Context, userID, passkeyID string, lifetime time.Duration) (token string, expiresAt time.Time, err error) {
	raw, err := newRandomID(32)
	if err != nil {
		return "", time.Time{}, err
	}
	var passkeyArg any
	if passkeyID != "" {
		passkeyArg = passkeyID
	}
	expiresAt = time.Now().UTC().Add(lifetime)
	_, err = a.pool.Exec(ctx,
		`INSERT INTO innsegl_auth.sessions (session_id_hash, user_id, passkey_id, expires_at)
		 VALUES ($1, $2, $3, $4)`,
		hashToken(raw), userID, passkeyArg, expiresAt)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("api: creating a session for user %s: %w", userID, err)
	}
	return raw, expiresAt, nil
}

// VerifySession reports the user a live, unrevoked, unexpired session token
// belongs to, and which passkey (if any) issued it — this is the one query
// server.go's deny-by-default gate runs on every gated request, and also
// what answers Account.passkeys[].current (#445).
func (a *AuthStore) VerifySession(ctx context.Context, token string) (userID, passkeyID string, ok bool, err error) {
	if token == "" {
		return "", "", false, nil
	}
	var pk *string
	err = a.pool.QueryRow(ctx,
		`SELECT user_id, passkey_id FROM innsegl_auth.sessions
		 WHERE session_id_hash = $1 AND revoked_at IS NULL AND expires_at > clock_timestamp()`,
		hashToken(token)).Scan(&userID, &pk)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, fmt.Errorf("api: verifying a session: %w", err)
	}
	if pk != nil {
		passkeyID = *pk
	}
	return userID, passkeyID, true, nil
}

// RevokeSession is sign-out: the server-side row is marked revoked, not
// merely left for the browser to forget (ADR-0062: "an explicit logout that
// removes the server-side session row"). Revoking an unknown or
// already-revoked token is not an error — a sign-out is idempotent by
// nature, and a caller who has already signed out gets the same 200 either
// way, matching the cookie already being gone client-side.
func (a *AuthStore) RevokeSession(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	_, err := a.pool.Exec(ctx,
		`UPDATE innsegl_auth.sessions SET revoked_at = clock_timestamp()
		 WHERE session_id_hash = $1 AND revoked_at IS NULL`,
		hashToken(token))
	if err != nil {
		return fmt.Errorf("api: revoking a session: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Auth events (ADR-0062: "Every enrolment, sign-in and refusal is recorded")
// ---------------------------------------------------------------------------

// Auth event types, spelled once. Every one of these is a fact about the
// sign-in surface, never about ledger content.
const (
	AuthEventEnrolmentRefused   = "enrolment_refused"
	AuthEventEnrolmentCompleted = "enrolment_completed"
	AuthEventSignInSucceeded    = "signin_succeeded"
	AuthEventSignInRefused      = "signin_refused"
	AuthEventSignOut            = "signout"
	// AuthEventPasskeyAdded and AuthEventPasskeyRemoved are #445's own
	// additions: the account page's two ways the set of credentials that can
	// sign in changes, outside enrolment itself.
	AuthEventPasskeyAdded             = "passkey_added"
	AuthEventPasskeyRemoved           = "passkey_removed"
	AuthEventRecoveryCodesRegenerated = "recovery_codes_regenerated"
)

// RecordAuthEvent appends one row. userID may be empty: a refusal often names
// no user at all. A failure to record is logged by the caller and never
// blocks the ceremony it is recording — the same "witness, never a gate"
// posture internal/gateway's own telemetry receiver holds, applied here to a
// database write instead of a network one.
func (a *AuthStore) RecordAuthEvent(ctx context.Context, eventType, userID, detail string) error {
	var userIDArg any
	if userID != "" {
		userIDArg = userID
	}
	_, err := a.pool.Exec(ctx,
		`INSERT INTO innsegl_auth.auth_events (event_type, user_id, detail) VALUES ($1, $2, $3)`,
		eventType, userIDArg, detail)
	if err != nil {
		return fmt.Errorf("api: recording an auth event: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// One-time enrolment codes (ADR-0062 decision (b))
// ---------------------------------------------------------------------------

// CreateEnrolmentCode mints a new one-time code and stores its hash. Minting
// is the CLI's job (cmd/innsegl admin-credential enrol-code); this method is
// what it calls having already opened an AuthStore with a write-capable DSN
// of its own, the same shape the removed resolve-alert CLI used for
// internal/ledger.Store.ResolveAlert.
func (a *AuthStore) CreateEnrolmentCode(ctx context.Context, ttl time.Duration) (code string, expiresAt time.Time, err error) {
	raw, err := newRandomID(16)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt = time.Now().UTC().Add(ttl)
	_, err = a.pool.Exec(ctx,
		`INSERT INTO innsegl_auth.enrolment_codes (code_hash, expires_at) VALUES ($1, $2)`,
		hashToken(raw), expiresAt)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("api: minting an enrolment code: %w", err)
	}
	return raw, expiresAt, nil
}

// ConsumeEnrolmentCode atomically marks one code used, and only ever
// succeeds once per code: the UPDATE's own WHERE used_at IS NULL is the
// single-use guarantee, enforced by the server rather than by a
// check-then-set race in Go (AUTH-004: a reused code is refused).
func (a *AuthStore) ConsumeEnrolmentCode(ctx context.Context, code string) error {
	tag, err := a.pool.Exec(ctx,
		`UPDATE innsegl_auth.enrolment_codes SET used_at = clock_timestamp()
		 WHERE code_hash = $1 AND used_at IS NULL AND expires_at > clock_timestamp()`,
		hashToken(code))
	if err != nil {
		return fmt.Errorf("api: consuming an enrolment code: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrEnrolmentCodeUsed
	}
	return nil
}

// ---------------------------------------------------------------------------
// WebAuthn ceremonies — the pending state between Begin and Finish.
// ---------------------------------------------------------------------------

// SaveCeremony stores one ceremony's go-webauthn SessionData (opaque JSON,
// round-tripped exactly) and returns the ceremony id the client is handed
// back to present on Finish.
func (a *AuthStore) SaveCeremony(ctx context.Context, kind string, sessionData []byte, pendingUserID, pendingDisplayName string, ttl time.Duration) (ceremonyID string, err error) {
	id, err := newRandomID(16)
	if err != nil {
		return "", err
	}
	var userArg, nameArg any
	if pendingUserID != "" {
		userArg, nameArg = pendingUserID, pendingDisplayName
	}
	_, err = a.pool.Exec(ctx,
		`INSERT INTO innsegl_auth.webauthn_ceremonies
		   (ceremony_id, kind, session_data, pending_user_id, pending_display_name, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		id, kind, sessionData, userArg, nameArg, time.Now().UTC().Add(ttl))
	if err != nil {
		return "", fmt.Errorf("api: saving a %s ceremony: %w", kind, err)
	}
	return id, nil
}

// Ceremony is what SaveCeremony stored.
type Ceremony struct {
	Kind               string
	SessionData        []byte
	PendingUserID      string
	PendingDisplayName string
}

// LoadAndConsumeCeremony reads and DELETES the ceremony row in one
// statement, so a Finish call can only ever be answered once — a second
// attempt with the same ceremony id, replayed or not, finds nothing
// (AUTH-004).
func (a *AuthStore) LoadAndConsumeCeremony(ctx context.Context, ceremonyID, kind string) (Ceremony, error) {
	var c Ceremony
	var userID, displayName *string
	err := a.pool.QueryRow(ctx,
		`DELETE FROM innsegl_auth.webauthn_ceremonies
		 WHERE ceremony_id = $1 AND kind = $2 AND expires_at > clock_timestamp()
		 RETURNING session_data, pending_user_id, pending_display_name`,
		ceremonyID, kind).Scan(&c.SessionData, &userID, &displayName)
	if errors.Is(err, pgx.ErrNoRows) {
		return Ceremony{}, ErrCeremonyNotFound
	}
	if err != nil {
		return Ceremony{}, fmt.Errorf("api: loading a %s ceremony: %w", kind, err)
	}
	c.Kind = kind
	if userID != nil {
		c.PendingUserID = *userID
	}
	if displayName != nil {
		c.PendingDisplayName = *displayName
	}
	return c, nil
}

// ---------------------------------------------------------------------------
// Recovery codes (migration 0009, #445; ADR-0062's 2026-10-01 amendment).
// ---------------------------------------------------------------------------

// recoveryCodeAlphabet is Crockford's own 32-symbol base32 alphabet: digits
// and uppercase letters with 0/O, 1/I/L and U removed, because those are
// exactly the characters a person mis-types or mis-reads for one another
// when copying a code off a screen or a piece of paper. It is a published,
// reviewed answer to "pick a human-safe alphabet" rather than one invented
// here.
const recoveryCodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// recoveryCodeCount is how many codes first enrolment mints, and how many a
// regeneration replaces them with (ADR-0062 amendment: "Ten single-use
// codes").
const recoveryCodeCount = 10

// recoveryCodeRawBytes of crypto/rand encode, 5 bits at a time, to exactly
// 16 recoveryCodeAlphabet symbols (80 bits is a multiple of 5, so no
// padding symbol is ever needed) — comfortably over the "≥ 64 bits each"
// floor. generateRecoveryCode splits the 16 symbols into two groups of
// eight around a dash, the same shape "xxxx-xxxx" names, just two chars
// wider a side to carry the extra entropy.
const recoveryCodeRawBytes = 10

// generateRecoveryCode mints one fresh code, formatted for a person to read
// and type back: UPPERCASE-WITH-A-DASH, from recoveryCodeAlphabet only.
func generateRecoveryCode() (string, error) {
	raw := make([]byte, recoveryCodeRawBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("api: no randomness available: %w", err)
	}
	symbols := make([]byte, 0, 16)
	var buf uint32
	var bits uint
	for _, b := range raw {
		buf = buf<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			idx := (buf >> bits) & 0x1F
			symbols = append(symbols, recoveryCodeAlphabet[idx])
		}
	}
	return string(symbols[:8]) + "-" + string(symbols[8:]), nil
}

// canonicalRecoveryCode normalises a person's input to the same form
// generateRecoveryCode's own hash is stored under: uppercase, no dash, no
// surrounding whitespace — "Accept the code case-insensitively and with or
// without the dash" (#445), satisfied by hashing (and comparing against) the
// SAME canonical string at both mint time and consume time rather than
// trying to normalise a stored hash after the fact.
func canonicalRecoveryCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	var sb strings.Builder
	sb.Grow(len(code))
	for _, r := range code {
		if r == '-' || r == ' ' || r == '\t' {
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// MintRecoveryCodes deletes every existing code for userID and inserts
// recoveryCodeCount fresh ones in one transaction — ADR-0062 amendment:
// "the account page regenerates them, which voids the rest", and first
// enrolment is this SAME operation on a user who had none yet (the DELETE
// removes nothing). Returns the raw, display-form codes: shown once, never
// stored.
func (a *AuthStore) MintRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	codes := make([]string, recoveryCodeCount)
	for i := range codes {
		c, err := generateRecoveryCode()
		if err != nil {
			return nil, err
		}
		codes[i] = c
	}

	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("api: beginning a transaction to mint recovery codes: %w", err)
	}
	defer func() { discardError(tx.Rollback(ctx)) }()

	if _, err := tx.Exec(ctx,
		`DELETE FROM innsegl_auth.recovery_codes WHERE user_id = $1`, userID); err != nil {
		return nil, fmt.Errorf("api: voiding earlier recovery codes for user %s: %w", userID, err)
	}
	for _, c := range codes {
		if _, err := tx.Exec(ctx,
			`INSERT INTO innsegl_auth.recovery_codes (code_hash, user_id) VALUES ($1, $2)`,
			hashToken(canonicalRecoveryCode(c)), userID); err != nil {
			return nil, fmt.Errorf("api: minting a recovery code for user %s: %w", userID, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("api: committing minted recovery codes for user %s: %w", userID, err)
	}
	return codes, nil
}

// ConsumeRecoveryCode atomically marks one matching, unused code used and
// reports the user it belonged to and how many of that user's codes remain
// unused — the single-use guarantee is the UPDATE's own
// WHERE used_at IS NULL, the same shape ConsumeEnrolmentCode already uses,
// enforced by the server rather than a check-then-set race in Go.
func (a *AuthStore) ConsumeRecoveryCode(ctx context.Context, code string) (userID string, remaining int, err error) {
	canon := canonicalRecoveryCode(code)
	if canon == "" {
		return "", 0, ErrRecoveryCodeInvalid
	}

	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("api: beginning a transaction to consume a recovery code: %w", err)
	}
	defer func() { discardError(tx.Rollback(ctx)) }()

	err = tx.QueryRow(ctx,
		`UPDATE innsegl_auth.recovery_codes SET used_at = clock_timestamp()
		 WHERE code_hash = $1 AND used_at IS NULL
		 RETURNING user_id`,
		hashToken(canon)).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", 0, ErrRecoveryCodeInvalid
	}
	if err != nil {
		return "", 0, fmt.Errorf("api: consuming a recovery code: %w", err)
	}

	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM innsegl_auth.recovery_codes WHERE user_id = $1 AND used_at IS NULL`,
		userID).Scan(&remaining); err != nil {
		return "", 0, fmt.Errorf("api: counting remaining recovery codes for user %s: %w", userID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", 0, fmt.Errorf("api: committing a consumed recovery code: %w", err)
	}
	return userID, remaining, nil
}

// RecoveryCodesRemaining answers Account.recovery_codes_remaining: how many
// of a user's codes are still unused.
func (a *AuthStore) RecoveryCodesRemaining(ctx context.Context, userID string) (int, error) {
	var n int
	err := a.pool.QueryRow(ctx,
		`SELECT count(*) FROM innsegl_auth.recovery_codes WHERE user_id = $1 AND used_at IS NULL`,
		userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("api: counting remaining recovery codes for user %s: %w", userID, err)
	}
	return n, nil
}
