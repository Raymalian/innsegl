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

// CountUsers reports how many users exist. First-enrolment logic reads this:
// ADR-0062's first user is enrolled in the owner's physical presence and
// every later one by an existing signed-in user, and #409 builds only the
// first case.
func (a *AuthStore) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := a.pool.QueryRow(ctx, `SELECT count(*) FROM innsegl_auth.users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("api: counting users: %w", err)
	}
	return n, nil
}

// CreateUser inserts a user row. userID is minted by the caller (NewUserID)
// so the enrolment handler can hand the same id to BeginRegistration before
// the row exists — go-webauthn's own ceremony needs a WebAuthnID before
// FinishRegistration, and the row is only written once the ceremony
// completes (CompleteEnrolment), keeping a never-finished registration from
// leaving a user with no passkey.
func (a *AuthStore) CreateUser(ctx context.Context, userID, displayName string) error {
	_, err := a.pool.Exec(ctx,
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

// EnrolmentOpen reports whether the first-enrolment (or recovery) door is
// open: true whenever no passkey exists anywhere in this deployment.
// ADR-0062: "Recovery ... re-runs first-user enrolment" — this is the SAME
// door, not a second one, because it is the same question either way, "does
// a passkey exist yet". A stale, passkey-less user row from an abandoned
// ceremony does not close it; CreateUser mints a fresh user_id each time
// this reopens rather than reusing one.
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

// AddPasskey inserts one credential, storing the library's own
// webauthn.Credential whole as JSON (see migration 0008's column comment for
// why) plus the attestation format ADR-0062 asks to have recorded on its own
// row.
func (a *AuthStore) AddPasskey(ctx context.Context, userID string, cred webauthn.Credential) error {
	body, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("api: encoding the passkey credential: %w", err)
	}
	credentialID := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(cred.ID)
	_, err = a.pool.Exec(ctx,
		`INSERT INTO innsegl_auth.passkeys (credential_id, user_id, credential, attestation_format)
		 VALUES ($1, $2, $3, $4)`,
		credentialID, userID, body, cred.AttestationFormat)
	if err != nil {
		return fmt.Errorf("api: adding a passkey for user %s: %w", userID, err)
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
	credentialID := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(cred.ID)
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
// cookie jar.
func (a *AuthStore) CreateSession(ctx context.Context, userID string, lifetime time.Duration) (token string, expiresAt time.Time, err error) {
	raw, err := newRandomID(32)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt = time.Now().UTC().Add(lifetime)
	_, err = a.pool.Exec(ctx,
		`INSERT INTO innsegl_auth.sessions (session_id_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
		hashToken(raw), userID, expiresAt)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("api: creating a session for user %s: %w", userID, err)
	}
	return raw, expiresAt, nil
}

// VerifySession reports the user a live, unrevoked, unexpired session token
// belongs to. This is the one query server.go's deny-by-default gate runs on
// every gated request.
func (a *AuthStore) VerifySession(ctx context.Context, token string) (userID string, ok bool, err error) {
	if token == "" {
		return "", false, nil
	}
	err = a.pool.QueryRow(ctx,
		`SELECT user_id FROM innsegl_auth.sessions
		 WHERE session_id_hash = $1 AND revoked_at IS NULL AND expires_at > clock_timestamp()`,
		hashToken(token)).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("api: verifying a session: %w", err)
	}
	return userID, true, nil
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
// of its own, the same shape `innsegl resolve-alert` uses for
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
