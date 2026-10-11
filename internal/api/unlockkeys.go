// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"filippo.io/age"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"innsegl.dev/innsegl/internal/unlockkey"
)

// Unlock keys (#613, ADR-0082): hardware security keys an owner or admin of
// the operator organisation enrols from the account page, and later uses to
// unlock the CA key store, or to apply a new set of recipients, from any
// browser that has PRF for security keys.
//
//	GET  /api/v1/account/unlock-keys                 every enrolled key, with its state
//	POST /api/v1/account/unlock-keys/begin|finish    enrol one: {label} -> three ceremonies
//	POST /api/v1/account/unlock-keys/revoke/begin|finish   {id}, after a fresh passkey
//	GET  /api/v1/account/ca-custody                  the custodian's status
//	POST /api/v1/account/ca-custody/unlock/begin|finish    unlockcustody.go
//	POST /api/v1/account/ca-custody/reseal/begin|finish|confirm
//
// What the server holds of a key is public: its WebAuthn public key, the two
// salts the browser passes as the PRF input, and the two age recipients the
// browser derived from the PRF output (internal/unlockkey). The PRF output
// and the identities never reach the server; an assertion that carries a
// PRF result is refused, and nothing is recorded of it.
//
// A key's state is not stored. It is read from the custodian on every list:
// revoked once revoked; active while its custody recipient is in the set the
// material is sealed to; pending otherwise. So a reseal from the operator's
// machine (`innsegl ca-custody reseal`) and one from the dashboard both make
// a key active, and nothing here can drift from what the custodian seals to.

// Ceremony kinds, migration 0023's.
const (
	ceremonyKindAddUnlockKey    = "add_unlock_key"
	ceremonyKindRevokeUnlockKey = "revoke_unlock_key"
	ceremonyKindCAUnlock        = "ca_unlock"
	ceremonyKindCAReseal        = "ca_reseal"
	ceremonyKindCAResealConfirm = "ca_reseal_confirm"
)

// Auth events the unlock-key routes record. No row holds material, a PRF
// output or an identity: keys by id, recipients by fingerprint.
const (
	AuthEventUnlockKeyAdded       = "unlock_key_added"
	AuthEventUnlockKeyRefused     = "unlock_key_refused"
	AuthEventUnlockKeyRevoked     = "unlock_key_revoked"
	AuthEventCAUnlocked           = "ca_unlocked"
	AuthEventCAUnlockRefused      = "ca_unlock_refused"
	AuthEventCustodyResealStaged  = "custody_reseal_staged"
	AuthEventCustodyResealed      = "custody_resealed"
	AuthEventCustodyResealRefused = "custody_reseal_refused"
)

// Key states.
const (
	unlockKeyPending = "pending"
	unlockKeyActive  = "active"
	unlockKeyRevoked = "revoked"
	unlockKeyUnknown = "unknown"
)

// unlockSaltSize is one PRF salt: 32 random bytes, public.
const unlockSaltSize = 32

var (
	// ErrUnlockKeyNotFound: no unlock key has that id.
	ErrUnlockKeyNotFound = errors.New("api: no such unlock key")
	// ErrUnlockKeyRevoked: the key was revoked, for good.
	ErrUnlockKeyRevoked = errors.New("api: that unlock key is revoked")
)

const (
	unlockKeyNotFoundMessage = "no such unlock key"
	unlockKeyRevokedMessage  = "that unlock key is already revoked; a revoked key stays revoked"
	unlockKeyRoleMessage     = "unlock keys are for an owner or an admin of the operator's organisation (ADR-0082)"
	unlockKeyOwnerMessage    = "only an owner of the operator's organisation applies a new set of recipients"
	unlockKeyOthersMessage   = "only an owner revokes someone else's unlock key"
)

// UnlockKey is one enrolled security key as the account page lists it.
type UnlockKey struct {
	ID                 string     `json:"id"`
	Label              string     `json:"label"`
	State              string     `json:"state"`
	Mine               bool       `json:"mine"`
	Owner              string     `json:"owner"`
	CustodyRecipient   string     `json:"custody_recipient"`
	CustodyFingerprint string     `json:"custody_fingerprint"`
	BackupRecipient    string     `json:"backup_recipient"`
	BackupFingerprint  string     `json:"backup_fingerprint"`
	CreatedAt          time.Time  `json:"created_at"`
	LastUsedAt         *time.Time `json:"last_used_at"`
	RevokedAt          *time.Time `json:"revoked_at"`
}

// UnlockKeyList answers GET /api/v1/account/unlock-keys.
type UnlockKeyList struct {
	Custody UnlockKeyCustody `json:"custody"`
	Keys    []UnlockKey      `json:"keys"`
}

// UnlockKeyCustody is what the list knows of the custodian: off, not
// answering, or the digest of the set the material is sealed to.
type UnlockKeyCustody struct {
	Enabled   bool   `json:"enabled"`
	Reachable bool   `json:"reachable"`
	SetDigest string `json:"set_digest,omitempty"`
	Error     string `json:"error,omitempty"`
}

// UnlockKeyEnrolBegin starts an enrolment.
type UnlockKeyEnrolBegin struct {
	Label string `json:"label"`
}

// UnlockKeyEnrolChallenge is the three ceremonies an enrolment takes, in
// order: Confirm with the person's own sign-in passkey (the step-up), Create
// on the security key, then PRF: a get() on the new credential that
// evaluates the two salts, whose results stay in the browser.
type UnlockKeyEnrolChallenge struct {
	CeremonyID  string                        `json:"ceremony_id"`
	Confirm     *protocol.CredentialAssertion `json:"confirm"`
	Create      *protocol.CredentialCreation  `json:"create"`
	PRF         *protocol.CredentialAssertion `json:"prf"`
	CustodySalt protocol.URLEncodedBase64     `json:"custody_salt"`
	BackupSalt  protocol.URLEncodedBase64     `json:"backup_salt"`
	Format      string                        `json:"format"`
}

// UnlockKeyEnrolFinish completes one: the three responses, and the two
// recipients the browser derived. The PRF assertion carries no PRF result.
type UnlockKeyEnrolFinish struct {
	CeremonyID       string          `json:"ceremony_id"`
	Confirmation     json.RawMessage `json:"confirmation"`
	Credential       json.RawMessage `json:"credential"`
	Assertion        json.RawMessage `json:"assertion"`
	CustodyRecipient string          `json:"custody_recipient"`
	BackupRecipient  string          `json:"backup_recipient"`
}

// UnlockKeyRevoke names the key to revoke.
type UnlockKeyRevoke struct {
	ID string `json:"id"`
}

// unlockKeySelection is every security-key registration: a roaming,
// non-discoverable credential, with user verification (ADR-0082 decisions 2
// and 3). Never the sign-in passkey's resident, possibly synced kind.
var unlockKeySelection = protocol.AuthenticatorSelection{
	AuthenticatorAttachment: protocol.CrossPlatform,
	ResidentKey:             protocol.ResidentKeyRequirementDiscouraged,
	RequireResidentKey:      protocol.ResidentKeyNotRequired(),
	UserVerification:        protocol.VerificationRequired,
}

var securityKeyHint = []protocol.PublicKeyCredentialHints{protocol.PublicKeyCredentialHintSecurityKey}

// unlockUserHandle is the WebAuthn user handle every unlock key of a person
// is registered under. Not their sign-in handle: an authenticator that kept
// a resident credential for the same handle would replace their passkey.
func unlockUserHandle(userID string) string {
	sum := sha256.Sum256([]byte("innsegl unlock key\x00" + userID))
	return "unlock-" + hex.EncodeToString(sum[:16])
}

// recipientFingerprint is how a recipient is named in an audit row and on
// the page beside its full text.
func recipientFingerprint(r string) string {
	sum := sha256.Sum256([]byte(r))
	return "sha256:" + hex.EncodeToString(sum[:8])
}

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

// unlockKeyRow is one row of innsegl_auth.unlock_keys, with its owner's
// display name.
type unlockKeyRow struct {
	ID               string
	UserID           string
	Owner            string
	Label            string
	Credential       webauthn.Credential
	CustodyRecipient string
	BackupRecipient  string
	CustodySalt      []byte
	BackupSalt       []byte
	CreatedAt        time.Time
	LastUsedAt       *time.Time
	RevokedAt        *time.Time
}

const unlockKeyColumns = `k.credential_id, k.user_id, u.display_name, k.label, k.credential,
	k.custody_recipient, k.backup_recipient, k.custody_salt, k.backup_salt,
	k.created_at, k.last_used_at, k.revoked_at
	FROM innsegl_auth.unlock_keys k JOIN innsegl_auth.users u USING (user_id)`

func scanUnlockKey(row pgx.Row) (unlockKeyRow, error) {
	var k unlockKeyRow
	var body []byte
	if err := row.Scan(&k.ID, &k.UserID, &k.Owner, &k.Label, &body, &k.CustodyRecipient, &k.BackupRecipient,
		&k.CustodySalt, &k.BackupSalt, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt); err != nil {
		return unlockKeyRow{}, err
	}
	if err := json.Unmarshal(body, &k.Credential); err != nil {
		return unlockKeyRow{}, fmt.Errorf("api: decoding a stored unlock key: %w", err)
	}
	return k, nil
}

// unlockKeys answers every unlock key, oldest first; userID non-empty
// narrows them to one person's.
func (a *AuthStore) unlockKeys(ctx context.Context, userID string) ([]unlockKeyRow, error) {
	rows, err := a.pool.Query(ctx, `SELECT `+unlockKeyColumns+`
		WHERE $1 = '' OR k.user_id = $1 ORDER BY k.created_at, k.credential_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("api: listing unlock keys: %w", err)
	}
	defer rows.Close()
	var out []unlockKeyRow
	for rows.Next() {
		k, err := scanUnlockKey(rows)
		if err != nil {
			return nil, fmt.Errorf("api: reading an unlock key: %w", err)
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("api: listing unlock keys: %w", err)
	}
	return out, nil
}

// unlockKey answers one key, or ErrUnlockKeyNotFound.
func (a *AuthStore) unlockKey(ctx context.Context, id string) (unlockKeyRow, error) {
	k, err := scanUnlockKey(a.pool.QueryRow(ctx, `SELECT `+unlockKeyColumns+` WHERE k.credential_id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return unlockKeyRow{}, ErrUnlockKeyNotFound
	}
	if err != nil {
		return unlockKeyRow{}, fmt.Errorf("api: reading an unlock key: %w", err)
	}
	return k, nil
}

// errUnlockKeyTaken is an insert that collides with an enrolled credential
// or recipient.
var errUnlockKeyTaken = errors.New("api: that security key or recipient is already enrolled")

// addUnlockKey inserts one key.
func (a *AuthStore) addUnlockKey(ctx context.Context, k unlockKeyRow) (time.Time, error) {
	body, err := json.Marshal(k.Credential)
	if err != nil {
		return time.Time{}, fmt.Errorf("api: encoding the unlock key credential: %w", err)
	}
	var created time.Time
	err = a.pool.QueryRow(ctx, `INSERT INTO innsegl_auth.unlock_keys
		(credential_id, user_id, label, credential, custody_recipient, backup_recipient,
		 custody_salt, backup_salt, format)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING created_at`,
		k.ID, k.UserID, k.Label, body, k.CustodyRecipient, k.BackupRecipient,
		k.CustodySalt, k.BackupSalt, unlockkey.FormatVersion).Scan(&created)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return time.Time{}, errUnlockKeyTaken
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("api: adding an unlock key: %w", err)
	}
	return created, nil
}

// touchUnlockKey writes back the credential a verified assertion returned
// (its counter) and stamps its use. A key revoked since is ErrUnlockKeyRevoked.
func (a *AuthStore) touchUnlockKey(ctx context.Context, cred webauthn.Credential) error {
	body, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("api: encoding the unlock key credential: %w", err)
	}
	tag, err := a.pool.Exec(ctx, `UPDATE innsegl_auth.unlock_keys SET credential = $2, last_used_at = clock_timestamp()
		WHERE credential_id = $1 AND revoked_at IS NULL`, credentialIDString(cred.ID), body)
	if err != nil {
		return fmt.Errorf("api: updating an unlock key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUnlockKeyRevoked
	}
	return nil
}

// revokeUnlockKey revokes one key for good.
func (a *AuthStore) revokeUnlockKey(ctx context.Context, id, actor string) error {
	tag, err := a.pool.Exec(ctx, `UPDATE innsegl_auth.unlock_keys
		SET revoked_at = clock_timestamp(), revoked_by = $2
		WHERE credential_id = $1 AND revoked_at IS NULL`, id, actor)
	if err != nil {
		return fmt.Errorf("api: revoking an unlock key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		if _, gerr := a.unlockKey(ctx, id); gerr != nil {
			return gerr
		}
		return ErrUnlockKeyRevoked
	}
	return nil
}

// ---------------------------------------------------------------------------
// Routes, the role, the Origin and the limit
// ---------------------------------------------------------------------------

func (s *Server) registerUnlockKeyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/account/unlock-keys", s.unlockRoute(s.handleUnlockKeys))
	mux.HandleFunc("POST /api/v1/account/unlock-keys/begin", s.unlockRoute(s.handleUnlockKeyBegin))
	mux.HandleFunc("POST /api/v1/account/unlock-keys/finish", s.unlockRoute(s.handleUnlockKeyFinish))
	mux.HandleFunc("POST /api/v1/account/unlock-keys/revoke/begin", s.unlockRoute(s.handleUnlockKeyRevokeBegin))
	mux.HandleFunc("POST /api/v1/account/unlock-keys/revoke/finish", s.unlockRoute(s.handleUnlockKeyRevokeFinish))
	mux.HandleFunc("GET /api/v1/account/ca-custody", s.unlockRoute(s.handleCustodyStatus))
	mux.HandleFunc("POST /api/v1/account/ca-custody/unlock/begin", s.unlockRoute(s.handleCustodyUnlockBegin))
	mux.HandleFunc("POST /api/v1/account/ca-custody/unlock/finish", s.unlockRoute(s.handleCustodyUnlockFinish))
	mux.HandleFunc("POST /api/v1/account/ca-custody/reseal/begin", s.unlockRoute(s.handleCustodyResealBegin))
	mux.HandleFunc("POST /api/v1/account/ca-custody/reseal/finish", s.unlockRoute(s.handleCustodyResealFinish))
	mux.HandleFunc("POST /api/v1/account/ca-custody/reseal/confirm", s.unlockRoute(s.handleCustodyResealConfirm))
}

// unlockRoute is what every route here shares beyond serveAccount's session
// and same-origin check: a POST must carry the dashboard's Origin (a browser
// always sends it; its absence is something other than the dashboard), a
// POST spends one of the person's tokens, and the accounts spine must exist.
func (s *Server) unlockRoute(h http.HandlerFunc) http.HandlerFunc {
	return s.withOrgs(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if r.Header.Get("Origin") != s.webAuthnConfig.RPOrigin {
				writeError(w, http.StatusForbidden, codeForbidden,
					"this request carries no Origin, or not the dashboard's own; unlock keys answer the dashboard only")
				return
			}
			if wait, ok := s.unlockLimit.allow(accountSessionFrom(r).userID); !ok {
				w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
				writeError(w, http.StatusTooManyRequests, codeTooManyRequests,
					"too many unlock-key requests; wait and retry")
				return
			}
		}
		h(w, r)
	})
}

// codeTooManyRequests is a request over a rate limit.
const codeTooManyRequests = "too_many_requests"

// operatorRole answers the caller's role in the operator organisation when
// it is one of allowed, and writes the refusal when it is not.
func (s *Server) operatorRole(ctx context.Context, w http.ResponseWriter, userID, refusal string, allowed ...string) (string, bool) {
	ms, err := s.orgs.Memberships(ctx, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, organisationsLoadMessage)
		return "", false
	}
	for _, m := range ms {
		if !m.Operator {
			continue
		}
		for _, a := range allowed {
			if m.Role == a {
				return m.Role, true
			}
		}
	}
	writeError(w, http.StatusForbidden, codeForbidden, refusal)
	return "", false
}

func (s *Server) ownerOrAdmin(ctx context.Context, w http.ResponseWriter, userID string) (string, bool) {
	return s.operatorRole(ctx, w, userID, unlockKeyRoleMessage, roleOwner, roleAdmin)
}

// unlockKeyBurst and unlockKeyRefill bound a person's POSTs to these routes:
// an enrolment is two, an unlock two, a reseal three.
const (
	unlockKeyBurst  = 20
	unlockKeyRefill = 15 * time.Second
)

// unlockLimiter is a token bucket per person.
type unlockLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	buckets map[string]*unlockBucket
}

type unlockBucket struct {
	tokens float64
	at     time.Time
}

func newUnlockLimiter(now func() time.Time) *unlockLimiter {
	if now == nil {
		now = time.Now
	}
	return &unlockLimiter{now: now, buckets: map[string]*unlockBucket{}}
}

// allow spends a token for id, or answers how long until one is back.
func (l *unlockLimiter) allow(id string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.buckets[id]
	if b == nil {
		b = &unlockBucket{tokens: unlockKeyBurst, at: now}
		l.buckets[id] = b
	}
	b.tokens = math.Min(unlockKeyBurst, b.tokens+float64(now.Sub(b.at))/float64(unlockKeyRefill))
	b.at = now
	if b.tokens < 1 {
		return time.Duration((1 - b.tokens) * float64(unlockKeyRefill)), false
	}
	b.tokens--
	return 0, true
}

// ---------------------------------------------------------------------------
// GET /api/v1/account/unlock-keys
// ---------------------------------------------------------------------------

// custodySet is the custodian's set, as a list needs it.
type custodySet struct {
	info    UnlockKeyCustody
	members map[string]bool
}

func (s *Server) readCustodySet(ctx context.Context) custodySet {
	if s.custody == nil {
		return custodySet{}
	}
	set, err := s.custody.recipients(ctx)
	if err != nil {
		return custodySet{info: UnlockKeyCustody{Enabled: true, Error: err.Error()}}
	}
	members := map[string]bool{}
	for _, r := range set.Recipients {
		members[r] = true
	}
	return custodySet{info: UnlockKeyCustody{Enabled: true, Reachable: true, SetDigest: set.Digest}, members: members}
}

func (c custodySet) state(k unlockKeyRow) string {
	switch {
	case k.RevokedAt != nil:
		return unlockKeyRevoked
	case !c.info.Enabled:
		return unlockKeyPending
	case !c.info.Reachable:
		return unlockKeyUnknown
	case c.members[k.CustodyRecipient]:
		return unlockKeyActive
	default:
		return unlockKeyPending
	}
}

func unlockKeyView(k unlockKeyRow, state, viewer string) UnlockKey {
	return UnlockKey{
		ID: k.ID, Label: k.Label, State: state, Mine: k.UserID == viewer, Owner: k.Owner,
		CustodyRecipient: k.CustodyRecipient, CustodyFingerprint: recipientFingerprint(k.CustodyRecipient),
		BackupRecipient: k.BackupRecipient, BackupFingerprint: recipientFingerprint(k.BackupRecipient),
		CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt, RevokedAt: k.RevokedAt,
	}
}

func (s *Server) handleUnlockKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	if _, ok := s.ownerOrAdmin(ctx, w, userID); !ok {
		return
	}
	rows, err := s.authStore.unlockKeys(ctx, "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not list the unlock keys")
		return
	}
	set := s.readCustodySet(ctx)
	out := UnlockKeyList{Custody: set.info, Keys: []UnlockKey{}}
	for _, k := range rows {
		out.Keys = append(out.Keys, unlockKeyView(k, set.state(k), userID))
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// POST /api/v1/account/unlock-keys/begin, .../finish
// ---------------------------------------------------------------------------

// pendingUnlockKey is what an enrolment ceremony stores: the three
// go-webauthn sessions, round-tripped unmodified, and the salts. All public.
type pendingUnlockKey struct {
	Confirm     webauthn.SessionData `json:"confirm"`
	Register    webauthn.SessionData `json:"register"`
	PRF         webauthn.SessionData `json:"prf"`
	CustodySalt []byte               `json:"custody_salt"`
	BackupSalt  []byte               `json:"backup_salt"`
}

func newSalt() ([]byte, error) {
	b := make([]byte, unlockSaltSize)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (s *Server) handleUnlockKeyBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req UnlockKeyEnrolBegin
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	label := strings.TrimSpace(req.Label)
	if label == "" || utf8.RuneCountInString(label) > 64 {
		writeError(w, http.StatusBadRequest, codeBadRequest, "label must be 1-64 characters")
		return
	}
	if _, ok := s.ownerOrAdmin(ctx, w, userID); !ok {
		return
	}
	user, err := loadUser(ctx, s.authStore, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not load the account")
		return
	}
	if len(user.credentials) == 0 {
		writeError(w, http.StatusForbidden, codeForbidden, confirmNeedsPasskey)
		return
	}
	existing, err := s.authStore.unlockKeys(ctx, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not list the unlock keys")
		return
	}
	var exclude []protocol.CredentialDescriptor
	for _, k := range existing {
		if k.RevokedAt == nil {
			exclude = append(exclude, k.Credential.Descriptor())
		}
	}
	custodySalt, err := newSalt()
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "no randomness available")
		return
	}
	backupSalt, err := newSalt()
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "no randomness available")
		return
	}

	confirm, confirmSession, err := s.webAuthn.BeginLogin(user,
		webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not begin the confirmation: "+err.Error())
		return
	}
	keyUser := dbUser{id: unlockUserHandle(userID), displayName: user.displayName}
	create, registerSession, err := s.webAuthn.BeginRegistration(keyUser,
		webauthn.WithAuthenticatorSelection(unlockKeySelection),
		webauthn.WithPublicKeyCredentialHints(securityKeyHint),
		webauthn.WithExclusions(exclude),
		webauthn.WithExtensions(webauthn.WithExtensionPRFSupport()),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not begin the registration: "+err.Error())
		return
	}
	prf, prfSession, err := s.webAuthn.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired),
		webauthn.WithAssertionPublicKeyCredentialHints(securityKeyHint),
		webauthn.WithAssertionExtensions(webauthn.WithExtensionPRF(protocol.PRFValues{First: custodySalt, Second: backupSalt})),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not begin the PRF ceremony: "+err.Error())
		return
	}
	// The PRF get() names no credential (the new one has no id yet); it is
	// verified against the new credential, under the unlock handle.
	prfSession.UserID = keyUser.WebAuthnID()
	body, err := json.Marshal(pendingUnlockKey{Confirm: *confirmSession, Register: *registerSession, PRF: *prfSession,
		CustodySalt: custodySalt, BackupSalt: backupSalt})
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the ceremony")
		return
	}
	ceremonyID, err := s.authStore.SaveCeremony(ctx, ceremonyKindAddUnlockKey, body, userID, label, authCeremonyTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the ceremony")
		return
	}
	writeJSON(w, http.StatusOK, UnlockKeyEnrolChallenge{
		CeremonyID: ceremonyID, Confirm: confirm, Create: create, PRF: prf,
		CustodySalt: custodySalt, BackupSalt: backupSalt, Format: unlockkey.FormatVersion,
	})
}

// hasPRFOutput answers whether a response carries what the PRF evaluated:
// a browser that sent it has sent the secret the identities derive from.
func hasPRFOutput(o protocol.AuthenticationExtensionsClientOutputs) bool {
	return (o.PRF != nil && o.PRF.Results != nil) || o.HMACGetSecret != nil
}

const prfOutputMessage = "the request carries the PRF output, which must never leave the browser; " +
	"nothing was stored or forwarded. The dashboard strips it; a client that sends it is not the dashboard"

// parseUnlockAssertion parses an assertion and refuses one that carries a
// PRF output. The refusal names no part of it.
func parseUnlockAssertion(body []byte) (*protocol.ParsedCredentialAssertionData, int, string) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return nil, http.StatusUnauthorized, "the security key's assertion is not readable"
	}
	if hasPRFOutput(parsed.ClientExtensionResults) {
		return nil, http.StatusBadRequest, prfOutputMessage
	}
	return parsed, 0, ""
}

// parseAgeX25519 accepts a plain age X25519 recipient (age1…) and nothing
// else: what internal/unlockkey derives.
func parseAgeX25519(s string) (string, bool) {
	s = strings.TrimSpace(s)
	r, err := age.ParseX25519Recipient(s)
	if err != nil {
		return "", false
	}
	return r.String(), true
}

func (s *Server) handleUnlockKeyFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req UnlockKeyEnrolFinish
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	refuse := func(status int, message string) {
		s.recordAuth(ctx, AuthEventUnlockKeyRefused, userID, message)
		writeError(w, status, codeForStatus(status), message)
	}
	ceremony, err := s.authStore.LoadAndConsumeCeremony(ctx, req.CeremonyID, ceremonyKindAddUnlockKey)
	if err != nil || ceremony.PendingUserID != userID {
		writeError(w, http.StatusUnauthorized, codeUnauthorized, confirmExpiredMessage)
		return
	}
	if _, ok := s.ownerOrAdmin(ctx, w, userID); !ok {
		return
	}
	var pending pendingUnlockKey
	if jerr := json.Unmarshal(ceremony.SessionData, &pending); jerr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not read the saved ceremony")
		return
	}

	// 1. The step-up: the person's own sign-in passkey, fresh, with UV.
	user, err := loadUser(ctx, s.authStore, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not load the account")
		return
	}
	passkey, err := s.webAuthn.FinishLogin(user, pending.Confirm, credentialHTTPRequest(req.Confirmation))
	if err != nil {
		refuse(http.StatusUnauthorized, "your sign-in passkey did not confirm this: "+err.Error())
		return
	}
	if uerr := s.authStore.UpdatePasskey(ctx, *passkey); uerr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not update the passkey")
		return
	}

	// 2. The security key's registration: UV required, then hardware and PRF.
	keyUser := dbUser{id: unlockUserHandle(userID), displayName: user.displayName}
	cred, err := s.webAuthn.FinishRegistration(keyUser, pending.Register, credentialHTTPRequest(req.Credential))
	if err != nil {
		refuse(http.StatusUnauthorized, "the security key did not verify: "+err.Error())
		return
	}
	if cred.Flags.BackupEligible {
		refuse(http.StatusBadRequest, "this credential is backup-eligible: a synced passkey, not a hardware key. "+
			"Unlock keys are hardware security keys only (ADR-0082 decision 3)")
		return
	}
	if !cred.Flags.UserVerified {
		refuse(http.StatusUnauthorized, "the security key did not verify its PIN (ADR-0082 decision 2)")
		return
	}
	if cred.Extensions.PRFEnabled == nil || !*cred.Extensions.PRFEnabled {
		refuse(http.StatusBadRequest, "this browser or security key has no PRF (hmac-secret) for this credential; "+
			"use a browser and key that do")
		return
	}

	// 3. The PRF get() on the new credential: a real assertion, with UV,
	// and without its result.
	parsed, status, message := parseUnlockAssertion(req.Assertion)
	if parsed == nil {
		refuse(status, message)
		return
	}
	keyUser.credentials = []webauthn.Credential{*cred}
	asserted, err := s.webAuthn.ValidateLogin(keyUser, pending.PRF, parsed)
	if err != nil {
		refuse(http.StatusUnauthorized, "the security key's assertion did not verify: "+err.Error())
		return
	}

	// 4. The two recipients the browser derived.
	custody, ok := parseAgeX25519(req.CustodyRecipient)
	backup, ok2 := parseAgeX25519(req.BackupRecipient)
	if !ok || !ok2 {
		refuse(http.StatusBadRequest, "each recipient must be a plain age X25519 recipient (age1…), as the "+
			"dashboard derives it ("+unlockkey.FormatVersion+")")
		return
	}
	if custody == backup {
		refuse(http.StatusBadRequest, "the custody and backup recipients are one recipient; each is derived from its own salt")
		return
	}

	row := unlockKeyRow{
		ID: credentialIDString(asserted.ID), UserID: userID, Owner: user.displayName, Label: ceremony.PendingDisplayName,
		Credential: *asserted, CustodyRecipient: custody, BackupRecipient: backup,
		CustodySalt: pending.CustodySalt, BackupSalt: pending.BackupSalt,
	}
	created, err := s.authStore.addUnlockKey(ctx, row)
	if errors.Is(err, errUnlockKeyTaken) {
		refuse(http.StatusConflict, "that security key or recipient is already enrolled")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the unlock key")
		return
	}
	row.CreatedAt = created
	s.recordAuth(ctx, AuthEventUnlockKeyAdded, userID, "key "+row.ID+"; custody "+recipientFingerprint(custody)+
		"; backup "+recipientFingerprint(backup)+"; attestation format: "+asserted.AttestationFormat)
	writeJSON(w, http.StatusOK, unlockKeyView(row, unlockKeyPending, userID))
}

// codeForStatus is the error code for a refusal's status.
func codeForStatus(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return codeUnauthorized
	case http.StatusForbidden:
		return codeForbidden
	case http.StatusConflict:
		return codeConflict
	case http.StatusNotFound:
		return codeNotFound
	case http.StatusServiceUnavailable:
		return codeUnavailable
	case http.StatusRequestEntityTooLarge, http.StatusBadRequest:
		return codeBadRequest
	default:
		return codeInternal
	}
}

// ---------------------------------------------------------------------------
// POST /api/v1/account/unlock-keys/revoke/begin, .../finish
// ---------------------------------------------------------------------------

// revocable answers the key when userID may revoke it now: their own, or
// anyone's for an owner; not one already revoked.
func (s *Server) revocable(ctx context.Context, w http.ResponseWriter, userID, id string) (unlockKeyRow, bool) {
	role, ok := s.ownerOrAdmin(ctx, w, userID)
	if !ok {
		return unlockKeyRow{}, false
	}
	k, err := s.authStore.unlockKey(ctx, id)
	if errors.Is(err, ErrUnlockKeyNotFound) {
		writeError(w, http.StatusNotFound, codeNotFound, unlockKeyNotFoundMessage)
		return unlockKeyRow{}, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not read the unlock key")
		return unlockKeyRow{}, false
	}
	if k.UserID != userID && role != roleOwner {
		writeError(w, http.StatusForbidden, codeForbidden, unlockKeyOthersMessage)
		return unlockKeyRow{}, false
	}
	if k.RevokedAt != nil {
		writeError(w, http.StatusConflict, codeConflict, unlockKeyRevokedMessage)
		return unlockKeyRow{}, false
	}
	return k, true
}

func (s *Server) handleUnlockKeyRevokeBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req UnlockKeyRevoke
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	if _, ok := s.revocable(ctx, w, userID, req.ID); !ok {
		return
	}
	s.beginConfirmation(ctx, w, ceremonyKindRevokeUnlockKey, userID, req)
}

func (s *Server) handleUnlockKeyRevokeFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req UnlockKeyRevoke
	if !s.finishConfirmation(w, r, ceremonyKindRevokeUnlockKey, userID, &req) {
		return
	}
	k, ok := s.revocable(ctx, w, userID, req.ID)
	if !ok {
		return
	}
	if err := s.authStore.revokeUnlockKey(ctx, k.ID, userID); err != nil {
		switch {
		case errors.Is(err, ErrUnlockKeyRevoked):
			writeError(w, http.StatusConflict, codeConflict, unlockKeyRevokedMessage)
		case errors.Is(err, ErrUnlockKeyNotFound):
			writeError(w, http.StatusNotFound, codeNotFound, unlockKeyNotFoundMessage)
		default:
			writeError(w, http.StatusInternalServerError, codeInternal, "could not revoke the unlock key")
		}
		return
	}
	s.recordAuth(ctx, AuthEventUnlockKeyRevoked, userID, "key "+k.ID+"; custody "+
		recipientFingerprint(k.CustodyRecipient)+"; it leaves the set at the next reseal")
	k, err := s.authStore.unlockKey(ctx, k.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not read the unlock key")
		return
	}
	writeJSON(w, http.StatusOK, unlockKeyView(k, unlockKeyRevoked, userID))
}
