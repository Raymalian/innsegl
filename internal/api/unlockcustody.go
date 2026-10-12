// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"innsegl.dev/innsegl/internal/cacustody"
)

// The dashboard's unlock and reseal (#613, ADR-0082 decisions 4 and 7).
//
// The browser opens the sealed material with the identity its security key
// derives, and sends back the material it opened beside a fresh assertion
// from that key. This file verifies the assertion against an active unlock
// key of the signed-in owner or admin BEFORE it decodes the material, then
// forwards the material once to the custodian over the unlock network and
// drops it. Nothing here logs, stores or repeats the material: a refusal
// says which step refused, never what was sent.
//
// The custodian is reached only on the routes custodyRoutes names. It is the
// same custodian the core forwards the operator machine's requests to
// (cmd/innsegl/corecacustody.go); this is the dashboard's door to it.

// custodyRoutes is the allowlist: the custodian routes the API may reach,
// each with its one method. Nothing else is ever requested.
var custodyRoutes = map[string]string{
	cacustody.PathStatus:        http.MethodGet,
	cacustody.PathMaterial:      http.MethodGet,
	cacustody.PathRecipients:    http.MethodGet,
	cacustody.PathUnlock:        http.MethodPost,
	cacustody.PathReseal:        http.MethodPost,
	cacustody.PathResealConfirm: http.MethodPost,
}

// maxCustodyAnswer bounds what the API reads back from the custodian: the
// sealed material is a few hundred bytes per recipient.
const maxCustodyAnswer = 1 << 20

const custodyOffMessage = "custody is off on this core: the CA key is in a file, and there is nothing to unlock " +
	"(no custodian URL is configured)"

const custodyDownMessage = "the custodian is not answering; retry"

// custodyClient reaches the custodian.
type custodyClient struct {
	base string
	http *http.Client
}

func newCustodyClient(base string) *custodyClient {
	if base == "" {
		return nil
	}
	return &custodyClient{base: strings.TrimSuffix(base, "/"), http: &http.Client{
		Timeout: 60 * time.Second,
		// The custodian answers; it never sends the API anywhere else.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// errCustodyRoute is a request for a route the allowlist does not hold. It
// is a programming error, refused before anything is sent.
var errCustodyRoute = errors.New("api: the custodian route is not on the allowlist")

// do sends one request on an allowlisted route and answers the status and
// the bounded body.
func (c *custodyClient) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	if custodyRoutes[path] != method {
		return 0, nil, fmt.Errorf("%w: %s %s", errCustodyRoute, method, path)
	}
	reader := io.Reader(http.NoBody)
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(io.LimitReader(resp.Body, maxCustodyAnswer))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, out, nil
}

// get reads a GET route's 200 answer.
func (c *custodyClient) get(ctx context.Context, path string) ([]byte, error) {
	status, body, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, errors.New(custodyDownMessage)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("the custodian answered %d: %s", status, custodianError(body))
	}
	return body, nil
}

func (c *custodyClient) recipients(ctx context.Context) (cacustody.RecipientSet, error) {
	body, err := c.get(ctx, cacustody.PathRecipients)
	if err != nil {
		return cacustody.RecipientSet{}, err
	}
	var set cacustody.RecipientSet
	if err := json.Unmarshal(body, &set); err != nil {
		return cacustody.RecipientSet{}, errors.New("the custodian answered something unreadable")
	}
	return set, nil
}

func (c *custodyClient) material(ctx context.Context) ([]byte, error) {
	return c.get(ctx, cacustody.PathMaterial)
}

// status is the core's own answer shape (cacustody.CoreStatus), so the page
// reads one status whichever door it came through.
func (c *custodyClient) status(ctx context.Context) cacustody.CoreStatus {
	body, err := c.get(ctx, cacustody.PathStatus)
	if err != nil {
		return cacustody.CoreStatus{Enabled: true, Sealed: true, Error: err.Error()}
	}
	var st cacustody.Status
	if err := json.Unmarshal(body, &st); err != nil {
		return cacustody.CoreStatus{Enabled: true, Sealed: true, Error: "the custodian answered something unreadable"}
	}
	return cacustody.CoreStatus{Enabled: true, Initialized: st.Initialized, Sealed: st.Sealed,
		CanSign: st.CanSign, Reason: st.Reason, Error: st.Error}
}

// custodianError is the custodian's own refusal text. The custodian never
// repeats material in one (internal/cacustody); it is bounded here anyway.
func custodianError(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil || e.Error == "" {
		return "no reason given"
	}
	if len(e.Error) > 300 {
		return e.Error[:300]
	}
	return e.Error
}

// CustodyChallenge is an unlock's or a reseal's assertion, over the
// person's active unlock keys with each one's custody salt as its PRF input,
// and the sealed material the browser opens with the identity it derives.
type CustodyChallenge struct {
	CeremonyID string `json:"ceremony_id"`
	*protocol.CredentialAssertion
	Sealed []byte `json:"sealed"`
}

// CustodyFinish is the assertion and the material it opened. Material is
// read only after Credential verifies.
type CustodyFinish struct {
	CeremonyID string          `json:"ceremony_id"`
	Credential json.RawMessage `json:"credential"`
	Material   json.RawMessage `json:"material"`
}

// CustodyUnlocked answers a completed unlock with the custodian's status.
type CustodyUnlocked struct {
	Status cacustody.CoreStatus `json:"status"`
}

// ResealRecipient is one member of a proposed set, as the owner confirms it.
type ResealRecipient struct {
	Recipient   string `json:"recipient"`
	Fingerprint string `json:"fingerprint"`
	Label       string `json:"label"`
	KeyID       string `json:"key_id,omitempty"`
}

// ResealChallenge is CustodyChallenge plus the set it proposes: every
// member, what it adds and what it removes, and the digest the custodian
// will seal to and no other.
type ResealChallenge struct {
	CustodyChallenge
	Recipients []ResealRecipient `json:"recipients"`
	Added      []ResealRecipient `json:"added"`
	Removed    []ResealRecipient `json:"removed"`
	SetDigest  string            `json:"set_digest"`
}

// ResealStagedAnswer is the staged copy for the browser to open with the
// same key, and the confirm that applies it.
type ResealStagedAnswer struct {
	ConfirmID string                 `json:"confirm_id"`
	Staged    cacustody.ResealStaged `json:"staged"`
}

// ResealConfirmRequest applies a staged copy: what the browser read from
// it.
type ResealConfirmRequest struct {
	ConfirmID string          `json:"confirm_id"`
	Material  json.RawMessage `json:"material"`
	Check     string          `json:"check"`
}

// Resealed answers an applied reseal.
type Resealed struct {
	SetDigest  string `json:"set_digest"`
	Recipients int    `json:"recipients"`
}

// pendingCustody is what an unlock or reseal ceremony stores.
type pendingCustody struct {
	Session    webauthn.SessionData `json:"session"`
	Recipients []string             `json:"recipients,omitempty"`
	SetDigest  string               `json:"set_digest,omitempty"`
}

// pendingResealConfirm is what a staged reseal waits with.
type pendingResealConfirm struct {
	SetDigest  string `json:"set_digest"`
	KeyID      string `json:"key_id"`
	Recipients int    `json:"recipients"`
}

// requireCustody answers the client, or writes that custody is off.
func (s *Server) requireCustody(w http.ResponseWriter) (*custodyClient, bool) {
	if s.custody == nil {
		writeError(w, http.StatusServiceUnavailable, codeUnavailable, custodyOffMessage)
		return nil, false
	}
	return s.custody, true
}

// ---------------------------------------------------------------------------
// GET /api/v1/account/ca-custody
// ---------------------------------------------------------------------------

func (s *Server) handleCustodyStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.ownerOrAdmin(r.Context(), w, accountSessionFrom(r).userID); !ok {
		return
	}
	if s.custody == nil {
		writeJSON(w, http.StatusOK, cacustody.CoreStatus{})
		return
	}
	writeJSON(w, http.StatusOK, s.custody.status(r.Context()))
}

// ---------------------------------------------------------------------------
// The challenge both an unlock and a reseal begin with
// ---------------------------------------------------------------------------

// activeKeysOf is userID's keys that open the material now: not revoked,
// and in the set it is sealed to.
func activeKeysOf(rows []unlockKeyRow, userID string, set cacustody.RecipientSet) []unlockKeyRow {
	var out []unlockKeyRow
	for _, k := range rows {
		if k.UserID == userID && k.RevokedAt == nil && slices.Contains(set.Recipients, k.CustodyRecipient) {
			out = append(out, k)
		}
	}
	return out
}

// custodyChallenge begins an assertion over keys, each with its custody
// salt as the PRF input, and reads the sealed material.
func (s *Server) custodyChallenge(ctx context.Context, w http.ResponseWriter, c *custodyClient, userID string,
	keys []unlockKeyRow) (CustodyChallenge, webauthn.SessionData, bool) {
	sealed, err := c.material(ctx)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, codeUnavailable, "could not read the sealed material: "+err.Error())
		return CustodyChallenge{}, webauthn.SessionData{}, false
	}
	user := dbUser{id: unlockUserHandle(userID)}
	evals := map[string]protocol.PRFValues{}
	for _, k := range keys {
		user.credentials = append(user.credentials, k.Credential)
		evals[protocol.URLEncodedBase64(k.Credential.ID).String()] = protocol.PRFValues{First: k.CustodySalt}
	}
	assertion, session, err := s.webAuthn.BeginLogin(user,
		webauthn.WithUserVerification(protocol.VerificationRequired),
		webauthn.WithAssertionPublicKeyCredentialHints(securityKeyHint),
		webauthn.WithAssertionExtensions(webauthn.WithExtensionPRFByCredential(evals, nil)),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not begin the ceremony: "+err.Error())
		return CustodyChallenge{}, webauthn.SessionData{}, false
	}
	return CustodyChallenge{CredentialAssertion: assertion, Sealed: sealed}, *session, true
}

// noActiveKeyMessage is an unlock or reseal by someone none of whose keys
// opens the material.
const noActiveKeyMessage = "none of your unlock keys opens the sealed material yet: a new key is pending until " +
	"a reseal applies it, from the operator's machine (`innsegl ca-custody reseal --add <recipient>`) or here " +
	"by an owner with an active key"

// ---------------------------------------------------------------------------
// The finish both an unlock and a reseal share: the assertion, then the
// material
// ---------------------------------------------------------------------------

// verifiedCustodyFinish consumes a ceremony of kind, checks the role again,
// and verifies the assertion against an active unlock key of the person.
// Only then does it decode the material. It writes every refusal itself,
// recording it under event.
func (s *Server) verifiedCustodyFinish(w http.ResponseWriter, r *http.Request, kind, event string,
	role func(context.Context, http.ResponseWriter, string) (string, bool)) (unlockKeyRow, pendingCustody, cacustody.Material, bool) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req CustodyFinish
	if !decodeAuthRequest(w, r, &req) {
		return unlockKeyRow{}, pendingCustody{}, cacustody.Material{}, false
	}
	refuse := func(status int, message string) (unlockKeyRow, pendingCustody, cacustody.Material, bool) {
		s.recordAuth(ctx, event, userID, message)
		writeError(w, status, codeForStatus(status), message)
		return unlockKeyRow{}, pendingCustody{}, cacustody.Material{}, false
	}
	ceremony, err := s.authStore.LoadAndConsumeCeremony(ctx, req.CeremonyID, kind)
	if err != nil || ceremony.PendingUserID != userID {
		return refuse(http.StatusUnauthorized, confirmExpiredMessage)
	}
	if _, ok := role(ctx, w, userID); !ok {
		return unlockKeyRow{}, pendingCustody{}, cacustody.Material{}, false
	}
	var pending pendingCustody
	if jerr := json.Unmarshal(ceremony.SessionData, &pending); jerr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not read the saved ceremony")
		return unlockKeyRow{}, pendingCustody{}, cacustody.Material{}, false
	}

	// The assertion, first.
	parsed, status, message := parseUnlockAssertion(req.Credential)
	if parsed == nil {
		return refuse(status, message)
	}
	key, err := s.authStore.unlockKey(ctx, credentialIDString(parsed.RawID))
	if err != nil || key.UserID != userID || key.RevokedAt != nil {
		return refuse(http.StatusUnauthorized, "the assertion is not from an active unlock key of yours")
	}
	user := dbUser{id: unlockUserHandle(userID), credentials: []webauthn.Credential{key.Credential}}
	cred, err := s.webAuthn.ValidateLogin(user, pending.Session, parsed)
	if err != nil {
		return refuse(http.StatusUnauthorized, "the security key's assertion did not verify: "+err.Error())
	}
	if !cred.Flags.UserVerified {
		return refuse(http.StatusUnauthorized, "the security key did not verify its PIN (ADR-0082 decision 2)")
	}
	if err := s.authStore.touchUnlockKey(ctx, *cred); err != nil {
		return refuse(http.StatusUnauthorized, "the assertion is not from an active unlock key of yours")
	}

	// Then the material.
	m, ok := decodeMaterial(req.Material)
	if !ok {
		return refuse(http.StatusBadRequest, "the material is not readable unlock material; nothing was forwarded")
	}
	return key, pending, m, true
}

// decodeMaterial reads opened unlock material: every field, and no other.
func decodeMaterial(raw json.RawMessage) (cacustody.Material, bool) {
	var m cacustody.Material
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil || !m.Valid() {
		return cacustody.Material{}, false
	}
	return m, true
}

// forwardRefusal maps a custodian's answer to a refusal of the dashboard's
// own: the custodian's 4xx with its reason, anything else as unavailable.
func forwardRefusal(status int, body []byte) (int, string) {
	switch status {
	case http.StatusBadRequest, http.StatusForbidden, http.StatusConflict, http.StatusRequestEntityTooLarge:
		return status, custodianError(body)
	default:
		return http.StatusServiceUnavailable, "the custodian did not complete this; retry"
	}
}

// ---------------------------------------------------------------------------
// POST /api/v1/account/ca-custody/unlock/begin, .../finish
// ---------------------------------------------------------------------------

func (s *Server) handleCustodyUnlockBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	if _, ok := s.ownerOrAdmin(ctx, w, userID); !ok {
		return
	}
	c, ok := s.requireCustody(w)
	if !ok {
		return
	}
	set, err := c.recipients(ctx)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, codeUnavailable, err.Error())
		return
	}
	rows, err := s.authStore.unlockKeys(ctx, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not list the unlock keys")
		return
	}
	keys := activeKeysOf(rows, userID, set)
	if len(keys) == 0 {
		writeError(w, http.StatusConflict, codeConflict, noActiveKeyMessage)
		return
	}
	ch, session, ok := s.custodyChallenge(ctx, w, c, userID, keys)
	if !ok {
		return
	}
	if !s.saveCustodyCeremony(ctx, w, ceremonyKindCAUnlock, userID, pendingCustody{Session: session}, &ch) {
		return
	}
	writeJSON(w, http.StatusOK, ch)
}

func (s *Server) saveCustodyCeremony(ctx context.Context, w http.ResponseWriter, kind, userID string, p pendingCustody, ch *CustodyChallenge) bool {
	body, err := json.Marshal(p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the ceremony")
		return false
	}
	id, err := s.authStore.SaveCeremony(ctx, kind, body, userID, "", authCeremonyTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the ceremony")
		return false
	}
	ch.CeremonyID = id
	return true
}

func (s *Server) handleCustodyUnlockFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	c, ok := s.requireCustody(w)
	if !ok {
		return
	}
	key, _, m, ok := s.verifiedCustodyFinish(w, r, ceremonyKindCAUnlock, AuthEventCAUnlockRefused, s.ownerOrAdmin)
	if !ok {
		return
	}
	status, body, err := c.do(ctx, http.MethodPost, cacustody.PathUnlock, m)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, codeUnavailable, custodyDownMessage)
		return
	}
	if status != http.StatusNoContent && status != http.StatusOK {
		code, message := forwardRefusal(status, body)
		s.recordAuth(ctx, AuthEventCAUnlockRefused, userID, "key "+key.ID+": the custodian refused: "+message)
		writeError(w, code, codeForStatus(code), message)
		return
	}
	s.recordAuth(ctx, AuthEventCAUnlocked, userID, "key "+key.ID+"; custody "+recipientFingerprint(key.CustodyRecipient))
	writeJSON(w, http.StatusOK, CustodyUnlocked{Status: c.status(ctx)})
}

// ---------------------------------------------------------------------------
// POST /api/v1/account/ca-custody/reseal/begin, .../finish, .../confirm
// ---------------------------------------------------------------------------

func (s *Server) ownerOnly(ctx context.Context, w http.ResponseWriter, userID string) (string, bool) {
	return s.operatorRole(ctx, w, userID, unlockKeyOwnerMessage, roleOwner)
}

// proposedSet is the set a reseal applies: the current one, plus every
// unlock key not revoked, less every revoked one. Recipients the API knows
// nothing of (the host's own) stay as they are.
func proposedSet(current []string, rows []unlockKeyRow) []string {
	set := map[string]bool{}
	for _, r := range current {
		set[r] = true
	}
	for _, k := range rows {
		set[k.CustodyRecipient] = k.RevokedAt == nil
	}
	var out []string
	for r, in := range set {
		if in {
			out = append(out, r)
		}
	}
	slices.Sort(out)
	return out
}

func resealView(list []string, rows []unlockKeyRow) []ResealRecipient {
	out := []ResealRecipient{}
	for _, r := range list {
		v := ResealRecipient{Recipient: r, Fingerprint: recipientFingerprint(r),
			Label: "a recipient set on the host (the operator's machine)"}
		for _, k := range rows {
			if k.CustodyRecipient == r {
				v.Label, v.KeyID = "unlock key "+k.Label+" ("+k.Owner+")", k.ID
			}
		}
		out = append(out, v)
	}
	return out
}

func difference(a, b []string) []string {
	var out []string
	for _, r := range a {
		if !slices.Contains(b, r) {
			out = append(out, r)
		}
	}
	return out
}

func (s *Server) handleCustodyResealBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	if _, ok := s.ownerOnly(ctx, w, userID); !ok {
		return
	}
	c, ok := s.requireCustody(w)
	if !ok {
		return
	}
	current, err := c.recipients(ctx)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, codeUnavailable, err.Error())
		return
	}
	rows, err := s.authStore.unlockKeys(ctx, "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not list the unlock keys")
		return
	}
	keys := activeKeysOf(rows, userID, current)
	if len(keys) == 0 {
		writeError(w, http.StatusConflict, codeConflict, noActiveKeyMessage)
		return
	}
	proposed := proposedSet(current.Recipients, rows)
	digest := cacustody.SetDigest(proposed)
	if digest == cacustody.SetDigest(current.Recipients) {
		writeError(w, http.StatusConflict, codeConflict, "the sealed set is already current; nothing to reseal")
		return
	}
	ch, session, ok := s.custodyChallenge(ctx, w, c, userID, keys)
	if !ok {
		return
	}
	if !s.saveCustodyCeremony(ctx, w, ceremonyKindCAReseal, userID,
		pendingCustody{Session: session, Recipients: proposed, SetDigest: digest}, &ch) {
		return
	}
	writeJSON(w, http.StatusOK, ResealChallenge{
		CustodyChallenge: ch,
		Recipients:       resealView(proposed, rows),
		Added:            resealView(difference(proposed, current.Recipients), rows),
		Removed:          resealView(difference(current.Recipients, proposed), rows),
		SetDigest:        digest,
	})
}

func (s *Server) handleCustodyResealFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	c, ok := s.requireCustody(w)
	if !ok {
		return
	}
	key, pending, m, ok := s.verifiedCustodyFinish(w, r, ceremonyKindCAReseal, AuthEventCustodyResealRefused, s.ownerOnly)
	if !ok {
		return
	}
	status, body, err := c.do(ctx, http.MethodPost, cacustody.PathReseal, cacustody.ResealRequest{
		Material: m, Opener: key.CustodyRecipient, Recipients: pending.Recipients, SetDigest: pending.SetDigest})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, codeUnavailable, custodyDownMessage)
		return
	}
	if status != http.StatusOK {
		code, message := forwardRefusal(status, body)
		s.recordAuth(ctx, AuthEventCustodyResealRefused, userID, "key "+key.ID+": the custodian refused: "+message)
		writeError(w, code, codeForStatus(code), message)
		return
	}
	var staged cacustody.ResealStaged
	if jerr := json.Unmarshal(body, &staged); jerr != nil {
		writeError(w, http.StatusServiceUnavailable, codeUnavailable, "the custodian answered something unreadable")
		return
	}
	confirm, err := json.Marshal(pendingResealConfirm{SetDigest: staged.SetDigest, KeyID: key.ID, Recipients: len(staged.Recipients)})
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the confirm")
		return
	}
	confirmID, err := s.authStore.SaveCeremony(ctx, ceremonyKindCAResealConfirm, confirm, userID, "", cacustody.ResealWindow)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the confirm")
		return
	}
	s.recordAuth(ctx, AuthEventCustodyResealStaged, userID, "set "+staged.SetDigest+"; opened by key "+key.ID)
	writeJSON(w, http.StatusOK, ResealStagedAnswer{ConfirmID: confirmID, Staged: staged})
}

// handleCustodyResealConfirm applies the staged copy. It takes no new
// assertion: the confirm is single-use, bound to the reseal whose assertion
// was verified, and what it carries (the check from inside the staged copy)
// proves the same key opened that copy; the custodian checks it.
func (s *Server) handleCustodyResealConfirm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req ResealConfirmRequest
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	if _, ok := s.ownerOnly(ctx, w, userID); !ok {
		return
	}
	c, ok := s.requireCustody(w)
	if !ok {
		return
	}
	refuse := func(status int, message string) {
		s.recordAuth(ctx, AuthEventCustodyResealRefused, userID, message)
		writeError(w, status, codeForStatus(status), message)
	}
	ceremony, err := s.authStore.LoadAndConsumeCeremony(ctx, req.ConfirmID, ceremonyKindCAResealConfirm)
	if err != nil || ceremony.PendingUserID != userID {
		refuse(http.StatusUnauthorized, "this reseal has expired or was already confirmed; start over")
		return
	}
	var pending pendingResealConfirm
	if jerr := json.Unmarshal(ceremony.SessionData, &pending); jerr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not read the saved confirm")
		return
	}
	m, ok := decodeMaterial(req.Material)
	if !ok || req.Check == "" {
		refuse(http.StatusBadRequest, "the confirm needs the material and the check read from the staged copy")
		return
	}
	status, body, err := c.do(ctx, http.MethodPost, cacustody.PathResealConfirm,
		cacustody.ResealConfirm{Material: m, Check: req.Check, SetDigest: pending.SetDigest})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, codeUnavailable, custodyDownMessage)
		return
	}
	if status != http.StatusNoContent && status != http.StatusOK {
		code, message := forwardRefusal(status, body)
		refuse(code, "the custodian refused the confirm: "+message)
		return
	}
	s.recordAuth(ctx, AuthEventCustodyResealed, userID, "set "+pending.SetDigest+"; opened by key "+pending.KeyID)
	writeJSON(w, http.StatusOK, Resealed{SetDigest: pending.SetDigest, Recipients: pending.Recipients})
}
