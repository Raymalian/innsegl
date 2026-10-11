// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/jackc/pgx/v5/pgconn"

	"innsegl.dev/innsegl/internal/cacustody"
	"innsegl.dev/innsegl/internal/unlockkey"
	"innsegl.dev/innsegl/internal/webauthntest"
)

// #613 (RM-365), ADR-0082: the dashboard API enrols hardware security keys as
// unlock keys, lists and revokes them, and runs an unlock and a reseal that
// check a fresh WebAuthn assertion from an unlock key before anything reaches
// the custodian.
//
// The server, the session, the passkeys and the registry are real
// (Postgres, the software authenticator). The browser is this file: it
// derives the age identities from a simulated PRF output with
// internal/unlockkey, as web/src/lib/unlockkey does, and opens the sealed
// material itself. The custodian is a fake for the unit cases and a real one
// on a real OpenBao for AUTH-018.
//
// AUTH-013 to AUTH-018 and API-041 are PROPOSED for doc 07's TC-AUTH and
// TC-API: the next free numbers there and in the code on 2026-10-11.

// ---------------------------------------------------------------------------
// The browser and the security key
// ---------------------------------------------------------------------------

// prfKey is a soft security key with the PRF extension: an authenticator,
// and the hmac-secret it evaluates salts with.
type prfKey struct {
	*webauthntest.Authenticator
	secret []byte
}

func newPRFKey(t *testing.T) *prfKey {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	return &prfKey{Authenticator: newSoftAuthenticator(t), secret: secret}
}

// output is what the browser's PRF extension answers for salt: the
// authenticator's HMAC over WebAuthn's own hash of it.
func (k *prfKey) output(salt []byte) []byte {
	h := sha256.Sum256(append([]byte("WebAuthn PRF\x00"), salt...))
	mac := hmac.New(sha256.New, k.secret)
	mac.Write(h[:])
	return mac.Sum(nil)
}

func (k *prfKey) identity(t *testing.T, salt []byte, p unlockkey.Purpose) *age.X25519Identity {
	t.Helper()
	id, err := unlockkey.Derive(k.output(salt), p)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (k *prfKey) idB64() string {
	return protocol.URLEncodedBase64(k.CredentialID()).String()
}

func prfEnabled() protocol.AuthenticationExtensionsClientOutputs {
	yes := true
	return protocol.AuthenticationExtensionsClientOutputs{PRF: &protocol.PRFOutputs{Enabled: &yes}}
}

// unlockDo is do with the dashboard's own Origin on the request, as a
// browser sends it on every POST.
func unlockDo(t *testing.T, method, target, payload, origin string, cookie *http.Cookie) answer {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	var reader io.Reader
	if payload != "" {
		reader = strings.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		t.Fatal(err)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return answer{status: resp.StatusCode, header: resp.Header, body: body}
}

func (h orgHarness) post(t *testing.T, path string, body any) answer {
	t.Helper()
	return unlockDo(t, http.MethodPost, h.srv.URL+path, mustJSON(t, body), testWebAuthnConfig.RPOrigin, h.cookie)
}

func (h orgHarness) get(t *testing.T, path string) answer {
	t.Helper()
	return unlockDo(t, http.MethodGet, h.srv.URL+path, "", "", h.cookie)
}

// enrolOptions changes one thing about an enrolment, for the refusals.
type enrolOptions struct {
	noPRF        bool
	confirmWith  *webauthntest.Authenticator
	prfResults   bool
	finish       func(*UnlockKeyEnrolFinish)
	afterBegin   func(UnlockKeyEnrolChallenge)
	beginAnswers *answer
}

// enrolUnlockKey is the browser's whole enrolment: the sign-in passkey's
// step-up, create() on the security key, get() with PRF, the two derived
// recipients, and finish.
func (h orgHarness) enrolUnlockKey(t *testing.T, key *prfKey, label string, o enrolOptions) answer {
	t.Helper()
	begin := h.post(t, "/api/v1/account/unlock-keys/begin", UnlockKeyEnrolBegin{Label: label})
	if o.beginAnswers != nil {
		*o.beginAnswers = begin
	}
	if begin.status != http.StatusOK {
		return begin
	}
	var ch UnlockKeyEnrolChallenge
	decodeBody(t, begin, &ch)
	if o.afterBegin != nil {
		o.afterBegin(ch)
	}
	confirmer := h.auth
	if o.confirmWith != nil {
		confirmer = o.confirmWith
	}
	confirmation, err := confirmer.Assert(ch.Confirm, testWebAuthnConfig.RPOrigin, h.userID)
	if err != nil {
		t.Fatal(err)
	}
	key.Extensions = prfEnabled()
	if o.noPRF {
		key.Extensions = protocol.AuthenticationExtensionsClientOutputs{}
	}
	created, err := key.Register(ch.Create, testWebAuthnConfig.RPOrigin)
	if err != nil {
		t.Fatal(err)
	}
	// The browser strips the PRF results before sending the assertion.
	key.Extensions = protocol.AuthenticationExtensionsClientOutputs{}
	if o.prfResults {
		key.Extensions = protocol.AuthenticationExtensionsClientOutputs{PRF: &protocol.PRFOutputs{
			Results: &protocol.PRFValues{First: key.output(ch.CustodySalt), Second: key.output(ch.BackupSalt)}}}
	}
	asserted, err := key.Assert(ch.PRF, testWebAuthnConfig.RPOrigin, "")
	if err != nil {
		t.Fatal(err)
	}
	key.Extensions = protocol.AuthenticationExtensionsClientOutputs{}
	finish := UnlockKeyEnrolFinish{
		CeremonyID: ch.CeremonyID, Confirmation: confirmation, Credential: created, Assertion: asserted,
		CustodyRecipient: key.identity(t, ch.CustodySalt, unlockkey.PurposeCustody).Recipient().String(),
		BackupRecipient:  key.identity(t, ch.BackupSalt, unlockkey.PurposeBackup).Recipient().String(),
	}
	if o.finish != nil {
		o.finish(&finish)
	}
	return h.post(t, "/api/v1/account/unlock-keys/finish", finish)
}

func (h orgHarness) mustEnrol(t *testing.T, key *prfKey, label string) UnlockKey {
	t.Helper()
	a := h.enrolUnlockKey(t, key, label, enrolOptions{})
	if a.status != http.StatusOK {
		t.Fatalf("enrol %q: %d %s", label, a.status, a.body)
	}
	var k UnlockKey
	decodeBody(t, a, &k)
	return k
}

func (h orgHarness) unlockKeys(t *testing.T) UnlockKeyList {
	t.Helper()
	a := h.get(t, "/api/v1/account/unlock-keys")
	if a.status != http.StatusOK {
		t.Fatalf("list: %d %s", a.status, a.body)
	}
	var l UnlockKeyList
	decodeBody(t, a, &l)
	return l
}

func keyByID(l UnlockKeyList, id string) (UnlockKey, bool) {
	for _, k := range l.Keys {
		if k.ID == id {
			return k, true
		}
	}
	return UnlockKey{}, false
}

// openWith is the browser opening a custody challenge's sealed material with
// the key it touched: the salt the server named for that credential, the
// derived custody identity, age.
func openWith(t *testing.T, ch CustodyChallenge, key *prfKey) (cacustody.Material, *age.X25519Identity) {
	t.Helper()
	prf := ch.Response.Extensions.PRF
	if prf == nil {
		t.Fatalf("the challenge asks for no PRF: %+v", ch.Response.Extensions)
	}
	salt, ok := prf.EvalByCredential[key.idB64()]
	if !ok {
		t.Fatalf("the challenge names no salt for this key; it names %d", len(prf.EvalByCredential))
	}
	id := key.identity(t, salt.First, unlockkey.PurposeCustody)
	m, err := cacustody.Open(ch.Sealed, []age.Identity{id})
	if err != nil {
		t.Fatalf("the browser cannot open the sealed material with this key: %v", err)
	}
	return m, id
}

func (h orgHarness) custodyFinish(t *testing.T, route string, ch CustodyChallenge, key *prfKey, material any) answer {
	t.Helper()
	credential, err := key.Assert(ch.CredentialAssertion, testWebAuthnConfig.RPOrigin, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(material)
	if err != nil {
		t.Fatal(err)
	}
	return h.post(t, route, CustodyFinish{CeremonyID: ch.CeremonyID, Credential: credential, Material: raw})
}

// unlockWith is the dashboard's unlock, start to end, with one key.
func (h orgHarness) unlockWith(t *testing.T, key *prfKey) answer {
	t.Helper()
	begin := h.post(t, "/api/v1/account/ca-custody/unlock/begin", struct{}{})
	if begin.status != http.StatusOK {
		return begin
	}
	var ch CustodyChallenge
	decodeBody(t, begin, &ch)
	m, _ := openWith(t, ch, key)
	return h.custodyFinish(t, "/api/v1/account/ca-custody/unlock/finish", ch, key, m)
}

// ---------------------------------------------------------------------------
// A fake custodian, for the unit cases
// ---------------------------------------------------------------------------

type fakeCustodian struct {
	mu       sync.Mutex
	material cacustody.Material
	sealed   []byte
	set      []string
	locked   bool
	calls    []string
	unlocks  int
	srv      *httptest.Server
	// script answers a path with a fixed status and body, before anything
	// else: the error cases.
	script map[string]scripted
}

type scripted struct {
	status int
	body   string
}

func (f *fakeCustodian) answer(path string, status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.script == nil {
		f.script = map[string]scripted{}
	}
	f.script[path] = scripted{status: status, body: body}
}

func newFakeCustodian(t *testing.T, host *age.X25519Identity) *fakeCustodian {
	t.Helper()
	f := &fakeCustodian{
		material: cacustody.Material{UnsealKey: "unseal-" + randHex(t), RoleID: "role-" + randHex(t),
			SecretID: "secret-" + randHex(t), BackupRoleID: "brole-" + randHex(t), BackupSecretID: "bsecret-" + randHex(t)},
		locked: true,
	}
	f.reseal(t, host.Recipient().String())
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, "status")
		writeJSON(w, http.StatusOK, cacustody.Status{Initialized: true, Sealed: f.locked, CanSign: !f.locked})
	})
	mux.HandleFunc("/material", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, "material")
		_, werr := w.Write(f.sealed)
		discardError(werr)
	})
	mux.HandleFunc("/recipients", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, "recipients")
		writeJSON(w, http.StatusOK, cacustody.RecipientSet{Recipients: f.set, Digest: cacustody.SetDigest(f.set), Recorded: true})
	})
	mux.HandleFunc("/unlock", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, "unlock")
		f.unlocks++
		var m cacustody.Material
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ca custody: the unlock is not material"})
			return
		}
		if m != f.material {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "ca custody: the unlock material was not accepted"})
			return
		}
		f.locked = false
		w.WriteHeader(http.StatusNoContent)
	})
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		s, ok := f.script[r.URL.Path]
		f.mu.Unlock()
		if !ok {
			mux.ServeHTTP(w, r)
			return
		}
		w.WriteHeader(s.status)
		_, werr := w.Write([]byte(s.body))
		discardError(werr)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// reseal seals the fake's material to set, as a CLI reseal would.
func (f *fakeCustodian) reseal(t *testing.T, set ...string) {
	t.Helper()
	var rs []age.Recipient
	for _, s := range set {
		r, err := age.ParseX25519Recipient(s)
		if err != nil {
			t.Fatal(err)
		}
		rs = append(rs, r)
	}
	sealed, err := cacustody.Seal(f.material, rs)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sealed, f.set = sealed, slices.Sorted(slices.Values(set))
}

func (f *fakeCustodian) unlockCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.unlocks
}

func randHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func newHostIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// newUnlockHarness is newOrgHarness with a custodian at custodianURL.
func newUnlockHarness(t *testing.T, role, custodianURL string) orgHarness {
	t.Helper()
	return newOrgHarness(t, role, true, func(c *ServerConfig) { c.CACustodianURL = custodianURL })
}

// ---------------------------------------------------------------------------
// AUTH-013: enrolment takes a hardware key with PRF and a PIN, an owner or
// admin of the operator organisation, and a fresh sign-in passkey
// ---------------------------------------------------------------------------

func TestAUTH013EnrolAHardwareKeyWithPRFAndAPIN(t *testing.T) {
	f := newFakeCustodian(t, newHostIdentity(t))
	h := newUnlockHarness(t, roleOwner, f.srv.URL)
	key := newPRFKey(t)

	var ch UnlockKeyEnrolChallenge
	a := h.enrolUnlockKey(t, key, "blue key", enrolOptions{afterBegin: func(c UnlockKeyEnrolChallenge) { ch = c }})
	if a.status != http.StatusOK {
		t.Fatalf("enrol: %d %s", a.status, a.body)
	}

	sel := ch.Create.Response.AuthenticatorSelection
	if sel.AuthenticatorAttachment != protocol.CrossPlatform || sel.ResidentKey != protocol.ResidentKeyRequirementDiscouraged ||
		sel.UserVerification != protocol.VerificationRequired {
		t.Errorf("create() asks for %+v; want a cross-platform, non-discoverable credential with user verification", sel)
	}
	if ch.Create.Response.Extensions.PRF == nil {
		t.Error("create() does not ask for the PRF extension")
	}
	if ch.Confirm.Response.UserVerification != protocol.VerificationRequired ||
		ch.PRF.Response.UserVerification != protocol.VerificationRequired {
		t.Error("an assertion of the enrolment does not require user verification")
	}
	if ch.PRF.Response.Extensions.PRF == nil ||
		!bytes.Equal(ch.PRF.Response.Extensions.PRF.Eval.First, ch.CustodySalt) ||
		!bytes.Equal(ch.PRF.Response.Extensions.PRF.Eval.Second, ch.BackupSalt) {
		t.Error("the PRF assertion does not evaluate the two salts")
	}
	if len(ch.CustodySalt) != 32 || len(ch.BackupSalt) != 32 || bytes.Equal(ch.CustodySalt, ch.BackupSalt) {
		t.Errorf("salts: %d and %d bytes, equal %v", len(ch.CustodySalt), len(ch.BackupSalt), bytes.Equal(ch.CustodySalt, ch.BackupSalt))
	}
	if ch.Format != unlockkey.FormatVersion {
		t.Errorf("format %q, want %q", ch.Format, unlockkey.FormatVersion)
	}

	var k UnlockKey
	decodeBody(t, a, &k)
	wantCustody := key.identity(t, ch.CustodySalt, unlockkey.PurposeCustody).Recipient().String()
	if k.Label != "blue key" || k.State != "pending" || !k.Mine || k.CustodyRecipient != wantCustody ||
		k.CustodyFingerprint == "" || k.BackupFingerprint == "" {
		t.Errorf("the enrolled key: %+v", k)
	}
	l := h.unlockKeys(t)
	if got, ok := keyByID(l, k.ID); !ok || got.State != "pending" {
		t.Errorf("the list after enrolment: %+v", l)
	}
	if !l.Custody.Enabled || !l.Custody.Reachable || l.Custody.SetDigest != cacustody.SetDigest(f.set) {
		t.Errorf("the list's custody: %+v", l.Custody)
	}

	c, ctx := ownerConnAPI(t, h.ownerDSN)
	var custodySalt, backupSalt []byte
	var format string
	if err := c.QueryRow(ctx, `SELECT custody_salt, backup_salt, format FROM innsegl_auth.unlock_keys
		WHERE credential_id = $1`, k.ID).Scan(&custodySalt, &backupSalt, &format); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(custodySalt, ch.CustodySalt) || !bytes.Equal(backupSalt, ch.BackupSalt) || format != unlockkey.FormatVersion {
		t.Error("the row does not hold the salts the browser was given")
	}
	if events := h.authEventDetails(t); !strings.Contains(events, AuthEventUnlockKeyAdded+":") {
		t.Errorf("no %s event:\n%s", AuthEventUnlockKeyAdded, events)
	}
}

func TestAUTH013EnrolmentRefusals(t *testing.T) {
	f := newFakeCustodian(t, newHostIdentity(t))
	h := newUnlockHarness(t, roleAdmin, f.srv.URL)
	other := newSoftAuthenticator(t)

	cases := []struct {
		name   string
		key    func(*prfKey)
		opts   enrolOptions
		status int
		reason string
	}{
		{name: "no PRF", opts: enrolOptions{noPRF: true}, status: http.StatusBadRequest, reason: "PRF"},
		{name: "a synced passkey", key: func(k *prfKey) { k.BackupEligible = true }, status: http.StatusBadRequest, reason: "backup-eligible"},
		{name: "no PIN", key: func(k *prfKey) { k.WithoutUserVerification = true }, status: http.StatusUnauthorized, reason: "did not verify"},
		{name: "no fresh sign-in passkey", opts: enrolOptions{confirmWith: other}, status: http.StatusUnauthorized, reason: "passkey"},
		{name: "the PRF output sent", opts: enrolOptions{prfResults: true}, status: http.StatusBadRequest, reason: "PRF output"},
		{name: "a recipient that is not age X25519", opts: enrolOptions{finish: func(f *UnlockKeyEnrolFinish) {
			f.CustodyRecipient = "age1tag1qwrtxjm9e7t3jkqrs4nzmeyzvcuv8v6qxx9t2vy9xrhcjmfz2lnzgpm9fpa"
		}}, status: http.StatusBadRequest, reason: "recipient"},
		{name: "one recipient twice", opts: enrolOptions{finish: func(f *UnlockKeyEnrolFinish) {
			f.BackupRecipient = f.CustodyRecipient
		}}, status: http.StatusBadRequest, reason: "recipient"},
		{name: "a label too long", opts: enrolOptions{}, status: http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key := newPRFKey(t)
			if c.key != nil {
				c.key(key)
			}
			label := "key"
			if c.name == "a label too long" {
				label = strings.Repeat("x", 65)
			}
			a := h.enrolUnlockKey(t, key, label, c.opts)
			if a.status != c.status {
				t.Fatalf("status %d, want %d: %s", a.status, c.status, a.body)
			}
			if c.reason != "" && !strings.Contains(string(a.body), c.reason) {
				t.Errorf("the refusal does not say %q: %s", c.reason, a.body)
			}
		})
	}
	if l := h.unlockKeys(t); len(l.Keys) != 0 {
		t.Errorf("a refused enrolment stored a key: %+v", l.Keys)
	}
	events := h.authEventDetails(t)
	for _, want := range []string{"PRF", "backup-eligible", "did not verify"} {
		if !strings.Contains(events, AuthEventUnlockKeyRefused+":") || !strings.Contains(events, want) {
			t.Errorf("no %s event saying %q:\n%s", AuthEventUnlockKeyRefused, want, events)
		}
	}
}

func TestAUTH013OnlyAnOwnerOrAdminOfTheOperatorOrganisationEnrols(t *testing.T) {
	f := newFakeCustodian(t, newHostIdentity(t))
	h := newUnlockHarness(t, roleMember, f.srv.URL)
	if a := h.post(t, "/api/v1/account/unlock-keys/begin", UnlockKeyEnrolBegin{Label: "k"}); a.status != http.StatusForbidden {
		t.Errorf("a member begins an enrolment: %d %s", a.status, a.body)
	}
	if a := h.get(t, "/api/v1/account/unlock-keys"); a.status != http.StatusForbidden {
		t.Errorf("a member lists the unlock keys: %d %s", a.status, a.body)
	}

	// An owner of an organisation that is not the operator's.
	h.orgs.mu.Lock()
	h.orgs.memberships[h.userID] = []OrgMembership{{AccountID: orgB, Name: "example-team", Role: roleOwner}}
	h.orgs.mu.Unlock()
	if a := h.post(t, "/api/v1/account/unlock-keys/begin", UnlockKeyEnrolBegin{Label: "k"}); a.status != http.StatusForbidden {
		t.Errorf("an owner of another organisation begins an enrolment: %d %s", a.status, a.body)
	}

	// The role is checked again at finish: an admin demoted in between.
	h.orgs.mu.Lock()
	h.orgs.memberships[h.userID] = []OrgMembership{{AccountID: orgA, Name: "example-org", Operator: true, Role: roleAdmin}}
	h.orgs.mu.Unlock()
	key := newPRFKey(t)
	a := h.enrolUnlockKey(t, key, "k", enrolOptions{afterBegin: func(UnlockKeyEnrolChallenge) {
		h.orgs.mu.Lock()
		h.orgs.memberships[h.userID] = []OrgMembership{{AccountID: orgA, Name: "example-org", Operator: true, Role: roleMember}}
		h.orgs.mu.Unlock()
	}})
	if a.status != http.StatusForbidden {
		t.Errorf("a finish after a demotion: %d %s", a.status, a.body)
	}
}

// ---------------------------------------------------------------------------
// AUTH-014: an unlock verifies the assertion from an active unlock key before
// it reads the material, and forwards it once
// ---------------------------------------------------------------------------

func TestAUTH014UnlockChecksTheAssertionBeforeTheMaterial(t *testing.T) {
	host := newHostIdentity(t)
	f := newFakeCustodian(t, host)
	h := newUnlockHarness(t, roleAdmin, f.srv.URL)
	key := newPRFKey(t)
	k := h.mustEnrol(t, key, "blue key")
	f.reseal(t, host.Recipient().String(), k.CustodyRecipient)
	if got, _ := keyByID(h.unlockKeys(t), k.ID); got.State != "active" {
		t.Fatalf("a key in the sealed set is %q, want active", got.State)
	}

	begin := func() CustodyChallenge {
		t.Helper()
		a := h.post(t, "/api/v1/account/ca-custody/unlock/begin", struct{}{})
		if a.status != http.StatusOK {
			t.Fatalf("unlock/begin: %d %s", a.status, a.body)
		}
		var ch CustodyChallenge
		decodeBody(t, a, &ch)
		return ch
	}

	// A key that is not enrolled, and material that is not material: the
	// assertion is refused first, and nothing reaches the custodian.
	ch := begin()
	stranger := newPRFKey(t)
	if a := h.custodyFinish(t, "/api/v1/account/ca-custody/unlock/finish", ch, stranger, 12); a.status != http.StatusUnauthorized {
		t.Errorf("a stranger's assertion with junk material: %d %s; want 401, the assertion before the material", a.status, a.body)
	}
	// The ceremony is spent: the real key cannot reuse it.
	m, _ := openWith(t, ch, key)
	if a := h.custodyFinish(t, "/api/v1/account/ca-custody/unlock/finish", ch, key, m); a.status != http.StatusUnauthorized {
		t.Errorf("a replayed ceremony: %d %s", a.status, a.body)
	}
	// A good assertion and junk material: the material is read, and refused.
	ch = begin()
	if a := h.custodyFinish(t, "/api/v1/account/ca-custody/unlock/finish", ch, key, 12); a.status != http.StatusBadRequest {
		t.Errorf("a good assertion with junk material: %d %s", a.status, a.body)
	}
	if n := f.unlockCalls(); n != 0 {
		t.Fatalf("the custodian was asked to unlock %d time(s) before any good finish", n)
	}

	// Wrong material: forwarded once, and the custodian's refusal stands.
	ch = begin()
	wrong := m
	wrong.UnsealKey = "not-the-unseal-key"
	if a := h.custodyFinish(t, "/api/v1/account/ca-custody/unlock/finish", ch, key, wrong); a.status != http.StatusForbidden {
		t.Errorf("wrong material: %d %s", a.status, a.body)
	}

	// The real thing.
	a := h.unlockWith(t, key)
	if a.status != http.StatusOK {
		t.Fatalf("unlock: %d %s", a.status, a.body)
	}
	var done CustodyUnlocked
	decodeBody(t, a, &done)
	if !done.Status.Enabled || done.Status.Sealed || !done.Status.CanSign {
		t.Errorf("after the unlock: %+v", done.Status)
	}
	if n := f.unlockCalls(); n != 2 {
		t.Errorf("the custodian was asked to unlock %d times; want 2 (the wrong material, then the right)", n)
	}
	events := h.authEventDetails(t)
	for _, want := range []string{AuthEventCAUnlocked + ":", AuthEventCAUnlockRefused + ":"} {
		if !strings.Contains(events, want) {
			t.Errorf("no %q event:\n%s", want, events)
		}
	}
	if got, _ := keyByID(h.unlockKeys(t), k.ID); got.LastUsedAt == nil {
		t.Error("the key's last use is not recorded")
	}
}

func TestAUTH014APendingOrRevokedKeyCannotUnlock(t *testing.T) {
	host := newHostIdentity(t)
	f := newFakeCustodian(t, host)
	h := newUnlockHarness(t, roleOwner, f.srv.URL)
	key := newPRFKey(t)
	k := h.mustEnrol(t, key, "blue key")

	if a := h.post(t, "/api/v1/account/ca-custody/unlock/begin", struct{}{}); a.status != http.StatusConflict {
		t.Errorf("unlock with only a pending key: %d %s", a.status, a.body)
	}

	f.reseal(t, host.Recipient().String(), k.CustodyRecipient)
	a := h.post(t, "/api/v1/account/ca-custody/unlock/begin", struct{}{})
	if a.status != http.StatusOK {
		t.Fatalf("unlock/begin: %d %s", a.status, a.body)
	}
	var ch CustodyChallenge
	decodeBody(t, a, &ch)
	m, _ := openWith(t, ch, key)

	// Revoked between begin and finish.
	if r := h.confirmRevoke(t, k.ID, h.auth); r.status != http.StatusOK {
		t.Fatalf("revoke: %d %s", r.status, r.body)
	}
	if a := h.custodyFinish(t, "/api/v1/account/ca-custody/unlock/finish", ch, key, m); a.status != http.StatusUnauthorized {
		t.Errorf("a key revoked since begin: %d %s", a.status, a.body)
	}
	if a := h.post(t, "/api/v1/account/ca-custody/unlock/begin", struct{}{}); a.status != http.StatusConflict {
		t.Errorf("unlock with only a revoked key: %d %s", a.status, a.body)
	}
	if n := f.unlockCalls(); n != 0 {
		t.Errorf("the custodian was asked to unlock %d time(s)", n)
	}
}

func TestAUTH014WithCustodyOffTheRoutesSaySo(t *testing.T) {
	h := newUnlockHarness(t, roleOwner, "")
	if a := h.post(t, "/api/v1/account/ca-custody/unlock/begin", struct{}{}); a.status != http.StatusServiceUnavailable ||
		!strings.Contains(string(a.body), "custody is off") {
		t.Errorf("unlock with custody off: %d %s", a.status, a.body)
	}
	a := h.get(t, "/api/v1/account/ca-custody")
	var st cacustody.CoreStatus
	decodeBody(t, a, &st)
	if a.status != http.StatusOK || st.Enabled {
		t.Errorf("status with custody off: %d %+v", a.status, st)
	}
	key := newPRFKey(t)
	k := h.mustEnrol(t, key, "spare")
	l := h.unlockKeys(t)
	if l.Custody.Enabled {
		t.Errorf("the list says custody is on: %+v", l.Custody)
	}
	if got, _ := keyByID(l, k.ID); got.State != "pending" {
		t.Errorf("with custody off a key is %q, want pending", got.State)
	}
}

func TestAUTH014TheStatusRouteIsTheCustodiansAnswer(t *testing.T) {
	f := newFakeCustodian(t, newHostIdentity(t))
	h := newUnlockHarness(t, roleAdmin, f.srv.URL)
	a := h.get(t, "/api/v1/account/ca-custody")
	var st cacustody.CoreStatus
	decodeBody(t, a, &st)
	if a.status != http.StatusOK || !st.Enabled || !st.Initialized || !st.Sealed || st.CanSign {
		t.Errorf("status: %d %+v", a.status, st)
	}
	f.srv.Close()
	a = h.get(t, "/api/v1/account/ca-custody")
	decodeBody(t, a, &st)
	if a.status != http.StatusOK || !st.Enabled || st.Error == "" {
		t.Errorf("status with the custodian down: %d %+v", a.status, st)
	}
	if l := h.unlockKeys(t); l.Custody.Reachable || l.Custody.Error == "" {
		t.Errorf("the list with the custodian down: %+v", l.Custody)
	}
	if a := h.post(t, "/api/v1/account/ca-custody/unlock/begin", struct{}{}); a.status != http.StatusServiceUnavailable {
		t.Errorf("unlock with the custodian down: %d %s", a.status, a.body)
	}
}

// ---------------------------------------------------------------------------
// AUTH-015: no material, PRF output or derived identity in any answer or
// record
// ---------------------------------------------------------------------------

func TestAUTH015NoMaterialOrPRFOutputReachesARecordOrAnAnswer(t *testing.T) {
	host := newHostIdentity(t)
	f := newFakeCustodian(t, host)
	h := newUnlockHarness(t, roleOwner, f.srv.URL)
	key := newPRFKey(t)

	var ch UnlockKeyEnrolChallenge
	enrolled := h.enrolUnlockKey(t, key, "blue key", enrolOptions{afterBegin: func(c UnlockKeyEnrolChallenge) { ch = c }})
	if enrolled.status != http.StatusOK {
		t.Fatalf("enrol: %d %s", enrolled.status, enrolled.body)
	}
	var k UnlockKey
	decodeBody(t, enrolled, &k)
	f.reseal(t, host.Recipient().String(), k.CustodyRecipient)

	// An assertion that carries the PRF results is refused, and the
	// results are not repeated anywhere.
	begin := h.post(t, "/api/v1/account/ca-custody/unlock/begin", struct{}{})
	var uc CustodyChallenge
	decodeBody(t, begin, &uc)
	m, id := openWith(t, uc, key)
	key.Extensions = protocol.AuthenticationExtensionsClientOutputs{PRF: &protocol.PRFOutputs{
		Results: &protocol.PRFValues{First: key.output(ch.CustodySalt)}}}
	leaked := h.custodyFinish(t, "/api/v1/account/ca-custody/unlock/finish", uc, key, m)
	key.Extensions = protocol.AuthenticationExtensionsClientOutputs{}
	if leaked.status != http.StatusBadRequest || !strings.Contains(string(leaked.body), "PRF output") {
		t.Errorf("an assertion carrying the PRF output: %d %s", leaked.status, leaked.body)
	}
	if f.unlockCalls() != 0 {
		t.Error("material sent beside a PRF output was forwarded")
	}

	done := h.unlockWith(t, key)
	if done.status != http.StatusOK {
		t.Fatalf("unlock: %d %s", done.status, done.body)
	}

	secrets := []string{m.UnsealKey, m.RoleID, m.SecretID, m.BackupRoleID, m.BackupSecretID, id.String()}
	for _, salt := range [][]byte{ch.CustodySalt, ch.BackupSalt} {
		out := key.output(salt)
		secrets = append(secrets, hex.EncodeToString(out), base64.RawURLEncoding.EncodeToString(out),
			base64.StdEncoding.EncodeToString(out))
	}
	secrets = append(secrets, key.identity(t, ch.BackupSalt, unlockkey.PurposeBackup).String())
	records := h.authEventDetails(t) + "\n" + h.auditRows(t) + "\n" + h.unlockKeyRows(t)
	for _, body := range []answer{enrolled, leaked, done, h.get(t, "/api/v1/account/unlock-keys")} {
		records += "\n" + string(body.body)
	}
	for _, s := range secrets {
		if strings.Contains(records, s) {
			t.Errorf("a secret reached a record or an answer: %.12s…", s)
		}
	}
}

func (h orgHarness) auditRows(t *testing.T) string {
	t.Helper()
	c, ctx := ownerConnAPI(t, h.ownerDSN)
	var s string
	if err := c.QueryRow(ctx, `SELECT coalesce(string_agg(action || subject || detail::text, E'\n'), '')
		FROM innsegl_auth.audit`).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func (h orgHarness) unlockKeyRows(t *testing.T) string {
	t.Helper()
	c, ctx := ownerConnAPI(t, h.ownerDSN)
	var s string
	if err := c.QueryRow(ctx, `SELECT coalesce(string_agg(row_to_json(k)::text, E'\n'), '')
		FROM innsegl_auth.unlock_keys k`).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// ---------------------------------------------------------------------------
// AUTH-016: the routes refuse a foreign or missing Origin, and no session
// ---------------------------------------------------------------------------

func TestAUTH016UnlockKeyRoutesRefuseAForeignOriginOrNoSession(t *testing.T) {
	f := newFakeCustodian(t, newHostIdentity(t))
	h := newUnlockHarness(t, roleOwner, f.srv.URL)
	posts := []string{
		"/api/v1/account/unlock-keys/begin", "/api/v1/account/unlock-keys/finish",
		"/api/v1/account/unlock-keys/revoke/begin", "/api/v1/account/unlock-keys/revoke/finish",
		"/api/v1/account/ca-custody/unlock/begin", "/api/v1/account/ca-custody/unlock/finish",
		"/api/v1/account/ca-custody/reseal/begin", "/api/v1/account/ca-custody/reseal/finish",
		"/api/v1/account/ca-custody/reseal/confirm",
	}
	for _, p := range posts {
		if a := unlockDo(t, http.MethodPost, h.srv.URL+p, "{}", "https://evil.example", h.cookie); a.status != http.StatusForbidden {
			t.Errorf("%s from another origin: %d", p, a.status)
		}
		if a := unlockDo(t, http.MethodPost, h.srv.URL+p, "{}", "", h.cookie); a.status != http.StatusForbidden {
			t.Errorf("%s with no Origin: %d", p, a.status)
		}
		if a := unlockDo(t, http.MethodPost, h.srv.URL+p, "{}", testWebAuthnConfig.RPOrigin, nil); a.status != http.StatusUnauthorized {
			t.Errorf("%s with no session: %d", p, a.status)
		}
	}
	for _, p := range []string{"/api/v1/account/unlock-keys", "/api/v1/account/ca-custody"} {
		if a := unlockDo(t, http.MethodGet, h.srv.URL+p, "", "", nil); a.status != http.StatusUnauthorized {
			t.Errorf("GET %s with no session: %d", p, a.status)
		}
	}
	if f.unlockCalls() != 0 {
		t.Error("a refused request reached the custodian")
	}
}

// ---------------------------------------------------------------------------
// AUTH-017: revoking is forward-only and takes a fresh passkey; a reseal is
// the owner's
// ---------------------------------------------------------------------------

// confirmRevoke is revoke/begin, the sign-in passkey, revoke/finish.
func (h orgHarness) confirmRevoke(t *testing.T, id string, auth *webauthntest.Authenticator) answer {
	t.Helper()
	begin := h.post(t, "/api/v1/account/unlock-keys/revoke/begin", UnlockKeyRevoke{ID: id})
	if begin.status != http.StatusOK {
		return begin
	}
	return unlockDo(t, http.MethodPost, h.srv.URL+"/api/v1/account/unlock-keys/revoke/finish",
		h.assertion(t, begin, auth), testWebAuthnConfig.RPOrigin, h.cookie)
}

func TestAUTH017RevokingIsForwardOnlyAndTakesAFreshPasskey(t *testing.T) {
	f := newFakeCustodian(t, newHostIdentity(t))
	h := newUnlockHarness(t, roleAdmin, f.srv.URL)
	key := newPRFKey(t)
	k := h.mustEnrol(t, key, "blue key")

	if a := h.confirmRevoke(t, k.ID, newSoftAuthenticator(t)); a.status != http.StatusUnauthorized {
		t.Errorf("a revoke with another passkey: %d %s", a.status, a.body)
	}
	if a := h.confirmRevoke(t, "no-such-key", h.auth); a.status != http.StatusNotFound {
		t.Errorf("a revoke of no key: %d %s", a.status, a.body)
	}
	a := h.confirmRevoke(t, k.ID, h.auth)
	if a.status != http.StatusOK {
		t.Fatalf("revoke: %d %s", a.status, a.body)
	}
	var revoked UnlockKey
	decodeBody(t, a, &revoked)
	if revoked.State != "revoked" || revoked.RevokedAt == nil {
		t.Errorf("the revoked key: %+v", revoked)
	}
	if a := h.confirmRevoke(t, k.ID, h.auth); a.status != http.StatusConflict {
		t.Errorf("a second revoke: %d %s", a.status, a.body)
	}
	if !strings.Contains(h.authEventDetails(t), AuthEventUnlockKeyRevoked+":") {
		t.Error("no revoke event")
	}

	// The database holds the line for every role.
	c, ctx := ownerConnAPI(t, h.ownerDSN)
	for _, stmt := range []string{
		`UPDATE innsegl_auth.unlock_keys SET revoked_at = NULL, revoked_by = NULL WHERE credential_id = $1`,
		`UPDATE innsegl_auth.unlock_keys SET custody_recipient = backup_recipient || 'x' WHERE credential_id = $1`,
		`DELETE FROM innsegl_auth.unlock_keys WHERE credential_id = $1`,
	} {
		_, err := c.Exec(ctx, stmt, k.ID)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "IN009" {
			t.Errorf("as the owner, %q: %v; want IN009", stmt, err)
		}
	}
	_, err := h.authStore.pool.Exec(ctx, `DELETE FROM innsegl_auth.unlock_keys WHERE credential_id = $1`, k.ID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Errorf("as the auth writer, DELETE: %v; want 42501", err)
	}
}

func TestAUTH017OnlyAnOwnerRevokesSomeoneElsesKeyAndOnlyAnOwnerReseals(t *testing.T) {
	f := newFakeCustodian(t, newHostIdentity(t))
	h := newUnlockHarness(t, roleOwner, f.srv.URL)
	key := newPRFKey(t)
	k := h.mustEnrol(t, key, "owner's key")

	// The same person as an admin: their own key, yes; but not a reseal.
	h.orgs.mu.Lock()
	h.orgs.memberships[h.userID] = []OrgMembership{{AccountID: orgA, Name: "example-org", Operator: true, Role: roleAdmin}}
	h.orgs.mu.Unlock()
	if a := h.post(t, "/api/v1/account/ca-custody/reseal/begin", struct{}{}); a.status != http.StatusForbidden {
		t.Errorf("an admin begins a reseal: %d %s", a.status, a.body)
	}
	if a := h.post(t, "/api/v1/account/ca-custody/reseal/confirm", ResealConfirmRequest{ConfirmID: "x"}); a.status != http.StatusForbidden {
		t.Errorf("an admin confirms a reseal: %d %s", a.status, a.body)
	}

	// Someone else's key: an admin may not revoke it.
	c, ctx := ownerConnAPI(t, h.ownerDSN)
	if _, err := c.Exec(ctx, `INSERT INTO innsegl_auth.users (user_id, display_name) VALUES ('someone-else', 'Else')`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, `UPDATE innsegl_auth.unlock_keys SET user_id = 'someone-else' WHERE credential_id = $1`, k.ID); err == nil {
		t.Fatal("a key changed hands")
	}
	other := insertForeignUnlockKey(t, h, "someone-else")
	if a := h.post(t, "/api/v1/account/unlock-keys/revoke/begin", UnlockKeyRevoke{ID: other}); a.status != http.StatusForbidden {
		t.Errorf("an admin revokes someone else's key: %d %s", a.status, a.body)
	}
	h.orgs.mu.Lock()
	h.orgs.memberships[h.userID][0].Role = roleOwner
	h.orgs.mu.Unlock()
	if a := h.confirmRevoke(t, other, h.auth); a.status != http.StatusOK {
		t.Errorf("an owner revokes someone else's key: %d %s", a.status, a.body)
	}
	l := h.unlockKeys(t)
	if got, ok := keyByID(l, other); !ok || got.Mine || got.Owner != "Else" {
		t.Errorf("someone else's key in the list: %+v", got)
	}
}

// insertForeignUnlockKey enrols a key for another user straight into the
// table, as that user's own enrolment would have.
func insertForeignUnlockKey(t *testing.T, h orgHarness, userID string) string {
	t.Helper()
	c, ctx := ownerConnAPI(t, h.ownerDSN)
	custody, backup := newHostIdentity(t).Recipient().String(), newHostIdentity(t).Recipient().String()
	id := "FOREIGN" + strings.ToUpper(randHex(t))
	salt1, salt2 := make([]byte, 32), make([]byte, 32)
	_, _ = rand.Read(salt1)
	_, _ = rand.Read(salt2)
	if _, err := c.Exec(ctx, `INSERT INTO innsegl_auth.unlock_keys
		(credential_id, user_id, label, credential, custody_recipient, backup_recipient, custody_salt, backup_salt, format)
		VALUES ($1, $2, 'their key', '{}'::jsonb, $3, $4, $5, $6, $7)`,
		id, userID, custody, backup, salt1, salt2, unlockkey.FormatVersion); err != nil {
		t.Fatal(err)
	}
	return id
}

// ---------------------------------------------------------------------------
// API-041: the unlock-key routes are rate limited per person
// ---------------------------------------------------------------------------

func TestAPI041UnlockKeyRoutesAreRateLimitedPerPerson(t *testing.T) {
	f := newFakeCustodian(t, newHostIdentity(t))
	h := newUnlockHarness(t, roleOwner, f.srv.URL)
	var limited answer
	for i := 0; i < unlockKeyBurst+1; i++ {
		a := h.post(t, "/api/v1/account/unlock-keys/begin", UnlockKeyEnrolBegin{Label: "k"})
		if a.status == http.StatusTooManyRequests {
			limited = a
			break
		}
		if a.status != http.StatusOK {
			t.Fatalf("begin %d: %d %s", i, a.status, a.body)
		}
	}
	if limited.status != http.StatusTooManyRequests || limited.header.Get("Retry-After") == "" {
		t.Fatalf("after %d requests: %d, Retry-After %q", unlockKeyBurst+1, limited.status, limited.header.Get("Retry-After"))
	}
	// Reads are not limited.
	if a := h.get(t, "/api/v1/account/unlock-keys"); a.status != http.StatusOK {
		t.Errorf("a read after the limit: %d", a.status)
	}
}

func TestAPI041TheLimiterRefillsOverTime(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	l := newUnlockLimiter(func() time.Time { return now })
	for range unlockKeyBurst {
		if _, ok := l.allow("u"); !ok {
			t.Fatal("refused inside the burst")
		}
	}
	wait, ok := l.allow("u")
	if ok || wait <= 0 {
		t.Fatalf("past the burst: ok %v, wait %s", ok, wait)
	}
	if _, ok := l.allow("someone-else"); !ok {
		t.Error("one person's limit refused another")
	}
	now = now.Add(unlockKeyRefill)
	if _, ok := l.allow("u"); !ok {
		t.Error("no token back after one refill period")
	}
}
