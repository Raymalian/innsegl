// SPDX-License-Identifier: Apache-2.0

package devstack

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/go-webauthn/webauthn/protocol"

	"innsegl.dev/innsegl/internal/api"
	"innsegl.dev/innsegl/internal/cacustody"
	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/unlockkey"
)

// ---------------------------------------------------------------------------
// OPS-208 (PROPOSED for doc 07's TC-OPS; #617, ADR-0082) — an in-place
// update onto the second unlock device keeps a dev stack's data and serves
// the new surface. The rehearsal: a dev stack at the previous main, custody
// on, left running; phase "before" enrols the owner and leaves a session, a
// sign-in, a step-up and a minted token behind; `make update` from the new
// code; phase "after" checks what the update did to that data. The shell
// half (make update's exit code, every container healthy, signing before
// and after, a second update a no-op) is in runbooks/ca-custody.md.
// ---------------------------------------------------------------------------

func TestOPS208AnInPlaceUpdateKeepsTheDevStacksDataAndServesTheNewSurface(t *testing.T) {
	s := requireStack(t)
	switch phase := os.Getenv("INNSEGL_DEVSTACK_PHASE"); phase {
	case "before":
		o := s.theOwner(t)
		org := s.operatorOrg(t, o)
		// A step-up and a token: ceremony and token rows the update's
		// migrations meet as existing data.
		var tok api.EnrolmentToken
		s.confirm(t, o, "/api/v1/account/enrolment-tokens/begin", "/api/v1/account/enrolment-tokens/finish",
			api.EnrolmentTokenRequest{OrganisationID: org, Kind: "workstation"}, &tok)
		if tok.Token == "" {
			t.Fatal("no token was minted")
		}
		// A sign-in the update must carry: the cookie stays in the state.
		s.signIn(t, o)
	case "after":
		o, ok := s.load(t)
		if !ok {
			t.Fatalf("%s holds no owner: run phase before on the stack before the update", s.ownerPath())
		}
		// The session from before the update: migration 0024 gives it a
		// last-seen time. It answers live or ended idle, never an error.
		var st struct {
			Authenticated bool   `json:"authenticated"`
			Ended         string `json:"ended"`
		}
		s.must(t, http.MethodGet, "/api/v1/auth/session", nil, o.cookie, &st)
		if !st.Authenticated && st.Ended != "idle" {
			t.Errorf("the session from before the update is neither live nor ended idle: %+v", st)
		}
		t.Logf("the session from before the update: authenticated=%v ended=%q", st.Authenticated, st.Ended)
		// The passkey from before signs in.
		s.signIn(t, o)

		got := strings.Fields(docker(t, "exec", devPrefix+"postgres", "psql", "-U", "innsegl", "-d", "innsegl", "-tA", "-c",
			"SELECT version FROM innsegl.schema_migrations WHERE version IN ('0023', '0024') ORDER BY version"))
		if !slices.Equal(got, []string{"0023", "0024"}) {
			t.Errorf("migrations recorded: %v, want 0023 and 0024", got)
		}

		page := s.call(t, http.MethodGet, "/", nil, nil)
		csp := page.header.Get("Content-Security-Policy")
		if page.status != http.StatusOK || !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
			t.Errorf("the dashboard answered %d with Content-Security-Policy %q; want script-src 'self' and nothing inline",
				page.status, csp)
		}

		var keys api.UnlockKeyList
		s.must(t, http.MethodGet, "/api/v1/account/unlock-keys", nil, o.cookie, &keys)
		if !keys.Custody.Enabled || !keys.Custody.Reachable || keys.Custody.SetDigest == "" {
			t.Errorf("the unlock keys' custody after the update: %+v; want on, reachable, a set", keys.Custody)
		}
	default:
		t.Skipf("skipping: INNSEGL_DEVSTACK_PHASE is %q; OPS-208 runs once with before, on the old stack, "+
			"and once with after, on the updated one", phase)
	}
}

// ---------------------------------------------------------------------------
// OPS-209 (PROPOSED for doc 07's TC-OPS; #617, ADR-0082) — on a dev stack,
// a security key alone unlocks the CA key store. The owner enrols a key
// through the API (a soft authenticator with PRF, the browser's derivation);
// the operator's machine, a workstation of the operator organisation
// enrolled with a dashboard token, applies it with `innsegl ca-custody
// reseal --add`; the store restarts sealed with the machine's client service
// stopped; the dashboard's unlock opens it with the key and nothing else;
// and `innsegl ca-custody status` on the machine says the CA can sign.
// ---------------------------------------------------------------------------

func TestOPS209AnUnlockKeyAloneUnlocksTheDevStack(t *testing.T) {
	s := requireStack(t)
	devIdentity := os.Getenv("INNSEGL_DEVSTACK_IDENTITY")
	if devIdentity == "" {
		t.Fatal("INNSEGL_DEVSTACK_IDENTITY is unset: name the dev stack's own age identity file " +
			"(the one INNSEGL_CA_CUSTODY_RECIPIENTS names), never the operator's")
	}
	o := s.theOwner(t)
	org := s.operatorOrg(t, o)

	// 1. A security key, enrolled from the account page: pending.
	key := newPRFKey(t)
	k := s.enrolUnlockKey(t, o, key, "OPS-209 key")
	if got := s.keyState(t, o, k.ID); got != "pending" {
		t.Fatalf("a new key is %q, want pending", got)
	}

	// 2. The operator's machine applies it. Its own home, its own client
	// service on its own port: never the operator's.
	bin := buildInnsegl(t)
	home := t.TempDir()
	paths := client.ClientPaths(home)
	copyFile(t, devIdentity, paths.TrustIdentity)
	var tok api.EnrolmentToken
	s.confirm(t, o, "/api/v1/account/enrolment-tokens/begin", "/api/v1/account/enrolment-tokens/finish",
		api.EnrolmentTokenRequest{OrganisationID: org, Kind: "workstation"}, &tok)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	e, err := client.Enrol(ctx, client.EnrolOptions{CoreURL: s.core, Token: tok.Token, Name: "ops-209", CA: readCA(t, s.caPath)})
	if err != nil {
		t.Fatalf("enrolling the operator's machine: %v", err)
	}
	listen := freeLoopback(t)
	if err := client.WriteEnrolment(paths, e, listen); err != nil {
		t.Fatal(err)
	}
	svc := startClientService(t, bin, home, listen)
	code, out := cli(t, bin, home, "y\n", "ca-custody", "reseal", "--add", k.CustodyRecipient)
	if code != 0 || !strings.Contains(out, "resealed") {
		t.Fatalf("ca-custody reseal --add: exit %d\n%s\nclient service:\n%s", code, out, svc.log.String())
	}
	code, out = cli(t, bin, home, "", "ca-custody", "recipients")
	if code != 0 || !strings.Contains(out, k.CustodyRecipient) {
		t.Errorf("ca-custody recipients after the reseal: exit %d\n%s", code, out)
	}
	if got := s.keyState(t, o, k.ID); got != "active" {
		t.Fatalf("after the machine's reseal the key is %q, want active", got)
	}
	// From here the machine is out of the loop: its client service would
	// unlock a sealed store with the dev identity within a minute.
	svc.stop()

	// 3. The store restarts sealed.
	docker(t, "restart", devPrefix+"ca-store")
	st := s.waitCustody(t, o, func(st cacustody.CoreStatus) bool { return st.Sealed })
	if st.CanSign {
		t.Fatalf("a sealed store says the CA can sign: %+v", st)
	}

	// 4. The dashboard's unlock, with the key alone.
	var ch api.CustodyChallenge
	s.must(t, http.MethodPost, "/api/v1/account/ca-custody/unlock/begin", struct{}{}, o.cookie, &ch)
	m := openWith(t, ch, key)
	cred, err := key.Assert(ch.CredentialAssertion, s.dashboard, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var done api.CustodyUnlocked
	s.must(t, http.MethodPost, "/api/v1/account/ca-custody/unlock/finish",
		api.CustodyFinish{CeremonyID: ch.CeremonyID, Credential: cred, Material: raw}, o.cookie, &done)
	if done.Status.Sealed || !done.Status.CanSign {
		t.Fatalf("after the dashboard's unlock: %+v", done.Status)
	}

	// 5. The operator's machine, back, sees a CA that can sign.
	startClientService(t, bin, home, listen)
	code, out = cli(t, bin, home, "", "ca-custody", "status")
	if code != 0 || !strings.Contains(out, "the CA can sign") {
		t.Errorf("ca-custody status after the key's unlock: exit %d\n%s", code, out)
	}
}

// enrolUnlockKey is the account page's "Add a security key": the owner's
// passkey confirms, create() on the key, get() with PRF, the two recipients
// derived in the browser, finish. The PRF output never leaves this process.
func (s stack) enrolUnlockKey(t *testing.T, o *owner, key *prfKey, label string) api.UnlockKey {
	t.Helper()
	var ch api.UnlockKeyEnrolChallenge
	s.must(t, http.MethodPost, "/api/v1/account/unlock-keys/begin", api.UnlockKeyEnrolBegin{Label: label}, o.cookie, &ch)
	confirmation, err := o.auth.Assert(ch.Confirm, s.dashboard, o.userID)
	if err != nil {
		t.Fatal(err)
	}
	s.save(t, o)
	yes := true
	key.Extensions = protocol.AuthenticationExtensionsClientOutputs{PRF: &protocol.PRFOutputs{Enabled: &yes}}
	created, err := key.Register(ch.Create, s.dashboard)
	if err != nil {
		t.Fatal(err)
	}
	key.Extensions = protocol.AuthenticationExtensionsClientOutputs{}
	asserted, err := key.Assert(ch.PRF, s.dashboard, "")
	if err != nil {
		t.Fatal(err)
	}
	var k api.UnlockKey
	s.must(t, http.MethodPost, "/api/v1/account/unlock-keys/finish", api.UnlockKeyEnrolFinish{
		CeremonyID: ch.CeremonyID, Confirmation: confirmation, Credential: created, Assertion: asserted,
		CustodyRecipient: key.identity(t, ch.CustodySalt, unlockkey.PurposeCustody).Recipient().String(),
		BackupRecipient:  key.identity(t, ch.BackupSalt, unlockkey.PurposeBackup).Recipient().String(),
	}, o.cookie, &k)
	return k
}

func (s stack) keyState(t *testing.T, o *owner, id string) string {
	t.Helper()
	var l api.UnlockKeyList
	s.must(t, http.MethodGet, "/api/v1/account/unlock-keys", nil, o.cookie, &l)
	for _, k := range l.Keys {
		if k.ID == id {
			return k.State
		}
	}
	t.Fatalf("the key %s is not listed: %s", id, shortJSON(l))
	return ""
}

// waitCustody polls the dashboard's custody status until ok holds.
func (s stack) waitCustody(t *testing.T, o *owner, ok func(cacustody.CoreStatus) bool) cacustody.CoreStatus {
	t.Helper()
	var st cacustody.CoreStatus
	for deadline := time.Now().Add(90 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		st = cacustody.CoreStatus{}
		if a := s.call(t, http.MethodGet, "/api/v1/account/ca-custody", nil, o.cookie); a.status == http.StatusOK &&
			json.Unmarshal(a.body, &st) == nil && ok(st) {
			return st
		}
	}
	t.Fatalf("the custody status never got there; last %+v", st)
	return st
}

// openWith is the browser opening the challenge's sealed material with the
// key it touched: the salt the server named for that credential.
func openWith(t *testing.T, ch api.CustodyChallenge, key *prfKey) cacustody.Material {
	t.Helper()
	prf := ch.Response.Extensions.PRF
	if prf == nil {
		t.Fatal("the unlock challenge asks for no PRF")
	}
	salt, ok := prf.EvalByCredential[protocol.URLEncodedBase64(key.CredentialID()).String()]
	if !ok {
		t.Fatalf("the challenge names no salt for this key; it names %d", len(prf.EvalByCredential))
	}
	m, err := cacustody.Open(ch.Sealed, []age.Identity{key.identity(t, salt.First, unlockkey.PurposeCustody)})
	if err != nil {
		t.Fatalf("the key does not open the sealed material: %v", err)
	}
	return m
}
