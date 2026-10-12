// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/cacustody"
)

// #613: the unlock-key routes' own failure paths (AUTH-013 to AUTH-017's
// error returns). Each breaks one table with the migration owner's
// credential, or scripts one custodian answer, and reads the refusal back.

// activeKeyHarness is an owner with one enrolled key in the sealed set,
// and a second key pending, so a reseal has something to apply.
func activeKeyHarness(t *testing.T) (orgHarness, *fakeCustodian, *prfKey, UnlockKey) {
	t.Helper()
	host := newHostIdentity(t)
	f := newFakeCustodian(t, host)
	h := newUnlockHarness(t, roleOwner, f.srv.URL)
	key := newPRFKey(t)
	k := h.mustEnrol(t, key, "first")
	h.mustEnrol(t, newPRFKey(t), "second")
	f.reseal(t, host.Recipient().String(), k.CustodyRecipient)
	return h, f, key, k
}

func (h orgHarness) resealBegin(t *testing.T, key *prfKey) (ResealChallenge, answer) {
	t.Helper()
	begin := h.post(t, "/api/v1/account/ca-custody/reseal/begin", struct{}{})
	if begin.status != http.StatusOK {
		t.Fatalf("reseal/begin: %d %s", begin.status, begin.body)
	}
	var ch ResealChallenge
	decodeBody(t, begin, &ch)
	m, _ := openWith(t, ch.CustodyChallenge, key)
	return ch, h.custodyFinish(t, "/api/v1/account/ca-custody/reseal/finish", ch.CustodyChallenge, key, m)
}

func TestUnlockKeyResealMapsTheCustodiansAnswers(t *testing.T) {
	h, f, key, _ := activeKeyHarness(t)

	f.answer(cacustody.PathReseal, http.StatusConflict, `{"error":"ca custody: reseal refused: the set is not the one confirmed"}`)
	if _, a := h.resealBegin(t, key); a.status != http.StatusConflict || !strings.Contains(string(a.body), "not the one confirmed") {
		t.Errorf("a custodian 409: %d %s", a.status, a.body)
	}
	f.answer(cacustody.PathReseal, http.StatusInternalServerError, `{}`)
	if _, a := h.resealBegin(t, key); a.status != http.StatusServiceUnavailable {
		t.Errorf("a custodian 500: %d %s", a.status, a.body)
	}
	f.answer(cacustody.PathReseal, http.StatusOK, `not json`)
	if _, a := h.resealBegin(t, key); a.status != http.StatusServiceUnavailable || !strings.Contains(string(a.body), "unreadable") {
		t.Errorf("an unreadable staged copy: %d %s", a.status, a.body)
	}
	if !strings.Contains(h.authEventDetails(t), AuthEventCustodyResealRefused+":") {
		t.Error("no reseal refusal recorded")
	}
}

func TestUnlockKeyResealConfirmMapsTheCustodiansAnswers(t *testing.T) {
	h, f, key, _ := activeKeyHarness(t)
	f.answer(cacustody.PathReseal, http.StatusOK, mustJSON(t, cacustody.ResealStaged{Sealed: []byte("x"),
		Recipients: []string{"a"}, SetDigest: "sha256:aa", ExpiresAt: time.Now().Add(time.Minute)}))
	_, first := h.resealBegin(t, key)
	if first.status != http.StatusOK {
		t.Fatalf("staged: %d %s", first.status, first.body)
	}
	var staged ResealStagedAnswer
	decodeBody(t, first, &staged)
	material := []byte(mustJSON(t, f.material))
	confirm := func(req ResealConfirmRequest) answer {
		return h.post(t, "/api/v1/account/ca-custody/reseal/confirm", req)
	}
	if a := confirm(ResealConfirmRequest{ConfirmID: staged.ConfirmID, Material: []byte(`{"unseal_key":"x"}`), Check: "c"}); a.status != http.StatusBadRequest {
		t.Errorf("a confirm with incomplete material: %d %s", a.status, a.body)
	}
	if a := confirm(ResealConfirmRequest{ConfirmID: staged.ConfirmID, Material: material, Check: "c"}); a.status != http.StatusUnauthorized {
		t.Errorf("a spent confirm: %d %s", a.status, a.body)
	}
	for _, c := range []struct {
		status, want int
	}{{http.StatusForbidden, http.StatusForbidden}, {http.StatusBadGateway, http.StatusServiceUnavailable}} {
		_, a := h.resealBegin(t, key)
		decodeBody(t, a, &staged)
		f.answer(cacustody.PathResealConfirm, c.status, `{"error":"ca custody: reseal refused: the confirm does not carry the staged copy's check"}`)
		if a := confirm(ResealConfirmRequest{ConfirmID: staged.ConfirmID, Material: material, Check: "c"}); a.status != c.want {
			t.Errorf("a custodian %d on confirm: %d %s", c.status, a.status, a.body)
		}
	}
	_, first = h.resealBegin(t, key)
	decodeBody(t, first, &staged)
	f.answer(cacustody.PathResealConfirm, http.StatusNoContent, "")
	if a := confirm(ResealConfirmRequest{ConfirmID: staged.ConfirmID, Material: material, Check: "c"}); a.status != http.StatusOK {
		t.Errorf("an accepted confirm: %d %s", a.status, a.body)
	}
}

func TestUnlockKeyRoutesWithTheCustodianGone(t *testing.T) {
	h, f, key, _ := activeKeyHarness(t)
	f.answer(cacustody.PathReseal, http.StatusOK, mustJSON(t, cacustody.ResealStaged{Sealed: []byte("x"),
		Recipients: []string{"a"}, SetDigest: "sha256:aa", ExpiresAt: time.Now().Add(time.Minute)}))
	_, a := h.resealBegin(t, key)
	var staged ResealStagedAnswer
	decodeBody(t, a, &staged)
	material := []byte(mustJSON(t, f.material))
	confirm := func(req ResealConfirmRequest) answer {
		return h.post(t, "/api/v1/account/ca-custody/reseal/confirm", req)
	}
	begin := h.post(t, "/api/v1/account/ca-custody/reseal/begin", struct{}{})
	var ch ResealChallenge
	decodeBody(t, begin, &ch)
	m, _ := openWith(t, ch.CustodyChallenge, key)
	unlock := h.post(t, "/api/v1/account/ca-custody/unlock/begin", struct{}{})
	var uc CustodyChallenge
	decodeBody(t, unlock, &uc)
	f.srv.Close()
	if a := h.custodyFinish(t, "/api/v1/account/ca-custody/reseal/finish", ch.CustodyChallenge, key, m); a.status != http.StatusServiceUnavailable {
		t.Errorf("reseal/finish with the custodian gone: %d %s", a.status, a.body)
	}
	if a := h.custodyFinish(t, "/api/v1/account/ca-custody/unlock/finish", uc, key, m); a.status != http.StatusServiceUnavailable {
		t.Errorf("unlock/finish with the custodian gone: %d %s", a.status, a.body)
	}
	if a := confirm(ResealConfirmRequest{ConfirmID: staged.ConfirmID, Material: material, Check: "c"}); a.status != http.StatusServiceUnavailable {
		t.Errorf("confirm with the custodian gone: %d %s", a.status, a.body)
	}
	if a := h.post(t, "/api/v1/account/ca-custody/reseal/begin", struct{}{}); a.status != http.StatusServiceUnavailable {
		t.Errorf("reseal/begin with the custodian gone: %d %s", a.status, a.body)
	}
}

func TestUnlockKeyResealOfACurrentSetIsRefused(t *testing.T) {
	host := newHostIdentity(t)
	f := newFakeCustodian(t, host)
	h := newUnlockHarness(t, roleOwner, f.srv.URL)
	key := newPRFKey(t)
	k := h.mustEnrol(t, key, "only")
	f.reseal(t, host.Recipient().String(), k.CustodyRecipient)
	if a := h.post(t, "/api/v1/account/ca-custody/reseal/begin", struct{}{}); a.status != http.StatusConflict ||
		!strings.Contains(string(a.body), "already current") {
		t.Errorf("a reseal with nothing to apply: %d %s", a.status, a.body)
	}
	h2 := newUnlockHarness(t, roleOwner, "")
	for _, p := range []string{"reseal/begin", "reseal/finish", "reseal/confirm", "unlock/finish"} {
		if a := h2.post(t, "/api/v1/account/ca-custody/"+p, struct{}{}); a.status != http.StatusServiceUnavailable {
			t.Errorf("%s with custody off: %d %s", p, a.status, a.body)
		}
	}
}

func TestUnlockKeyCustodianAnswersItCannotRead(t *testing.T) {
	h, f, _, _ := activeKeyHarness(t)
	f.answer(cacustody.PathStatus, http.StatusOK, `not json`)
	var st cacustody.CoreStatus
	decodeBody(t, h.get(t, "/api/v1/account/ca-custody"), &st)
	if !strings.Contains(st.Error, "unreadable") {
		t.Errorf("an unreadable status: %+v", st)
	}
	f.answer(cacustody.PathMaterial, http.StatusNotFound, `{"error":"ca custody: no unlock material"}`)
	if a := h.post(t, "/api/v1/account/ca-custody/unlock/begin", struct{}{}); a.status != http.StatusServiceUnavailable ||
		!strings.Contains(string(a.body), "no unlock material") {
		t.Errorf("no material: %d %s", a.status, a.body)
	}
	f.answer(cacustody.PathRecipients, http.StatusOK, `not json`)
	if l := h.unlockKeys(t); l.Custody.Reachable || !strings.Contains(l.Custody.Error, "unreadable") {
		t.Errorf("an unreadable set: %+v", l.Custody)
	}
	if got := h.unlockKeys(t).Keys[0].State; got != unlockKeyUnknown {
		t.Errorf("a key with the set unreadable is %q", got)
	}
}

func TestUnlockKeyRoutesReportTheDatabase(t *testing.T) {
	h, _, key, k := activeKeyHarness(t)
	unlock := h.post(t, "/api/v1/account/ca-custody/unlock/begin", struct{}{})
	var uc CustodyChallenge
	decodeBody(t, unlock, &uc)
	m, _ := openWith(t, uc, key)

	h.ownerExec(t, `REVOKE UPDATE ON innsegl_auth.unlock_keys FROM `+AuthWriterRole)
	if a := h.custodyFinish(t, "/api/v1/account/ca-custody/unlock/finish", uc, key, m); a.status != http.StatusUnauthorized {
		t.Errorf("an unlock whose key cannot be stamped: %d %s", a.status, a.body)
	}
	if a := h.confirmRevoke(t, k.ID, h.auth); a.status != http.StatusInternalServerError {
		t.Errorf("a revoke that cannot be written: %d %s", a.status, a.body)
	}
	h.ownerExec(t, `REVOKE INSERT ON innsegl_auth.unlock_keys FROM `+AuthWriterRole)
	if a := h.enrolUnlockKey(t, newPRFKey(t), "third", enrolOptions{}); a.status != http.StatusInternalServerError {
		t.Errorf("an enrolment that cannot be stored: %d %s", a.status, a.body)
	}
	h.ownerExec(t, `REVOKE INSERT ON innsegl_auth.webauthn_ceremonies FROM `+AuthWriterRole)
	for _, p := range []string{"/api/v1/account/ca-custody/unlock/begin", "/api/v1/account/ca-custody/reseal/begin"} {
		if a := h.post(t, p, struct{}{}); a.status != http.StatusInternalServerError {
			t.Errorf("%s with no ceremony store: %d %s", p, a.status, a.body)
		}
	}
	if a := h.post(t, "/api/v1/account/unlock-keys/begin", UnlockKeyEnrolBegin{Label: "k"}); a.status != http.StatusInternalServerError {
		t.Errorf("enrol begin with no ceremony store: %d %s", a.status, a.body)
	}
	h.ownerExec(t, `ALTER TABLE innsegl_auth.unlock_keys RENAME TO unlock_keys_gone`)
	for _, p := range []string{"/api/v1/account/ca-custody/unlock/begin", "/api/v1/account/ca-custody/reseal/begin"} {
		if a := h.post(t, p, struct{}{}); a.status != http.StatusInternalServerError {
			t.Errorf("%s with no registry: %d %s", p, a.status, a.body)
		}
	}
	if a := h.post(t, "/api/v1/account/unlock-keys/begin", UnlockKeyEnrolBegin{Label: "k"}); a.status != http.StatusInternalServerError {
		t.Errorf("enrol begin with no registry: %d %s", a.status, a.body)
	}
	if a := h.post(t, "/api/v1/account/unlock-keys/revoke/begin", UnlockKeyRevoke{ID: k.ID}); a.status != http.StatusInternalServerError {
		t.Errorf("revoke begin with no registry: %d %s", a.status, a.body)
	}
	if a := h.get(t, "/api/v1/account/unlock-keys"); a.status != http.StatusInternalServerError {
		t.Errorf("the list with no registry: %d %s", a.status, a.body)
	}
	h.ownerExec(t, `ALTER TABLE innsegl_auth.passkeys RENAME TO passkeys_gone`)
	if a := h.post(t, "/api/v1/account/unlock-keys/begin", UnlockKeyEnrolBegin{Label: "k"}); a.status != http.StatusInternalServerError {
		t.Errorf("enrol begin with no passkeys: %d %s", a.status, a.body)
	}
}

func TestUnlockKeyCeremoniesThatAreNotTheirs(t *testing.T) {
	h, _, key, _ := activeKeyHarness(t)
	corrupt := func(id string) {
		h.ownerExec(t, `UPDATE innsegl_auth.webauthn_ceremonies SET session_data = '"x"' WHERE ceremony_id = $1`, id)
	}
	// An enrolment and an unlock whose stored ceremony is unreadable.
	var enrolID string
	if a := h.enrolUnlockKey(t, newPRFKey(t), "x", enrolOptions{afterBegin: func(c UnlockKeyEnrolChallenge) {
		enrolID = c.CeremonyID
		corrupt(enrolID)
	}}); a.status != http.StatusInternalServerError {
		t.Errorf("an unreadable enrolment: %d %s", a.status, a.body)
	}
	unlock := h.post(t, "/api/v1/account/ca-custody/unlock/begin", struct{}{})
	var uc CustodyChallenge
	decodeBody(t, unlock, &uc)
	m, _ := openWith(t, uc, key)
	corrupt(uc.CeremonyID)
	if a := h.custodyFinish(t, "/api/v1/account/ca-custody/unlock/finish", uc, key, m); a.status != http.StatusInternalServerError {
		t.Errorf("an unreadable unlock ceremony: %d %s", a.status, a.body)
	}
	// Another person's.
	if a := h.enrolUnlockKey(t, newPRFKey(t), "x", enrolOptions{afterBegin: func(c UnlockKeyEnrolChallenge) {
		h.ownerExec(t, `UPDATE innsegl_auth.webauthn_ceremonies SET pending_user_id = NULL WHERE ceremony_id = $1`, c.CeremonyID)
	}}); a.status != http.StatusUnauthorized {
		t.Errorf("another's enrolment: %d %s", a.status, a.body)
	}
	// A recipient someone already enrolled.
	first := h.unlockKeys(t).Keys[0]
	if a := h.enrolUnlockKey(t, newPRFKey(t), "dup", enrolOptions{finish: func(f *UnlockKeyEnrolFinish) {
		f.CustodyRecipient = first.CustodyRecipient
	}}); a.status != http.StatusConflict {
		t.Errorf("a recipient enrolled twice: %d %s", a.status, a.body)
	}
	// An assertion that is not one at all.
	unlock = h.post(t, "/api/v1/account/ca-custody/unlock/begin", struct{}{})
	decodeBody(t, unlock, &uc)
	if a := h.post(t, "/api/v1/account/ca-custody/unlock/finish", CustodyFinish{CeremonyID: uc.CeremonyID,
		Credential: []byte(`{}`), Material: []byte(`{}`)}); a.status != http.StatusUnauthorized {
		t.Errorf("no assertion: %d %s", a.status, a.body)
	}
	if a := h.enrolUnlockKey(t, newPRFKey(t), "bad", enrolOptions{finish: func(f *UnlockKeyEnrolFinish) {
		f.Assertion = []byte(`{}`)
	}}); a.status != http.StatusUnauthorized {
		t.Errorf("an enrolment with no PRF assertion: %d %s", a.status, a.body)
	}
	if a := h.enrolUnlockKey(t, newPRFKey(t), "bad", enrolOptions{finish: func(f *UnlockKeyEnrolFinish) {
		other := newPRFKey(t)
		f.Assertion = []byte(mustJSON(t, map[string]any{"id": other.idB64(), "rawId": other.idB64(), "type": "public-key",
			"response": map[string]string{"clientDataJSON": "e30", "authenticatorData": "AAAA", "signature": "AA"}}))
	}}); a.status != http.StatusUnauthorized {
		t.Errorf("an enrolment whose PRF assertion is another key's: %d %s", a.status, a.body)
	}
}

func TestUnlockKeyRoutesNeedTheSpineAndReportIt(t *testing.T) {
	h := newOrgHarness(t, roleOwner, false)
	if a := h.get(t, "/api/v1/account/unlock-keys"); a.status != http.StatusServiceUnavailable {
		t.Errorf("no accounts spine: %d %s", a.status, a.body)
	}
	f := newFakeCustodian(t, newHostIdentity(t))
	h = newUnlockHarness(t, roleOwner, f.srv.URL)
	h.orgs.mu.Lock()
	h.orgs.err = errors.New("the spine is down")
	h.orgs.mu.Unlock()
	if a := h.get(t, "/api/v1/account/unlock-keys"); a.status != http.StatusInternalServerError {
		t.Errorf("the spine failing: %d %s", a.status, a.body)
	}
}

func TestUnlockKeyEnrolmentNeedsASignInPasskey(t *testing.T) {
	f := newFakeCustodian(t, newHostIdentity(t))
	h := newUnlockHarness(t, roleOwner, f.srv.URL)
	h.ownerExec(t, `DELETE FROM innsegl_auth.passkeys`)
	if a := h.post(t, "/api/v1/account/unlock-keys/begin", UnlockKeyEnrolBegin{Label: "k"}); a.status != http.StatusForbidden {
		t.Errorf("no sign-in passkey: %d %s", a.status, a.body)
	}
}

func TestUnlockKeyCustodianClientRefusesARouteOffTheAllowlist(t *testing.T) {
	c := newCustodyClient("http://127.0.0.1:1/")
	if _, _, err := c.do(t.Context(), http.MethodGet, cacustody.PathUnlock, nil); !errors.Is(err, errCustodyRoute) {
		t.Errorf("GET /unlock: %v", err)
	}
	if _, _, err := c.do(t.Context(), http.MethodPost, "/anything", nil); !errors.Is(err, errCustodyRoute) {
		t.Errorf("POST /anything: %v", err)
	}
	if _, _, err := c.do(t.Context(), http.MethodPost, cacustody.PathUnlock, func() {}); err == nil {
		t.Error("a body that cannot be encoded was sent")
	}
	if got := custodianError([]byte("not json")); got != "no reason given" {
		t.Errorf("an unreadable refusal: %q", got)
	}
	if got := custodianError([]byte(`{"error":"` + strings.Repeat("x", 400) + `"}`)); len(got) != 300 {
		t.Errorf("a long refusal is %d characters", len(got))
	}
	for status, want := range map[int]string{
		http.StatusUnauthorized: codeUnauthorized, http.StatusForbidden: codeForbidden, http.StatusConflict: codeConflict,
		http.StatusNotFound: codeNotFound, http.StatusServiceUnavailable: codeUnavailable,
		http.StatusBadRequest: codeBadRequest, http.StatusTeapot: codeInternal,
	} {
		if got := codeForStatus(status); got != want {
			t.Errorf("codeForStatus(%d) = %q, want %q", status, got, want)
		}
	}
}
