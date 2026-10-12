// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// The step-up: a fresh assertion from one of the signed-in person's own
// passkeys, with user verification. It is the one place the dashboard asks
// for one. beginConfirmation and finishConfirmation (accountorg.go) wrap it
// for a change that is its own begin/finish pair; adding a passkey and
// enrolling an unlock key carry it beside a registration in one ceremony.
//
// What needs it: revoking, suspending and resuming a machine, minting an
// enrolment token, managing members and the organisation's sign-in,
// resolving alerts, enrolling and revoking an unlock key, and (#602) every
// change to how the account itself signs in — adding or removing a passkey,
// regenerating recovery codes, linking or unlinking an organisation's
// sign-in. A stolen session cookie then cannot make itself permanent.

// recoveryStepUpWindow is how long after a recovery-code sign-in that
// session may add a passkey with no passkey's confirmation (#602). The code
// it just spent is the fresh factor: a person who lost every passkey has no
// other. After the window, a passkey confirms it like any other session.
const recoveryStepUpWindow = 10 * time.Minute

// beginStepUp asks the user's own passkeys for a fresh assertion. It writes
// the refusal itself and returns false on any failure.
func (s *Server) beginStepUp(ctx context.Context, w http.ResponseWriter, userID string) (*protocol.CredentialAssertion, *webauthn.SessionData, bool) {
	user, err := loadUser(ctx, s.authStore, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not load the account")
		return nil, nil, false
	}
	if len(user.credentials) == 0 {
		writeError(w, http.StatusForbidden, codeForbidden, confirmNeedsPasskey)
		return nil, nil, false
	}
	assertion, session, err := s.webAuthn.BeginLogin(user,
		webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not begin the "+
			"confirmation ceremony: "+err.Error())
		return nil, nil, false
	}
	return assertion, session, true
}

// verifyStepUp checks a step-up assertion against the user's own passkeys
// and records the passkey's new counter. kind names the change in the auth
// event a refusal records. It writes the refusal itself and returns false on
// any failure, including an empty assertion.
func (s *Server) verifyStepUp(ctx context.Context, w http.ResponseWriter, kind, userID string,
	session webauthn.SessionData, assertion json.RawMessage,
) bool {
	if len(assertion) == 0 {
		s.recordAuth(ctx, AuthEventConfirmationRefused, userID, kind+": no passkey confirmation")
		writeError(w, http.StatusUnauthorized, codeUnauthorized, confirmMissingMessage)
		return false
	}
	user, err := loadUser(ctx, s.authStore, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not load the account")
		return false
	}
	cred, err := s.webAuthn.FinishLogin(user, session, credentialHTTPRequest(assertion))
	if err != nil {
		s.recordAuth(ctx, AuthEventConfirmationRefused, userID, kind+": the passkey did not verify: "+err.Error())
		writeError(w, http.StatusUnauthorized, codeUnauthorized, "the passkey did not confirm this: "+err.Error())
		return false
	}
	if uerr := s.authStore.UpdatePasskey(ctx, *cred); uerr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not update the passkey")
		return false
	}
	return true
}

// confirmMissingMessage refuses a change that came without the passkey
// confirmation it needs.
const confirmMissingMessage = "this change is confirmed with one of your passkeys, and none was sent"

// recoveryMayAddPasskey answers whether sess is a recovery-code sign-in
// still inside recoveryStepUpWindow.
func recoveryMayAddPasskey(sess accountSession) bool {
	return sess.recovery && time.Since(sess.openedAt) < recoveryStepUpWindow
}
