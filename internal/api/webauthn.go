// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// The relying party, and the one adapter between AuthStore's rows and
// go-webauthn's own User/Credential types.
//
// ADR-0062: "Passkey (WebAuthn) only, user verification required. No
// passwords, ever." userVerificationRequired is set on every ceremony this
// file begins — registration and login alike — never left to the client's
// default.
//
// The RP ID must be a DOMAIN. "127.0.0.1 is not a valid RP ID, localhost is"
// — WebAuthnConfig.RPID is validated by webauthn.New itself
// (protocol.ValidateRPID), so a deployment configured with an IP literal
// refuses to start rather than silently accepting a credential no browser
// could ever present back (a credential is bound to the RP ID it was created
// under, permanently).

// WebAuthnConfig is the relying-party configuration #409 wires from
// `innsegl api`'s flags.
type WebAuthnConfig struct {
	// RPID is the effective domain, e.g. "localhost". Never an IP literal.
	RPID string
	// RPOrigin is the exact origin the dashboard is served from, e.g.
	// "http://localhost:8082". Requests whose Origin header names anything
	// else are refused before a ceremony is even begun (AUTH-004).
	RPOrigin string
	// RPDisplayName is shown to the user by the platform's own passkey UI.
	// Empty defaults to "Innsegl".
	RPDisplayName string
}

func (c WebAuthnConfig) displayName() string {
	if c.RPDisplayName != "" {
		return c.RPDisplayName
	}
	return "Innsegl"
}

// newWebAuthn constructs the relying party, or refuses a configuration that
// could never work — an empty RP ID or origin, or (via webauthn.New's own
// validation) an RP ID that is not a domain.
func newWebAuthn(cfg WebAuthnConfig) (*webauthn.WebAuthn, error) {
	if cfg.RPID == "" {
		return nil, fmt.Errorf("api: webauthn needs an RP ID; 127.0.0.1 is not one, " +
			"localhost is (ADR-0062)")
	}
	if cfg.RPOrigin == "" {
		return nil, fmt.Errorf("api: webauthn needs an RP origin")
	}
	w, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.displayName(),
		RPOrigins:     []string{cfg.RPOrigin},
		// Attestation is recorded, never enforced (ADR-0062's enrolment
		// crux): this deployment requests no attestation statement at all,
		// so nothing about a passkey's chain of trust is a gate. A future
		// deployment wanting to record a richer format can raise this to
		// PreferDirectAttestation without touching anything else here —
		// passkeys.attestation_format already carries whatever comes back.
		AttestationPreference: protocol.PreferNoAttestation,
	})
	if err != nil {
		return nil, fmt.Errorf("api: configuring webauthn: %w", err)
	}
	return w, nil
}

// dbUser adapts AuthStore's rows to webauthn.User. It is never persisted
// itself — AuthStore's tables are the source of truth, this is a read-only
// view assembled per request.
type dbUser struct {
	id          string
	displayName string
	credentials []webauthn.Credential
}

func (u dbUser) WebAuthnID() []byte                         { return []byte(u.id) }
func (u dbUser) WebAuthnName() string                       { return u.displayName }
func (u dbUser) WebAuthnDisplayName() string                { return u.displayName }
func (u dbUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// loadUser assembles a dbUser from AuthStore for a known user id.
func loadUser(ctx context.Context, store *AuthStore, userID string) (dbUser, error) {
	u, err := store.UserByID(ctx, userID)
	if err != nil {
		return dbUser{}, err
	}
	creds, err := store.PasskeysByUser(ctx, userID)
	if err != nil {
		return dbUser{}, err
	}
	return dbUser{id: u.UserID, displayName: u.DisplayName, credentials: creds}, nil
}

// registrationSelection is every ceremony this deployment begins for a new
// passkey: user verification required, and a resident (discoverable) key
// required — the one-passkey-button sign-in page (doc 06, no username field)
// only works if the authenticator itself can produce a credential naming its
// own user without being told which one to look for.
var registrationSelection = protocol.AuthenticatorSelection{
	UserVerification:   protocol.VerificationRequired,
	ResidentKey:        protocol.ResidentKeyRequirementRequired,
	RequireResidentKey: protocol.ResidentKeyRequired(),
}
