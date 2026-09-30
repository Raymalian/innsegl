// SPDX-License-Identifier: Apache-2.0

// Package webauthntest is a from-scratch software WebAuthn authenticator,
// for this project's own tests only (RM-260/RM-261, AUTH-003/AUTH-004) —
// never for production code, and never a real device.
//
// go-webauthn v0.18.2 ships no browser or virtual-authenticator harness of
// its own (that is a client/browser concern, not a relying-party library's);
// what it DOES give a caller is the exact protocol types a real client's
// response decodes into, and its own tests build those directly rather than
// driving a browser (see the upstream package's own
// TestFinishRegistration_Success, which wraps a raw JSON body in an
// *http.Request the same way internal/api's handleEnrolFinish/
// handleLoginFinish do). This package is that same technique, producing a
// FRESH ceremony against a server's own randomly-generated challenge each
// time, rather than a fixed spec test vector — a fixed vector's challenge
// cannot match a live BeginRegistration/BeginLogin call.
//
// It reports userVerification unconditionally (attestation flags and
// assertion flags both set FlagUserVerified) — the property AUTH-003 exists
// to prove is enforced SERVER-SIDE (userVerification: required in the
// options a server sends), not that this fake authenticator could be
// coerced into skipping it; a real authenticator that omits UV is refused by
// the library regardless of what this package does.
//
// It is a package under internal/, not a _test.go file, so BOTH
// internal/api's own tests and cmd/innsegl's integration tests (which run
// the compiled `innsegl api` binary over real HTTP, in a different package)
// can share one implementation rather than two hand-maintained copies.
// Nothing outside a _test.go file imports it.
package webauthntest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
)

// Authenticator is one software passkey.
type Authenticator struct {
	key          *ecdsa.PrivateKey
	credentialID []byte
	signCount    uint32
}

// New mints a fresh P-256 key and a random credential id.
func New() (*Authenticator, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("webauthntest: generating a P-256 key: %w", err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("webauthntest: no randomness for a credential id: %w", err)
	}
	return &Authenticator{key: key, credentialID: id}, nil
}

// coseEC2Key is RFC 9053's COSE_Key for an EC2 (elliptic curve) key,
// P-256/ES256: kty=2 (EC2), alg=-7 (ES256), crv=1 (P-256). Integer map keys,
// via fxamacker/cbor's own "keyasint" struct tag — the same technique any
// COSE/CWT encoder needs, since COSE_Key is defined over integer labels, not
// strings.
type coseEC2Key struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

func (a *Authenticator) coseKeyBytes() ([]byte, error) {
	// SEC1 uncompressed point: 0x04 || X(32) || Y(32) for P-256. Read via
	// PublicKey.Bytes rather than the deprecated X/Y *big.Int fields
	// (crypto/ecdsa, Go 1.26+).
	uncompressed, err := a.key.PublicKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("webauthntest: encoding the public key point: %w", err)
	}
	body, err := cbor.Marshal(coseEC2Key{
		Kty: 2, Alg: -7, Crv: 1,
		X: uncompressed[1:33],
		Y: uncompressed[33:65],
	})
	if err != nil {
		return nil, fmt.Errorf("webauthntest: encoding the COSE public key: %w", err)
	}
	return body, nil
}

// authenticatorFlags, spelled once (protocol.FlagUserPresent |
// protocol.FlagUserVerified [| protocol.FlagAttestedCredentialData]).
const (
	flagUP byte = 0x01
	flagUV byte = 0x04
	flagAT byte = 0x40
)

// authData builds the raw authenticatorData bytes (WebAuthn §6.1): rpIdHash,
// flags, a big-endian sign counter and, for a registration ceremony,
// attestedCredentialData (aaguid, a 16-bit credential-id length, the
// credential id, then the COSE public key — no explicit public-key length,
// it is self-describing CBOR).
func (a *Authenticator) authData(rpID string, withAttestedCredential bool) ([]byte, error) {
	rpIDHash := sha256.Sum256([]byte(rpID))

	flags := flagUP | flagUV
	var attested []byte
	if withAttestedCredential {
		flags |= flagAT
		aaguid := make([]byte, 16) // zero AAGUID: this authenticator names no real model.
		idLen := make([]byte, 2)
		// This authenticator's own credential id (New, above) is always 16
		// bytes, nowhere near uint16's range; the conversion cannot overflow
		// in practice, and the field it fills is itself only 16 bits wide
		// per WebAuthn's own authenticatorData encoding.
		binary.BigEndian.PutUint16(idLen, uint16(len(a.credentialID))) //nolint:gosec // G115: bounded by New's own fixed 16-byte id

		attested = append(attested, aaguid...)
		attested = append(attested, idLen...)
		attested = append(attested, a.credentialID...)
		key, err := a.coseKeyBytes()
		if err != nil {
			return nil, err
		}
		attested = append(attested, key...)
	}

	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, a.signCount)

	out := make([]byte, 0, 37+len(attested))
	out = append(out, rpIDHash[:]...)
	out = append(out, flags)
	out = append(out, counter...)
	out = append(out, attested...)
	return out, nil
}

type collectedClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func clientDataJSON(typ, challenge, origin string) ([]byte, error) {
	body, err := json.Marshal(collectedClientData{Type: typ, Challenge: challenge, Origin: origin})
	if err != nil {
		return nil, fmt.Errorf("webauthntest: encoding clientDataJSON: %w", err)
	}
	return body, nil
}

// attestationObjectCBOR is {"fmt":"none","attStmt":{},"authData":<bytes>} —
// the "none" attestation statement format (WebAuthn §8.7), which carries no
// signature of its own: a Relying Party requesting no attestation
// (protocol.PreferNoAttestation) gets "none" back from every real
// authenticator too.
func attestationObjectCBOR(authData []byte) ([]byte, error) {
	body, err := cbor.Marshal(struct {
		Fmt      string         `cbor:"fmt"`
		AttStmt  map[string]any `cbor:"attStmt"`
		AuthData []byte         `cbor:"authData"`
	}{Fmt: "none", AttStmt: map[string]any{}, AuthData: authData})
	if err != nil {
		return nil, fmt.Errorf("webauthntest: encoding the attestation object: %w", err)
	}
	return body, nil
}

// Register answers one BeginRegistration's *protocol.CredentialCreation as a
// client's navigator.credentials.create() would, and returns it already
// JSON-encoded the way a registration-finish handler reads a request body.
func (a *Authenticator) Register(creation *protocol.CredentialCreation, origin string) ([]byte, error) {
	cdj, err := clientDataJSON("webauthn.create", creation.Response.Challenge.String(), origin)
	if err != nil {
		return nil, err
	}
	ad, err := a.authData(creation.Response.RelyingParty.ID, true)
	if err != nil {
		return nil, err
	}
	ao, err := attestationObjectCBOR(ad)
	if err != nil {
		return nil, err
	}

	resp := protocol.CredentialCreationResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   protocol.URLEncodedBase64(a.credentialID).String(),
				Type: "public-key",
			},
			RawID: protocol.URLEncodedBase64(a.credentialID),
		},
		AttestationResponse: protocol.AuthenticatorAttestationResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{
				ClientDataJSON: protocol.URLEncodedBase64(cdj),
			},
			AttestationObject: protocol.URLEncodedBase64(ao),
		},
	}
	body, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("webauthntest: encoding the registration response: %w", err)
	}
	return body, nil
}

// Assert answers one BeginLogin/BeginDiscoverableLogin's
// *protocol.CredentialAssertion, signing over authenticatorData ||
// sha256(clientDataJSON) with this authenticator's own key — exactly what a
// real authenticator signs (WebAuthn §6.3.3). userHandle is the user id the
// response reports itself as belonging to; pass a wrong one to simulate a
// forged assertion.
func (a *Authenticator) Assert(assertion *protocol.CredentialAssertion, origin, userHandle string) ([]byte, error) {
	a.signCount++
	cdj, err := clientDataJSON("webauthn.get", assertion.Response.Challenge.String(), origin)
	if err != nil {
		return nil, err
	}
	ad, err := a.authData(assertion.Response.RelyingPartyID, false)
	if err != nil {
		return nil, err
	}

	clientDataHash := sha256.Sum256(cdj)
	signed := append(append([]byte{}, ad...), clientDataHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("webauthntest: signing the assertion: %w", err)
	}

	resp := protocol.CredentialAssertionResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   protocol.URLEncodedBase64(a.credentialID).String(),
				Type: "public-key",
			},
			RawID: protocol.URLEncodedBase64(a.credentialID),
		},
		AssertionResponse: protocol.AuthenticatorAssertionResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{
				ClientDataJSON: protocol.URLEncodedBase64(cdj),
			},
			AuthenticatorData: protocol.URLEncodedBase64(ad),
			Signature:         protocol.URLEncodedBase64(sig),
			UserHandle:        protocol.URLEncodedBase64(userHandle),
		},
	}
	body, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("webauthntest: encoding the assertion response: %w", err)
	}
	return body, nil
}
