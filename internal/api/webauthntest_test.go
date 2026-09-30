// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
)

// A software WebAuthn authenticator, for AUTH-003/AUTH-004 only.
//
// go-webauthn v0.18.2 ships no browser or virtual-authenticator harness of
// its own (that is a client/browser concern, not a relying-party library's);
// what it DOES give a caller is the exact protocol types a real client's
// response decodes into, and its own tests build those directly rather than
// driving a browser (see the upstream package's own
// TestFinishRegistration_Success, which wraps a raw JSON body in an
// *http.Request the same way handleEnrolFinish/handleLoginFinish do). This
// file is that same technique, producing a FRESH ceremony against THIS
// server's own randomly-generated challenge each time, rather than a fixed
// spec test vector — a fixed vector's challenge cannot match a live
// BeginRegistration/BeginLogin call.
//
// It reports userVerification unconditionally (attestation flags and
// assertion flags both set FlagUserVerified) — the property AUTH-003 exists
// to prove is enforced SERVER-SIDE (userVerification: required in the
// options this server sends), not that this fake authenticator could be
// coerced into skipping it; a real authenticator that omits UV is refused by
// the library regardless of what this file does.

type softAuthenticator struct {
	key          *ecdsa.PrivateKey
	credentialID []byte
	signCount    uint32
}

func newSoftAuthenticator(t *testing.T) *softAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a P-256 key for the software authenticator: %v", err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatalf("no randomness for a credential id: %v", err)
	}
	return &softAuthenticator{key: key, credentialID: id}
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

func (a *softAuthenticator) coseKeyBytes(t *testing.T) []byte {
	t.Helper()
	pub := a.key.PublicKey
	body, err := cbor.Marshal(coseEC2Key{
		Kty: 2, Alg: -7, Crv: 1,
		X: pub.X.FillBytes(make([]byte, 32)),
		Y: pub.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("encoding the COSE public key: %v", err)
	}
	return body
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
func (a *softAuthenticator) authData(t *testing.T, rpID string, withAttestedCredential bool) []byte {
	t.Helper()
	rpIDHash := sha256.Sum256([]byte(rpID))

	flags := flagUP | flagUV
	var attested []byte
	if withAttestedCredential {
		flags |= flagAT
		aaguid := make([]byte, 16) // zero AAGUID: this authenticator names no real model.
		idLen := make([]byte, 2)
		binary.BigEndian.PutUint16(idLen, uint16(len(a.credentialID)))
		attested = append(attested, aaguid...)
		attested = append(attested, idLen...)
		attested = append(attested, a.credentialID...)
		attested = append(attested, a.coseKeyBytes(t)...)
	}

	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, a.signCount)

	out := make([]byte, 0, 37+len(attested))
	out = append(out, rpIDHash[:]...)
	out = append(out, flags)
	out = append(out, counter...)
	out = append(out, attested...)
	return out
}

type collectedClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func clientDataJSON(t *testing.T, typ, challenge, origin string) []byte {
	t.Helper()
	body, err := json.Marshal(collectedClientData{Type: typ, Challenge: challenge, Origin: origin})
	if err != nil {
		t.Fatalf("encoding clientDataJSON: %v", err)
	}
	return body
}

// attestationObjectCBOR is {"fmt":"none","attStmt":{},"authData":<bytes>} —
// the "none" attestation statement format (WebAuthn §8.7), which carries no
// signature of its own: registrationSelection requests no attestation
// (protocol.PreferNoAttestation), and "none" is what every real authenticator
// returns to a Relying Party that asked for nothing.
func attestationObjectCBOR(t *testing.T, authData []byte) []byte {
	t.Helper()
	body, err := cbor.Marshal(struct {
		Fmt      string         `cbor:"fmt"`
		AttStmt  map[string]any `cbor:"attStmt"`
		AuthData []byte         `cbor:"authData"`
	}{Fmt: "none", AttStmt: map[string]any{}, AuthData: authData})
	if err != nil {
		t.Fatalf("encoding the attestation object: %v", err)
	}
	return body
}

// register answers one BeginRegistration's *protocol.CredentialCreation as a
// client's navigator.credentials.create() would, and returns it already
// JSON-encoded the way handleEnrolFinish reads a request body.
func (a *softAuthenticator) register(t *testing.T, creation *protocol.CredentialCreation, origin string) []byte {
	t.Helper()
	cdj := clientDataJSON(t, "webauthn.create", creation.Response.Challenge.String(), origin)
	ad := a.authData(t, creation.Response.RelyingParty.ID, true)
	ao := attestationObjectCBOR(t, ad)

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
		t.Fatalf("encoding the registration response: %v", err)
	}
	return body
}

// assert answers one BeginLogin/BeginDiscoverableLogin's
// *protocol.CredentialAssertion, signing over authenticatorData ||
// sha256(clientDataJSON) with this authenticator's own key — exactly what a
// real authenticator signs (WebAuthn §6.3.3).
func (a *softAuthenticator) assert(t *testing.T, assertion *protocol.CredentialAssertion, origin, userHandle string) []byte {
	t.Helper()
	a.signCount++
	cdj := clientDataJSON(t, "webauthn.get", assertion.Response.Challenge.String(), origin)
	ad := a.authData(t, assertion.Response.RelyingPartyID, false)

	clientDataHash := sha256.Sum256(cdj)
	signed := append(append([]byte{}, ad...), clientDataHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatalf("signing the assertion: %v", err)
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
		t.Fatalf("encoding the assertion response: %v", err)
	}
	return body
}
