// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// The repository-scoped credential the identity-lifecycle listener requires.
//
// # The gap this closes
//
// Nothing authenticated a caller on the admin listener. Any process that could
// reach it could mint a run — doc 04's AB-13 and AB-15, and AB-23 in the words
// of the plan behind #264 — and the deployment that turned the listener split
// on published it, with six tools behind it and no check at all.
//
// The run token (runtoken.go) is not that check and cannot become it. It is
// per-RUN and is issued BY register_agent, so it can only defend tools that
// already hold a run id; the tool that creates one has nothing to present.
//
// # What the credential is
//
// A short-lived ES256 JWT carrying ONE subject-bearing claim — the repository
// — and nothing that identifies an account. The claim set is closed and the
// closure is enforced: a token carrying `sub`, an account id, an email or a
// display name is refused, so the rule cannot be broken later by whatever
// mints one. What a stranger needs to verify that an agent signed a change
// belongs to this system; everything that says WHO OPERATES the agent belongs
// to the account system, and never enters an event, a certificate, a trailer
// or a log line here.
//
// # Why verification is offline, from a file
//
// The key set is read once, at construction, from a path a deployment mounts.
// It is never fetched. Whatever issues credentials may be down, unreachable or
// not yet built without this system noticing: an already-issued credential
// keeps working and signing is unaffected. A verifier that fetched its keys
// would make every registration depend on the availability of the thing that
// is explicitly allowed to be absent.
//
// Read ONCE rather than watched, because a rotation is a deliberate act with a
// restart in it. Overlap is how a rotation happens without a window: the file
// holds the outgoing and the incoming key at the same time and both are
// admitted until the outgoing one is taken out.
//
// # Why every failure is one refusal
//
// Absent, malformed, expired, not yet valid, wrong audience, wrong issuer,
// unknown key id, bad signature: one status, one body, byte for byte. A
// distinguishable "wrong audience" is an oracle over which audiences exist,
// and a distinguishable "expired" tells a caller its token was otherwise
// admissible. The verifier therefore reports a BOOLEAN to the transport and
// keeps its reasons for `innsegl admin-credential verify`, which an operator
// runs on their own machine against their own token.
//
// # Where the check sits
//
// In front of the whole admin handler, so it is made before the MCP session
// layer and before any tool: a refused call runs no handler, appends nothing,
// claims no idempotency key and reaches neither SPIRE nor the ledger. It is
// deliberately NOT on the agent listener — a repository-scoped credential
// there would become credential-fetch authority over every run in that
// repository, which is wider than today's gap rather than narrower.
//
// # Why it is a header
//
// A transport header is outside the idempotency fingerprint, which is taken
// over the tool name and its arguments (idempotency.go). A credential inside
// the digest would make a replay depend on which token was used: the same call
// retried after the token expired would look like a different request and be
// refused as DUPLICATE_REQUEST.

const (
	// AdminCredentialIssuer is the `iss` every admin credential carries. A
	// FIXED string, never named after a tenant: an issuer that varied would
	// put the customer into the one field a verifier is guaranteed to read.
	AdminCredentialIssuer = "innsegl"

	// AdminCredentialAudience is the `aud` of a credential for the identity
	// lifecycle. It exists so that a credential minted for anything else —
	// the read API's scope tokens, when they are built — can never be
	// presented here, and the refusal for one is the refusal for every other
	// failure.
	//nolint:gosec // G101: an audience name, and a fixed public one; it is
	// compared against, never presented.
	AdminCredentialAudience = "innsegl-admin"

	// AdminCredentialAlgorithm is the only signature algorithm admitted.
	// Pinned rather than read from the token: `alg` is attacker-controlled,
	// and a verifier that honours it is the classic JWT defect.
	AdminCredentialAlgorithm = "ES256"

	// AdminCredentialMaxTTL bounds `exp - iat`. A credential is a short-lived
	// admission to ASK, not a key, and the thing that would otherwise be doing
	// the bounding — a revocation list — is a dependency on the issuer being
	// reachable, which this design does not have.
	AdminCredentialMaxTTL = 15 * time.Minute

	// adminCredentialLeeway absorbs the difference between two machines'
	// clocks on `exp`, `nbf` and `iat`. Small relative to the TTL, and fixed
	// rather than configurable: IP §6.8's bound is about the LEDGER's ordering
	// and borrowing it here would let a deployment widen an admission window
	// by changing something that reads as unrelated.
	adminCredentialLeeway = 30 * time.Second

	// adminCredentialMaxBytes bounds a presented token before anything parses
	// it. Four kilobytes is far above any credential this format produces and
	// far below anything worth spending CPU on.
	adminCredentialMaxBytes = 4096

	// adminCredentialMaxTokenIDBytes bounds `jti`.
	adminCredentialMaxTokenIDBytes = 64

	// adminCredentialScheme is the one authorization scheme read.
	adminCredentialScheme = "Bearer"

	// adminScopeHeader carries the VERIFIED repository from the middleware to
	// the tool layer.
	//
	// INTERNAL, and unforgeable because of how it is used rather than because
	// of its name: the middleware overwrites it on every admitted request, and
	// Bind reads it only on a server the verifier is installed on. A client
	// that sets it on the agent listener is talking to a server that never
	// looks at it; a client that sets it on the admin listener has it replaced
	// before any handler runs.
	adminScopeHeader = "X-Innsegl-Admin-Scope"
)

// adminCredentialRefusal is the ONE answer to every credential failure.
//
// Constant, complete, and identical in every case. It names what the listener
// wants and nothing about what was wrong with what it got: an operator who has
// misconfigured a deployment runs `innsegl admin-credential verify` against
// their own token on their own machine and is told exactly which check failed.
const adminCredentialRefusal = "unauthorized: the identity-lifecycle listener requires a " +
	"repository-scoped credential"

// AdminCredentialClaims is the closed claim set.
//
// # What is present, and why each is
//
//   - `iss`, `aud` — which system minted it and what it is for. Both fixed.
//   - `repo`  — doc 02 §5's host/org/name. The ONLY subject-bearing claim,
//     and the whole authorization: this credential admits calls about this
//     repository and no other.
//   - `iat`, `nbf`, `exp` — the window. `exp - iat` is bounded.
//   - `jti` — names the ISSUANCE, never the holder. Nothing in this system
//     reads it today; it exists so that an issuer's own record of what it
//     minted can be cross-checked against what was admitted, without
//     re-minting every credential to add the field later. It reaches no event,
//     no idempotency row and no log line.
//
// # What is absent, by rule and by test
//
// No `sub`, no account id, no principal id, no email, no display name, no
// organisation, no membership, no role. The JSON decoding is strict, so a
// token carrying any of them is refused rather than accepted-and-ignored: a
// field that is tolerated is a field something will start relying on.
//
// The KEY ID is in the JOSE header rather than here. It names the verifying
// key and is exactly what verification needs; it says nothing about who holds
// the private half.
type AdminCredentialClaims struct {
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	Repo      string `json:"repo"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	Expiry    int64  `json:"exp"`
	TokenID   string `json:"jti"`
}

// adminCredentialJOSEHeader is the token's header. Three members, closed for
// the claim set's reason.
type adminCredentialJOSEHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KID       string `json:"kid"`
}

// AdminCredentialJWK is one verifying key, in the JWK spelling a key set uses.
//
// EC P-256 only: one algorithm, so there is no negotiation to get wrong and no
// second code path that a token can steer verification into.
type AdminCredentialJWK struct {
	KeyType   string `json:"kty"`
	Curve     string `json:"crv"`
	KID       string `json:"kid"`
	Algorithm string `json:"alg,omitempty"`
	Use       string `json:"use,omitempty"`
	X         string `json:"x"`
	Y         string `json:"y"`
}

// AdminCredentialJWKSet is the file a deployment mounts: the public halves of
// every key whose credentials this listener admits.
type AdminCredentialJWKSet struct {
	Keys []AdminCredentialJWK `json:"keys"`
}

// adminCredentialCoordinateBytes is the fixed width of a P-256 coordinate. The
// JWK spelling is fixed-width base64url, so a short encoding is a different
// key rather than the same one written tersely.
const adminCredentialCoordinateBytes = 32

// adminCredentialPointBytes is (*ecdsa.PublicKey).Bytes behind a seam, so that
// the refusal below it — unreachable for a key that got past the guard in
// front of it — is reachable from a test rather than left as a branch nobody
// has taken. IP §2 puts a 100% branch floor on this package, and an error path
// nothing has driven is an error path nobody knows the shape of. Never
// reassigned outside tests; internal/segment's validateDigest and
// internal/verify's marshalIndent are the same idiom for the same reason.
var adminCredentialPointBytes = (*ecdsa.PublicKey).Bytes

// adminCredentialMarshal is json.Marshal behind a seam, for the same reason:
// the two values rendered under it are closed structs of strings and int64s,
// so the encoder cannot fail on them in production, and the join that reports
// a failure is a branch a test has to be able to reach.
var adminCredentialMarshal = json.Marshal

// AdminCredentialJWKOf renders a P-256 public key as a JWK, with the key id
// RFC 7638 derives from the key itself.
//
// The key id is DERIVED rather than chosen, so a key file is the whole of what
// a minting side needs: there is no second value to keep beside it, and two
// deployments cannot disagree about what to call one key.
func AdminCredentialJWKOf(pub *ecdsa.PublicKey) (AdminCredentialJWK, error) {
	// The coordinates are READ here, once, to find out whether there is a
	// point at all — and nowhere else. (*ecdsa.PublicKey).Bytes below PANICS
	// on a key that names a curve and holds no point, and the deprecation that
	// covers these fields is about MODIFYING them and rebuilding keys by hand,
	// which nothing here does. A nil check is not that, and there is no
	// non-panicking alternative to it.
	//
	//nolint:staticcheck // SA1019: read, never written; Bytes panics without it.
	if pub == nil || pub.Curve != elliptic.P256() || pub.X == nil || pub.Y == nil {
		return AdminCredentialJWK{}, errors.New(
			"an admin-credential key must be an ECDSA P-256 public key")
	}
	// The uncompressed SEC 1 encoding, from the key's own method rather than
	// from its coordinate fields: those are deprecated precisely because
	// reading and rebuilding them by hand is how an invalid key gets made.
	//
	// ONE refusal for all three ways this can fail — the method's own error, a
	// wrong length, a compressed form — because they are one fact: what came
	// back is not a P-256 point this format can carry.
	//
	// UNREACHABLE for a key that got past the guard above, and kept anyway:
	// the three lines below index into this slice, and a length assumed rather
	// than checked is how a key of the wrong shape becomes a silently wrong
	// key id. It is driven through adminCredentialPointBytes, which is what
	// makes "refused, with no key id derived" a measured fact rather than a
	// claim about a branch nothing has taken.
	point, err := adminCredentialPointBytes(pub)
	if err != nil || len(point) != 1+2*adminCredentialCoordinateBytes || point[0] != 4 {
		return AdminCredentialJWK{}, fmt.Errorf(
			"the verification key is not an uncompressed P-256 point: %w", err)
	}
	x := point[1 : 1+adminCredentialCoordinateBytes]
	y := point[1+adminCredentialCoordinateBytes:]

	jwk := AdminCredentialJWK{
		KeyType:   "EC",
		Curve:     "P-256",
		Algorithm: AdminCredentialAlgorithm,
		Use:       "sig",
		X:         base64.RawURLEncoding.EncodeToString(x),
		Y:         base64.RawURLEncoding.EncodeToString(y),
	}
	jwk.KID = adminCredentialThumbprint(jwk)
	return jwk, nil
}

// adminCredentialThumbprint is RFC 7638's key id: SHA-256 over the required
// members in lexicographic order, base64url. Written out rather than
// marshalled from a map, because the member ORDER is the specification.
func adminCredentialThumbprint(jwk AdminCredentialJWK) string {
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`, jwk.X, jwk.Y)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// AdminCredentialSigningInput is the `header.payload` a signature is taken
// over.
//
// It is here, and not with the minting command, so that ONE definition of the
// format produces the bytes that are signed and the bytes that are verified.
// The signing itself is deliberately elsewhere: this process holds no private
// key (E8), and a package that could sign is a package that could be handed
// one.
func AdminCredentialSigningInput(kid string, claims AdminCredentialClaims) (string, error) {
	if kid == "" {
		return "", errors.New("an admin credential needs a key id: a verifier has no way to " +
			"choose between the keys in a rotating key set without one")
	}
	// Neither Marshal can fail: both types are closed structs of strings and
	// int64s, with no interface member, no map and no custom marshaller
	// between them. The errors are joined and returned rather than dropped
	// anyway — a defect that made one of them possible must not be the thing
	// that silently signs an empty segment — and that is why there is one
	// unreachable branch here rather than two. It is driven through
	// adminCredentialMarshal, so what that branch RETURNS on the way out —
	// nothing to sign, and the encoder's own failure — is measured.
	header, headerErr := adminCredentialMarshal(adminCredentialJOSEHeader{
		Algorithm: AdminCredentialAlgorithm,
		Type:      "JWT",
		KID:       kid,
	})
	payload, payloadErr := adminCredentialMarshal(claims)
	if err := errors.Join(headerErr, payloadErr); err != nil {
		return "", fmt.Errorf("rendering the credential: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload), nil
}

// AdminCredentialConfig is what a verifier is built from.
type AdminCredentialConfig struct {
	// KeySetFile is the JWKS this listener admits credentials from. Required.
	// It is read once, here, and never again.
	KeySetFile string
}

// AdminCredentialVerifier admits a credential, or does not say why.
//
// THERE IS NO INJECTED CLOCK, and its absence is deliberate. One stood here —
// an `AdminCredentialConfig.Now` documented "for tests" — and nothing ever set
// it: not this process, which has one clock, and not a test, because every
// time-dependent refusal below is driven by minting claims around the real
// instant rather than by moving a fake one. A seam no caller uses is a
// production default nothing exercises and a branch nobody has taken, which is
// what IP §2's floor is for; a test-only caller would have taken it and proved
// nothing about the deployment. It was removed rather than covered.
type AdminCredentialVerifier struct {
	keys map[string]*ecdsa.PublicKey
	// kids is the key ids in file order, for the operator-facing report.
	kids []string
	file string
}

// AdminScope is what an admitted credential authorises: one repository.
type AdminScope struct{ Repo string }

// NewAdminCredentialVerifier reads the key set and builds the verifier, or
// reports why the deployment cannot be authenticated.
//
// EVERY PROBLEM HERE FAILS THE PROCESS. A deployment that believes it is
// authenticated and is not is worse than one that knows it is open, so an
// absent file, an unreadable one, an empty key set, a key of the wrong type
// and two keys sharing one id are all refused before anything listens.
func NewAdminCredentialVerifier(cfg AdminCredentialConfig) (*AdminCredentialVerifier, error) {
	if strings.TrimSpace(cfg.KeySetFile) == "" {
		return nil, errors.New("no admin-credential key set: the identity-lifecycle listener " +
			"cannot authenticate anything without the public keys it admits")
	}
	body, err := os.ReadFile(cfg.KeySetFile)
	if err != nil {
		return nil, fmt.Errorf("reading the admin-credential key set %s: %w", cfg.KeySetFile, err)
	}

	var set AdminCredentialJWKSet
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&set); err != nil {
		return nil, fmt.Errorf("the admin-credential key set %s is not a JWK set: %w",
			cfg.KeySetFile, err)
	}
	if len(set.Keys) == 0 {
		return nil, fmt.Errorf("the admin-credential key set %s holds no keys, so it would "+
			"admit nothing and every call would be refused", cfg.KeySetFile)
	}

	v := &AdminCredentialVerifier{
		keys: make(map[string]*ecdsa.PublicKey, len(set.Keys)),
		file: cfg.KeySetFile,
	}
	for i, jwk := range set.Keys {
		pub, keyErr := adminCredentialPublicKey(jwk)
		if keyErr != nil {
			return nil, fmt.Errorf("the admin-credential key set %s, key %d: %w",
				cfg.KeySetFile, i, keyErr)
		}
		if _, dup := v.keys[jwk.KID]; dup {
			// Two keys under one id is a key set whose answer depends on
			// iteration order, which is a verifier that admits different
			// credentials on different boots.
			return nil, fmt.Errorf("the admin-credential key set %s holds two keys with the "+
				"id %q; a verifier cannot choose between them", cfg.KeySetFile, jwk.KID)
		}
		v.keys[jwk.KID] = pub
		v.kids = append(v.kids, jwk.KID)
	}
	return v, nil
}

// adminCredentialPublicKey turns one JWK into a usable P-256 public key, or
// says what is wrong with it.
func adminCredentialPublicKey(jwk AdminCredentialJWK) (*ecdsa.PublicKey, error) {
	switch {
	case jwk.KeyType != "EC":
		return nil, fmt.Errorf("kty is %q; only EC keys are admitted", jwk.KeyType)
	case jwk.Curve != "P-256":
		return nil, fmt.Errorf("crv is %q; only P-256 is admitted", jwk.Curve)
	case jwk.Algorithm != "" && jwk.Algorithm != AdminCredentialAlgorithm:
		return nil, fmt.Errorf("alg is %q; only %s is admitted", jwk.Algorithm, AdminCredentialAlgorithm)
	case jwk.Use != "" && jwk.Use != "sig":
		return nil, fmt.Errorf("use is %q; a verification key is for signatures", jwk.Use)
	case jwk.KID == "":
		return nil, errors.New("no kid; a key that cannot be named cannot be selected by a token")
	}
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil || len(x) != adminCredentialCoordinateBytes {
		return nil, fmt.Errorf("x is not %d base64url-encoded bytes", adminCredentialCoordinateBytes)
	}
	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil || len(y) != adminCredentialCoordinateBytes {
		return nil, fmt.Errorf("y is not %d base64url-encoded bytes", adminCredentialCoordinateBytes)
	}

	// Parsed rather than assembled, so the standard library refuses a pair
	// that is not a point on the curve. A "public key" that is not a point
	// makes signature verification meaningless rather than merely wrong, and
	// building one field by field is what the deprecated coordinate accessors
	// exist to stop.
	point := make([]byte, 1+2*adminCredentialCoordinateBytes)
	point[0] = 4
	copy(point[1:], x)
	copy(point[1+adminCredentialCoordinateBytes:], y)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, fmt.Errorf("the coordinates are not a point on P-256: %w", err)
	}
	return pub, nil
}

// KeyIDs returns the key ids this verifier admits, in file order. For the
// start-up log: which keys are live is an operator's business, and a key id
// says nothing about who holds the private half.
func (v *AdminCredentialVerifier) KeyIDs() []string { return slices.Clone(v.kids) }

// KeySetFile returns the path the keys were read from.
func (v *AdminCredentialVerifier) KeySetFile() string { return v.file }

// Verify reports whether token is admissible and, if so, what it authorises.
//
// NO ERROR, ON PURPOSE. Every caller in this process renders one refusal, so a
// reason returned here could only ever be logged or leaked; not producing one
// is what makes the byte-identical refusal a property of the type rather than
// a discipline at each call site. `Explain` is the operator-facing form and is
// never reached from a served request.
func (v *AdminCredentialVerifier) Verify(token string) (AdminScope, bool) {
	scope, err := v.Explain(token)
	if err != nil {
		return AdminScope{}, false
	}
	return scope, true
}

// Explain verifies and says what failed. It exists for `innsegl
// admin-credential verify`, which an operator runs on their own machine
// against their own token — the debugging the served refusal deliberately
// withholds.
//
//nolint:gocyclo // One check per failure mode, each with its own message.
func (v *AdminCredentialVerifier) Explain(token string) (AdminScope, error) {
	if token == "" {
		return AdminScope{}, errors.New("no credential was presented")
	}
	if len(token) > adminCredentialMaxBytes {
		return AdminScope{}, fmt.Errorf("the credential is %d bytes, over the %d-byte bound",
			len(token), adminCredentialMaxBytes)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return AdminScope{}, fmt.Errorf("the credential has %d dot-separated segments, want 3",
			len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return AdminScope{}, fmt.Errorf("the header segment is not base64url: %w", err)
	}
	var header adminCredentialJOSEHeader
	if decodeErr := adminCredentialDecode(headerBytes, &header); decodeErr != nil {
		return AdminScope{}, fmt.Errorf("the header is not an admin-credential header: %w", decodeErr)
	}
	switch {
	case header.Algorithm != AdminCredentialAlgorithm:
		// The token's own `alg` never SELECTS anything; it is compared with
		// the one algorithm this verifier implements and nothing else.
		return AdminScope{}, fmt.Errorf("alg is %q; only %s is admitted",
			header.Algorithm, AdminCredentialAlgorithm)
	case header.Type != "" && header.Type != "JWT":
		return AdminScope{}, fmt.Errorf("typ is %q", header.Type)
	case header.KID == "":
		return AdminScope{}, errors.New("the header names no key id")
	}
	pub, known := v.keys[header.KID]
	if !known {
		return AdminScope{}, fmt.Errorf("key id %q is not in %s", header.KID, v.file)
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != 2*adminCredentialCoordinateBytes {
		return AdminScope{}, fmt.Errorf("the signature is not %d base64url-encoded bytes",
			2*adminCredentialCoordinateBytes)
	}
	// THE SIGNATURE BEFORE THE CLAIMS. Everything below reads values an
	// attacker chose; nothing reads them until the key set says they were
	// written by a key this deployment admits.
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(signature[:adminCredentialCoordinateBytes])
	s := new(big.Int).SetBytes(signature[adminCredentialCoordinateBytes:])
	if !ecdsa.Verify(pub, sum[:], r, s) {
		return AdminScope{}, fmt.Errorf("the signature does not verify under key %q", header.KID)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return AdminScope{}, fmt.Errorf("the claims segment is not base64url: %w", err)
	}
	var claims AdminCredentialClaims
	if err := adminCredentialDecode(payloadBytes, &claims); err != nil {
		// The strict decoding is what makes the closed claim set a property
		// rather than a convention: a member outside it is refused here.
		return AdminScope{}, fmt.Errorf("the claims are not an admin-credential claim set "+
			"(it carries a repository and nothing that identifies an account): %w", err)
	}
	return v.checkClaims(claims)
}

// checkClaims is the second half of Explain: what an admitted signature said.
//
// The clock is read HERE, on every call, and not once at construction: a
// verifier built at start-up and consulted for the life of the process must
// answer "expired" about the instant the call arrived.
func (v *AdminCredentialVerifier) checkClaims(claims AdminCredentialClaims) (AdminScope, error) {
	now := time.Now().UTC()
	switch {
	case claims.Issuer != AdminCredentialIssuer:
		return AdminScope{}, fmt.Errorf("iss is %q, want %q", claims.Issuer, AdminCredentialIssuer)
	case claims.Audience != AdminCredentialAudience:
		return AdminScope{}, fmt.Errorf("aud is %q, want %q", claims.Audience, AdminCredentialAudience)
	case claims.TokenID == "":
		return AdminScope{}, errors.New("jti is absent")
	case len(claims.TokenID) > adminCredentialMaxTokenIDBytes:
		return AdminScope{}, fmt.Errorf("jti is %d bytes, over the %d-byte bound",
			len(claims.TokenID), adminCredentialMaxTokenIDBytes)
	case claims.IssuedAt <= 0 || claims.NotBefore <= 0 || claims.Expiry <= 0:
		return AdminScope{}, errors.New("iat, nbf and exp are all required")
	case claims.Expiry <= claims.IssuedAt:
		return AdminScope{}, errors.New("exp is not after iat")
	case claims.Expiry-claims.IssuedAt > int64(AdminCredentialMaxTTL.Seconds()):
		return AdminScope{}, fmt.Errorf("exp is %ds after iat, over the %s bound",
			claims.Expiry-claims.IssuedAt, AdminCredentialMaxTTL)
	case time.Unix(claims.NotBefore, 0).After(now.Add(adminCredentialLeeway)):
		return AdminScope{}, errors.New("the credential is not valid yet")
	case time.Unix(claims.IssuedAt, 0).After(now.Add(adminCredentialLeeway)):
		return AdminScope{}, errors.New("iat is in the future")
	case !time.Unix(claims.Expiry, 0).After(now.Add(-adminCredentialLeeway)):
		return AdminScope{}, errors.New("the credential has expired")
	}
	// doc 02 §5's own grammar, from the one definition of it. A repository
	// this verifier admitted and the ledger would later refuse would be a
	// credential that authorises a call nothing can record.
	if err := event.ValidateRepo(claims.Repo); err != nil {
		return AdminScope{}, fmt.Errorf("repo %q is not doc 02 §5's host/org/name: %w",
			claims.Repo, err)
	}
	return AdminScope{Repo: claims.Repo}, nil
}

// adminCredentialDecode is the strict JSON read both segments use. Unknown
// members are an error: a field that is tolerated is a field something starts
// relying on, and the whole point of the claim set is that it is closed.
func adminCredentialDecode(body []byte, into any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing content after the JSON object")
	}
	return nil
}

// Handler wraps next with the credential check.
//
// It is the WHOLE listener's handler that is wrapped, not a route: the check
// is made before the MCP session layer, so `initialize` and `tools/list` are
// refused on the same terms as a tool call and an unauthenticated caller
// cannot even learn the surface.
func (v *AdminCredentialVerifier) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope, ok := v.Verify(adminCredentialToken(r.Header.Get("Authorization")))
		if !ok {
			// One status, one body, nothing derived from what was wrong. The
			// token is not logged, not echoed and not measured.
			//
			// http.Error rather than a hand-written write, for the reason its
			// own failure mode is: the status line is already sent by the time
			// a write can fail, so there is nothing to act on, and a branch
			// that could only be taken then would be an untestable one on a
			// path IP §2 holds to its branch floor. It also sets the content
			// type and nosniff, which a refusal a browser may see should have.
			w.Header().Set("WWW-Authenticate", adminCredentialScheme)
			http.Error(w, adminCredentialRefusal, http.StatusUnauthorized)
			return
		}
		// The credential does not travel further than the check. What goes on
		// is the repository it authorises — the only thing any tool needs, and
		// the only thing a log downstream could then possibly hold.
		r.Header.Del("Authorization")
		r.Header.Set(adminScopeHeader, scope.Repo)
		next.ServeHTTP(w, r)
	})
}

// adminCredentialToken reads the bearer token out of an Authorization header.
// Anything that is not exactly one `Bearer <token>` yields the empty string,
// which is refused like every other failure.
func adminCredentialToken(header string) string {
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, adminCredentialScheme) {
		return ""
	}
	return strings.TrimSpace(token)
}

// ---------------------------------------------------------------------------
// The scope, as the tools read it.
// ---------------------------------------------------------------------------

// adminScopeContextKey is this package's own type, so nothing outside it can
// place or read a scope by naming a string.
type adminScopeContextKey struct{}

// withAdminScope carries a verified credential's repository to the tools.
func withAdminScope(ctx context.Context, scope AdminScope) context.Context {
	return context.WithValue(ctx, adminScopeContextKey{}, scope)
}

// adminScopeOf returns the scope in ctx, and whether there is one. Absent
// means NO ENFORCEMENT: single-listener mode, and every deployment before
// #264.
func adminScopeOf(ctx context.Context) (AdminScope, bool) {
	scope, ok := ctx.Value(adminScopeContextKey{}).(AdminScope)
	return scope, ok
}

// adminScopeAdmits reports whether the caller may act on repo.
//
// # The two answers that are not obvious
//
// NO SCOPE ADMITS EVERYTHING. That is single-listener mode and every
// deployment that has not turned the check on: the tools behave exactly as
// they did, which is what makes this additive rather than a change to them.
//
// AN EMPTY REPOSITORY IS ADMITTED BY NOBODY once a scope is in force. A run
// registered before ADR-0045 made `repo` required has none recorded, and a run
// that cannot be shown to be in this credential's repository is not in it. The
// alternative — admitting it — would make every pre-ADR-0045 run reachable
// from every credential.
//
// Comparison is exact. doc 02 §5 lowercases the host and leaves org and name
// case-sensitive, so a case-folding comparison here would admit a repository
// that is a DIFFERENT repository on every forge that allows both spellings.
func adminScopeAdmits(ctx context.Context, repo string) bool {
	scope, enforced := adminScopeOf(ctx)
	if !enforced {
		return true
	}
	return repo != "" && repo == scope.Repo
}

// adminScopeRefusal is the refusal for a call whose arguments name a
// repository the credential does not authorise.
//
// INVARIANT_VIOLATION, which IP §4 defines as "either this code has a defect
// or something is using a credential it should not have" — the second half,
// exactly. The message names NEITHER repository: the credential's own is
// nothing the caller needs told back, and the one it asked about would confirm
// what a probe was guessing.
//
// It is deliberately NOT the refusal the run-scoped tools use. Those answer as
// a run that does not exist, because a run id is public in every Agent-Run
// trailer; a repository argument is the caller's own and reveals nothing by
// being refused.
func adminScopeRefusal(tool ToolName) error {
	return Errorf(ClassInvariantViolation, "",
		"%s: this credential does not authorise the repository this call names", tool)
}
