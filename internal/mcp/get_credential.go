// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/spire"
)

// get_credential — RM-023 (#31). IP §4:
//
//	get_credential(run_id, audience) → {jwt_svid, expires_at}. Fails closed if
//	run retired, entry missing, or audience not in the allowlist (`sigstore`
//	initially).
//
// # Four things this file is careful about
//
// FAIL CLOSED, IN ORDER. Four gates run before SPIRE is asked for anything:
// the run id has to name a run, the audience has to be on the allowlist, the
// ledger has to say the run is not retired, and SPIRE's own server has to
// still hold a registration entry for it. Only then is a credential minted,
// and only then is it released — after the issuance is recorded (I3).
//
// RETIREMENT IS IMMEDIATE, AND THAT IS THIS LAYER'S OBLIGATION. RM-014
// measured SPIRE's own convergence at 3–7 seconds: a deleted entry has to fall
// out of the server's cache and then the agent's, and inside that window an
// agent still serves an SVID it already minted. IP §6.2 allows no such grace
// path "through the MCP", so this tool caches nothing — no run state, no
// credential, and (ADR-0004) no idempotency key, which means a replay can
// never be answered out of a stored reply either. Every call re-reads
// authoritative state: the ledger for retirement, the SPIRE *server* for the
// entry. Both change the instant the write that changed them commits.
//
// NO IDEMPOTENCY KEY, EVER. ADR-0004: the tool takes none and
// `credential_issued` must carry none. IP §6.2 requires an expired SVID to be
// re-fetched transparently, so a repeat call is a second issuance and not a
// retry of the first. Each is its own auditable fact, and collapsing them
// would hide credential churn — which is precisely the signal an auditor is
// looking for.
//
// ONE AUDIENCE PER CREDENTIAL. The mint request names exactly one audience and
// carries no TTL. A multi-audience token would be accepted at more than one
// relying party, which is the misuse IP §6.2 exists to prevent; a TTL in the
// request would be this code's opportunity to extend one, which IP §6.2
// forbids outright. The server's own `default_jwt_svid_ttl` governs instead.

// AudienceSigstore is the audience IP §4 puts on the allowlist initially:
// "audience not in the allowlist (`sigstore` initially)". IP §1 is what it is
// for — "JWT-SVID (audience-bound to Sigstore) → SIGSTORE_ID_TOKEN → Fulcio".
const AudienceSigstore = "sigstore"

// Retired reports whether the run has been retired.
func (r CredentialRun) Retired() bool { return !r.RetiredAt.IsZero() }

// Ref renders the run as the reference internal/spire takes: the three PATH
// SEGMENTS of its SPIFFE ID, read off the ID itself.
//
// Not off AgentType and TaskID, which since RM-079 (#116) are the ledger's
// record of what the run really was and not what its identity says. SPIRE
// holds the segments and nothing else, so a lookup or a deletion built from
// the recorded values would address an entry that does not exist. Reading them
// off the recorded SPIFFE ID also means no read path needs the deployment
// secret: rotating it cannot strand a live run.
//
// It refuses an identity that is not one rather than returning a zero RunRef,
// which would ask SPIRE about `spiffe://{td}/agent///`. Both callers have
// already put the same string through credentialRunIdentity, so the error is
// unreachable from them — and it is returned rather than asserted because the
// directory is an interface and the next implementation of it is not this one.
func (r CredentialRun) Ref() (spire.RunRef, error) {
	run, err := spire.RunRefOf(r.SPIFFEID)
	if err != nil {
		return spire.RunRef{}, Errorf(ClassInvariantViolation, r.RunID,
			"run %q has no usable identity: %v", r.RunID, err)
	}
	return run, nil
}

// MintedCredential is one JWT-SVID as SPIRE handed it over.
//
// E8: the MCP holds tokens and metadata, never keys. Nothing in this struct is
// a private key and nothing in this package stores one; the token itself is
// handed to the caller and dropped.
type MintedCredential struct {
	Token     string
	SPIFFEID  string
	Audience  string
	ExpiresAt time.Time
}

// CredentialEntries asks SPIRE whether the run still has a registration entry.
// *spire.Client implements it.
//
// RequireActiveRun asks the SPIRE server, not an agent cache. That is the
// whole of why retirement can be immediate here: the server's datastore is
// authoritative the instant a delete commits, and this tool refuses on that
// answer rather than waiting for a cache to agree.
type CredentialEntries interface {
	RequireActiveRun(ctx context.Context, run spire.RunRef) error
}

// CredentialMinter mints one audience-bound JWT-SVID for one identity.
// NewSPIREMinter is the implementation; the interface exists so that the four
// gates above can be tested exhaustively without a container per case.
type CredentialMinter interface {
	MintJWTSVID(ctx context.Context, spiffeID, audience string) (MintedCredential, error)
}

// CredentialLedger appends the `credential_issued` event. *ledger.Store
// implements it.
type CredentialLedger interface {
	Append(ctx context.Context, body event.Fields) (event.Fields, error)
}

// CredentialConfig is what get_credential needs from the rest of the system.
type CredentialConfig struct {
	// Runs resolves run_id. Required.
	Runs CredentialRuns
	// Entries is SPIRE's answer to "does this run still exist?". Required.
	Entries CredentialEntries
	// Minter mints the JWT-SVID. Required.
	Minter CredentialMinter
	// Ledger records the issuance. Required — I3 admits no action without a
	// record, so a tool with nowhere to write is a tool that must not run.
	Ledger CredentialLedger
	// Audiences is the allowlist. Nil means IP §4's initial set, {sigstore}.
	// An empty slice is refused rather than read as "allow nothing", because a
	// caller that meant to configure an allowlist and supplied none has made a
	// mistake this package should not silently reinterpret.
	Audiences []string
	// Now is the clock the validity window is checked against. Nil is
	// time.Now.
	Now func() time.Time
}

// credentialService is the configured tool.
type credentialService struct {
	runs      CredentialRuns
	entries   CredentialEntries
	minter    CredentialMinter
	ledger    CredentialLedger
	audiences []string
	now       func() time.Time
}

var (
	credentialMu     sync.RWMutex
	credentialActive *credentialService
)

// ConfigureGetCredential installs the dependencies get_credential runs on.
//
// It is a package-level installation rather than a field on Config because the
// registration seam of ADR-0016 hands a binder nothing but the server, and
// server.go is shared by all five tool authors. Every dependency is required:
// each one is a gate, and a missing gate is an open door rather than a
// degraded mode.
func ConfigureGetCredential(cfg CredentialConfig) error {
	switch {
	case cfg.Runs == nil:
		return Errorf(ClassInvariantViolation, "", "get_credential has no run directory")
	case cfg.Entries == nil:
		return Errorf(ClassInvariantViolation, "", "get_credential has no SPIRE entry check")
	case cfg.Minter == nil:
		return Errorf(ClassInvariantViolation, "", "get_credential has no credential minter")
	case cfg.Ledger == nil:
		return Errorf(ClassInvariantViolation, "", "get_credential has no ledger; I3 admits no issuance without a record")
	}

	audiences := cfg.Audiences
	if audiences == nil {
		audiences = []string{AudienceSigstore}
	}
	if len(audiences) == 0 {
		return Errorf(ClassInvariantViolation, "", "get_credential was given an empty audience allowlist")
	}
	for _, a := range audiences {
		if a == "" {
			return Errorf(ClassInvariantViolation, "",
				"the audience allowlist contains an empty audience; doc 02 §1 has no empty-string placeholders")
		}
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	credentialMu.Lock()
	defer credentialMu.Unlock()
	credentialActive = &credentialService{
		runs:      cfg.Runs,
		entries:   cfg.Entries,
		minter:    cfg.Minter,
		ledger:    cfg.Ledger,
		audiences: slices.Clone(audiences),
		now:       now,
	}
	return nil
}

// getCredentialIn is IP §4's parameter list, exactly. There is no
// idempotency_key and there must never be one (ADR-0004).
type getCredentialIn struct {
	RunID    string `json:"run_id"`
	Audience string `json:"audience"`
}

// getCredentialOut is IP §4's result shape, exactly: {jwt_svid, expires_at}.
//
// expires_at is spelled the way doc 02 §1 spells an instant — RFC 3339 UTC at
// millisecond precision — which is the same string the `credential_issued`
// event carries in `credential_expiry`, so the reply and the record of it
// cannot disagree by format. Truncation to the millisecond moves the stated
// expiry earlier, never later, which is the safe direction under IP §6.2.
type getCredentialOut struct {
	JWTSVID   string `json:"jwt_svid"`
	ExpiresAt string `json:"expires_at"`
}

func init() { RegisterTool(ToolGetCredential, bindGetCredential) }

func bindGetCredential(s *Server) error {
	return Bind(s, &sdk.Tool{
		Name: string(ToolGetCredential),
		Description: "Issue a JWT-SVID for one agent run, bound to one audience. " +
			"The credential belongs to the run it was issued for and to no other; " +
			"it is short-lived and is re-fetched rather than extended.",
	}, getCredential)
}

func getCredential(ctx context.Context, _ *sdk.CallToolRequest, in getCredentialIn) (getCredentialOut, error) {
	credentialMu.RLock()
	svc := credentialActive
	credentialMu.RUnlock()
	if svc == nil {
		// Alert-level: a bound tool with no dependencies behind it is a defect
		// in the wiring, and IP §4 has no "internal error" class (ADR-0016).
		return getCredentialOut{}, Errorf(ClassInvariantViolation, in.RunID,
			"get_credential is bound but not configured; no credential can be issued")
	}
	return svc.issue(ctx, in)
}

// issue is the four gates, the mint, and the record.
func (c *credentialService) issue(ctx context.Context, in getCredentialIn) (getCredentialOut, error) {
	// Gate 1 — a run id that cannot name a run names no run. Checked before
	// any dependency is consulted, so a malformed id costs nothing.
	if err := event.ValidateIdentifier(in.RunID); err != nil {
		return getCredentialOut{}, Errorf(ClassRunNotFound, "",
			"%q is not a run id: %v", in.RunID, err)
	}

	// Gate 2 — the audience allowlist (IP §4, IP §6.2). Checked before the run
	// is resolved, because it is a property of the request alone: the answer
	// cannot depend on state, and so it cannot leak state either.
	if !slices.Contains(c.audiences, in.Audience) {
		return getCredentialOut{}, Errorf(ClassAudienceMismatch, in.RunID,
			"audience %q is not on the allowlist %v", in.Audience, c.audiences)
	}

	// Gate 3 — the run exists and has not been retired. The ledger is what
	// knows the difference between a run that was retired and one that never
	// existed; SPIRE cannot tell them apart, because both have no entry.
	run, found, err := c.runs.CredentialRun(ctx, in.RunID)
	if err != nil {
		return getCredentialOut{}, credentialLedgerError(in.RunID, err)
	}
	if !found {
		return getCredentialOut{}, Errorf(ClassRunNotFound, in.RunID, "no run %q", in.RunID)
	}
	if run.Retired() {
		return getCredentialOut{}, Errorf(ClassRunAlreadyRetired, in.RunID,
			"run %q was retired at %s; retirement is effective immediately (IP §6.2)",
			in.RunID, event.NewTimestamp(run.RetiredAt))
	}

	// The directory's answer is checked, not trusted. A directory that named
	// another run's identity, or one outside the /agent/ subtree, would
	// otherwise be a second route to AB-10 — this time through a component
	// SPIRE's authorization policy cannot see. The policy refuses it too
	// (deploy/compose/spire/authz-policy.rego); this is the same refusal one
	// layer up, so neither alone is load-bearing.
	spiffeID, err := credentialRunIdentity(in.RunID, run)
	if err != nil {
		return getCredentialOut{}, err
	}

	// Gate 4 — SPIRE still holds the entry. Asked of the server, whose answer
	// changes the instant a delete commits.
	ref, err := run.Ref()
	if err != nil {
		return getCredentialOut{}, err
	}
	if active := c.entries.RequireActiveRun(ctx, ref); active != nil {
		return getCredentialOut{}, active
	}

	cred, err := c.minter.MintJWTSVID(ctx, spiffeID, in.Audience)
	if err != nil {
		return getCredentialOut{}, err
	}

	// What came back is checked against what was asked for, with the same
	// function a relying party calls. A credential for another identity, for
	// another audience, or already outside its validity window is never
	// released, whatever SPIRE said.
	if err := RequireCredentialFor(cred, run, in.Audience, c.now()); err != nil {
		return getCredentialOut{}, err
	}

	// I3 — no action without a record, and the action is the RELEASE of the
	// credential (doc 02 §3: "a JWT/X.509-SVID was released to the run"). So
	// the record is written before the token is returned, and a token whose
	// issuance could not be recorded is never returned at all: it is dropped
	// here and expires unused. The reverse order would record a release that
	// never happened, which is a false entry in an append-only ledger and
	// therefore the worse of the two failures.
	expiry := event.NewTimestamp(cred.ExpiresAt).String()
	if _, err := c.ledger.Append(ctx, event.Fields{
		event.FieldSchemaVersion:    event.SchemaVersion,
		event.FieldEventType:        event.EventTypeCredentialIssued,
		event.FieldRunID:            run.RunID,
		event.FieldSpiffeID:         spiffeID,
		event.FieldSource:           event.SourceMCP,
		event.FieldAudience:         cred.Audience,
		event.FieldCredentialExpiry: expiry,
		// No idempotency_key. ADR-0004 forbids it on credential_issued, and
		// the ledger enforces the absence.
	}); err != nil {
		return getCredentialOut{}, credentialLedgerError(run.RunID, err)
	}

	return getCredentialOut{JWTSVID: cred.Token, ExpiresAt: expiry}, nil
}

// RequireCredentialFor is the check whatever is about to USE a credential
// makes: is this credential this run's, for this relying party, and still
// valid?
//
// It is published because the three refusals belong to the user of a
// credential and not only to its issuer. IP §6.2:
//
//   - "a credential from run A used in a sign_commit for run B →
//     INVARIANT_VIOLATION" (doc 07 MCP-014, invariant I2);
//   - "a credential minted for `sigstore` presented anywhere else must fail
//     … and be useless at the wrong relying party" (doc 07 MCP-008);
//   - "Never sign with an expired credential; never extend TTLs to 'help'"
//     (doc 07 SIG-005).
//
// sign_commit (RM-033, #41) is the caller this exists for, and it does not
// exist yet. get_credential calls it on every mint before releasing one, so
// the check is exercised by shipped code rather than only published for a
// future one.
//
// It is a check on the credential's METADATA. Verifying the token's signature
// against the trust bundle is a different job and belongs to the verifier
// (RM-037) and to Fulcio.
func RequireCredentialFor(cred MintedCredential, run CredentialRun, relyingParty string, now time.Time) error {
	if cred.SPIFFEID != run.SPIFFEID {
		return Errorf(ClassInvariantViolation, run.RunID,
			"credential belongs to %q, this run is %q; a credential is bound to one run (I2, IP §6.2)",
			cred.SPIFFEID, run.SPIFFEID)
	}
	if cred.Audience != relyingParty {
		return Errorf(ClassAudienceMismatch, run.RunID,
			"credential was minted for audience %q and is being presented to %q (IP §6.2)",
			cred.Audience, relyingParty)
	}
	if !cred.ExpiresAt.After(now) {
		return Errorf(ClassCredentialExpired, run.RunID,
			"credential expired at %s and it is now %s; re-fetch, never extend (IP §6.2)",
			event.NewTimestamp(cred.ExpiresAt), event.NewTimestamp(now))
	}
	return nil
}

// ---------------------------------------------------------------------------
// The SPIRE-backed minter.
// ---------------------------------------------------------------------------

// mintMethod is the one admin RPC this tool adds to the MCP's surface. It is
// allowlisted, and scoped to the agent subtree, in
// deploy/compose/spire/authz-policy.rego; ADR-0012 and ADR-0019 are why.
const mintMethod = "/spire.api.server.svid.v1.SVID/MintJWTSVID"

type spireMinter struct {
	svid svidv1.SVIDClient
}

// NewSPIREMinter returns the minter get_credential runs on in the deployment:
// SPIRE's own server SVID API over the admin connection the MCP already holds.
//
// The connection is supplied rather than dialled here because the MCP has
// exactly one admin channel to SPIRE — mTLS between its own attested X509-SVID
// and the server's (ADR-0011) — and a second one would be a second credential
// to protect.
func NewSPIREMinter(conn grpc.ClientConnInterface) CredentialMinter {
	return &spireMinter{svid: svidv1.NewSVIDClient(conn)}
}

// MintJWTSVID mints one JWT-SVID for one identity and one audience.
//
// The request carries no TTL. IP §6.2: "never extend TTLs to 'help'." With the
// field absent the server's `default_jwt_svid_ttl` governs — five minutes on
// the shipped stack — and there is no code path here that could lengthen it.
func (m *spireMinter) MintJWTSVID(ctx context.Context, spiffeID, audience string) (MintedCredential, error) {
	id, err := credentialSplitID(spiffeID)
	if err != nil {
		return MintedCredential{}, Errorf(ClassInvariantViolation, "",
			"%q is not an identity to mint for: %v", spiffeID, err)
	}
	resp, err := m.svid.MintJWTSVID(ctx, &svidv1.MintJWTSVIDRequest{
		Id:       id,
		Audience: []string{audience},
	})
	if err != nil {
		return MintedCredential{}, credentialMintError("", err)
	}
	svid := resp.GetSvid()
	if svid.GetToken() == "" {
		return MintedCredential{}, Errorf(ClassInvariantViolation, "",
			"%s returned no token for %s", mintMethod, spiffeID)
	}
	if svid.GetExpiresAt() <= 0 {
		return MintedCredential{}, Errorf(ClassInvariantViolation, "",
			"%s returned a token with no expiry for %s; a credential with no validity "+
				"window cannot be refused when it expires", mintMethod, spiffeID)
	}
	return MintedCredential{
		Token: svid.GetToken(),
		// The proto getters are nil-safe, so an answer with no id renders as
		// the empty string and is refused a moment later by
		// RequireCredentialFor rather than by a branch here that only a
		// malformed SPIRE could reach.
		SPIFFEID:  "spiffe://" + svid.GetId().GetTrustDomain() + svid.GetId().GetPath(),
		Audience:  audience,
		ExpiresAt: time.Unix(svid.GetExpiresAt(), 0).UTC(),
	}, nil
}

// credentialMintClass is one row of the mapping below.
type credentialMintClass struct {
	class     Class
	retryable bool
}

// credentialMintCodes maps a MintJWTSVID failure onto IP §4's vocabulary.
//
// PermissionDenied is INVARIANT_VIOLATION and not an attestation failure: the
// admin credential either is not what it should be, or was used for something
// it must never do (AB-10). Both are alert-level and neither improves on a
// retry. This is the same reading internal/spire's classifyAdmin takes of the
// entry API, kept in step with it deliberately.
var credentialMintCodes = map[codes.Code]credentialMintClass{
	codes.PermissionDenied:   {ClassInvariantViolation, false},
	codes.Unauthenticated:    {ClassInvariantViolation, false},
	codes.InvalidArgument:    {ClassInvariantViolation, false},
	codes.FailedPrecondition: {ClassInvariantViolation, false},
	codes.Unavailable:        {ClassIdentityUnavailable, true},
	codes.DeadlineExceeded:   {ClassIdentityUnavailable, true},
	codes.ResourceExhausted:  {ClassIdentityUnavailable, true},
	codes.Internal:           {ClassIdentityUnavailable, true},
	codes.Aborted:            {ClassIdentityUnavailable, true},
	codes.NotFound:           {ClassRunNotFound, false},
}

// credentialMintError classifies a MintJWTSVID failure.
func credentialMintError(runID string, err error) error {
	st, ok := status.FromError(err)
	if !ok {
		// No gRPC status: the server was never reached. A lost connection is
		// the commonest case and it is retryable (IP §6.1).
		return classifyAs(ClassIdentityUnavailable, runID, err.Error(), true, mintMethod, err)
	}
	mapped, known := credentialMintCodes[st.Code()]
	if !known {
		// Unrecognised is not the same as transient: do not spin.
		mapped = credentialMintClass{ClassIdentityUnavailable, false}
	}
	return classifyAs(mapped.class, runID, st.Message(), mapped.retryable, mintMethod, err)
}

// credentialSplitID parses a SPIFFE ID into SPIRE's wire form.
func credentialSplitID(id string) (*types.SPIFFEID, error) {
	rest, ok := strings.CutPrefix(id, "spiffe://")
	if !ok {
		return nil, errors.New("not a SPIFFE ID")
	}
	i := strings.IndexByte(rest, '/')
	if i <= 0 {
		return nil, errors.New("no trust domain and path")
	}
	return &types.SPIFFEID{TrustDomain: rest[:i], Path: rest[i:]}, nil
}
