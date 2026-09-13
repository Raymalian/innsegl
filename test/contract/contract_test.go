// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc/codes"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/signing"
	"innsegl.dev/innsegl/internal/spire"
)

// ---------------------------------------------------------------------------
// The retryability table.
//
// It is transcribed BY HAND from IP §4 and ADR-0016 and is never read from the
// code under test. A matrix that asks the implementation what it thinks the
// flag is proves only that the implementation agrees with itself; this table
// is the specification, and a production change that disagrees with it shows
// up as a diff against the documents rather than as a green run.
//
// Where IP states the flag verbatim the quotation is the source. Where it does
// not — eight of the eleven — ADR-0016 is binding and each row is marked
// *stated* or *derived* exactly as that ADR marks it.
// ---------------------------------------------------------------------------

type retryRule struct {
	retryable bool
	source    string
}

var ip4Retryable = map[mcp.Class]retryRule{
	mcp.ClassAttestationFailed:       {false, `stated — IP §6.1: "ATTESTATION_FAILED, not retryable"`},
	mcp.ClassIdentityUnavailable:     {true, `stated — IP §6.1: "spire-server down at register_agent → IDENTITY_UNAVAILABLE, retryable"`},
	mcp.ClassCredentialExpired:       {false, "derived — ADR-0016: the credential is part of the request; IP §6.2 forbids extending a TTL to help"},
	mcp.ClassAudienceMismatch:        {false, "derived — ADR-0016: the allowlist does not change between two identical calls"},
	mcp.ClassLedgerUnavailable:       {true, "derived — ADR-0016: IP §6.4, Postgres down is a dependency outage"},
	mcp.ClassSigningUnavailable:      {true, `stated — IP §6.3: "Fulcio down → SIGNING_UNAVAILABLE, retryable"`},
	mcp.ClassTransparencyUnavailable: {true, "derived — ADR-0016: IP §6.3, Rekor down is the same shape as Fulcio down"},
	mcp.ClassRunNotFound:             {false, "derived — ADR-0016: an absent run does not appear by being asked for twice"},
	mcp.ClassRunAlreadyRetired:       {false, "derived — ADR-0016: IP §6.2, retirement is immediate and terminal, and I4 forbids un-retiring"},
	mcp.ClassDuplicateRequest:        {false, "derived — ADR-0016: the second answer to a duplicate is the same duplicate (ADR-0004)"},
	mcp.ClassInvariantViolation:      {false, "derived — ADR-0016: IP §6.2 makes it alert-level; a retry repeats the violation"},
}

// ---------------------------------------------------------------------------
// The matrix.
// ---------------------------------------------------------------------------

// verdict is what this issue concluded about one tool × class cell.
//
// TWO VALUES, AND THE HISTORY OF THE THIRD IS WHY.
//
// RM-028 (#36) had a third, deferred, for the eleven sign_commit cells the tool
// did not yet exist to decide. RM-071 (#94) decided all eleven and removed the
// value with it, on this reasoning: IP §4 has exactly five tools and all five
// are now bound, so a verdict of "the tool does not exist yet" can never be
// constructed again.
//
// RM-131 (#210) made that premise false — the surface became eight names with
// three implementations outstanding — and put the value back, with the
// safeguard that TestMCP006TheMatrixIsExactlyToolsTimesClasses refused it on
// any tool that HAD a binder, so it could only ever describe a tool that
// genuinely was not there.
//
// RM-128 (#207) bound the eighth, so the premise holds again and the value is
// gone again. This time the assertion that replaced it is the positive one:
// the count test requires every name on the surface to HAVE a binder, which is
// the thing the deferred branch was really protecting. A ninth name added
// ahead of its implementation will fail there rather than be quietly
// describable, and whoever adds it can read this paragraph to see what the
// third value was for.
type verdict int

const (
	// reachable: an input a caller can send drives the SHIPPED tool to this
	// class. drive produces it.
	reachable verdict = iota
	// unreachable: no input can. IP §4 lists the class for every tool, so this
	// is a finding about the document, not a hole in the tests. why says which
	// dependency or argument the tool does not have.
	unreachable
)

// runIDRule is what IP §4's optional `run_id` must do on this cell. doc 02 §1
// makes absent and empty distinct states, so "absent" is asserted as the key
// not being there, never as the empty string.
type runIDRule int

const (
	runIDAbsent runIDRule = iota
	runIDPresent
)

type cell struct {
	tool    mcp.ToolName
	class   mcp.Class
	verdict verdict
	// why explains an unreachable cell. It is the finding.
	why string
	// runID is what the wire must carry. Only read when verdict is reachable.
	runID runIDRule
	// deadLedger marks a cell that needs Postgres to be genuinely down. Those
	// cells run together against one killed container.
	deadLedger bool
	// drive sends the input that reaches the class and returns what came back.
	drive func(t *testing.T, s *stack) wireError
}

// digestA and digestB are two well-formed doc 02 §1 payload digests. Two, so
// one idempotency key can be presented against two different requests.
const (
	digestA = "sha256:aa00000000000000000000000000000000000000000000000000000000000000"
	digestB = "sha256:bb00000000000000000000000000000000000000000000000000000000000000"
)

// matrix is every tool of IP §4 against every class of IP §4: 8 × 11 = 88.
//
// It is written out in full, in IP §4 order, rather than generated from the
// reachable cases — so that a class nobody thought about is a row that says so
// and not a row that is missing.
var matrix = []cell{
	// -----------------------------------------------------------------------
	// register_agent(agent_type, task_id, idempotency_key)
	// -----------------------------------------------------------------------
	{
		tool: mcp.ToolRegisterAgent, class: mcp.ClassAttestationFailed, verdict: unreachable,
		why: "register_agent reaches SPIRE only through the admin entry API, and internal/spire's " +
			"classifyAdmin (client.go) has no path to ATTESTATION_FAILED — it maps PermissionDenied " +
			"to INVARIANT_VIOLATION. The class is raised only by classifyWorkload (credential.go), " +
			"on the Workload API, which no MCP tool calls: attestation happens when the WORKLOAD " +
			"fetches its SVID from spire-agent, not when the MCP creates an entry. IP §6.1's " +
			"selector-mismatch case is real, and it is SPI-002's, not an MCP tool's.",
	},
	{
		tool: mcp.ToolRegisterAgent, class: mcp.ClassIdentityUnavailable, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			// IP §6.1's headline case: spire-server down at register_agent.
			s.spire.failRegister = &spire.Error{
				Class: spire.ClassIdentityUnavailable, Op: "register_agent",
				Message: "connection refused", Retryable: true,
			}
			return s.callExpectingError(t, mcp.ToolRegisterAgent, map[string]any{
				"agent_type": testAgentType, "task_id": testTaskID, "idempotency_key": "ident-down",
				"repo": testRepo, "branch": testBranch,
			})
		},
	},
	{
		tool: mcp.ToolRegisterAgent, class: mcp.ClassCredentialExpired, verdict: unreachable,
		why: "register_agent is handed no credential and mints none — IP §4 gives it three arguments, " +
			"none of them a token, and RegisterAgentConfig has no minter. There is nothing whose " +
			"validity window could have passed.",
	},
	{
		tool: mcp.ToolRegisterAgent, class: mcp.ClassAudienceMismatch, verdict: unreachable,
		why: "register_agent takes no audience and consults no allowlist. IP §4 puts the allowlist on " +
			"get_credential; asserted on the advertised input schema by " +
			"TestMCP006OnlyGetCredentialTakesAnAudience.",
	},
	{
		tool: mcp.ToolRegisterAgent, class: mcp.ClassLedgerUnavailable, verdict: reachable,
		runID: runIDAbsent, deadLedger: true,
		drive: func(t *testing.T, s *stack) wireError {
			return s.callExpectingError(t, mcp.ToolRegisterAgent, map[string]any{
				"agent_type": testAgentType, "task_id": testTaskID, "idempotency_key": "after-outage",
				"repo": testRepo, "branch": testBranch,
			})
		},
	},
	{
		tool: mcp.ToolRegisterAgent, class: mcp.ClassSigningUnavailable, verdict: unreachable,
		why: "no MCP tool but sign_commit talks to Fulcio (IP §6.3). RegisterAgentConfig has no " +
			"Sigstore dependency to fail; RM-033 (#41) is where this class becomes reachable.",
	},
	{
		tool: mcp.ToolRegisterAgent, class: mcp.ClassTransparencyUnavailable, verdict: unreachable,
		why: "no MCP tool but sign_commit talks to Rekor (IP §6.3). Deferred to RM-033 (#41) the same " +
			"way SIGNING_UNAVAILABLE is.",
	},
	{
		tool: mcp.ToolRegisterAgent, class: mcp.ClassRunNotFound, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			// classifyAdmin maps codes.NotFound to RUN_NOT_FOUND, and a
			// registration whose attested PARENT node is gone is exactly that:
			// SPIRE has nothing to hang the entry off.
			s.spire.failRegister = &spire.Error{
				Class: spire.ClassRunNotFound, Op: "register_agent",
				Message: "no such parent entry " + testParentID, Retryable: false,
			}
			return s.callExpectingError(t, mcp.ToolRegisterAgent, map[string]any{
				"agent_type": testAgentType, "task_id": testTaskID, "idempotency_key": "no-parent",
				"repo": testRepo, "branch": testBranch,
			})
		},
	},
	{
		tool: mcp.ToolRegisterAgent, class: mcp.ClassRunAlreadyRetired, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			// SPIRE says the entry exists and then says it holds none. The
			// only things that delete a run's entry are retirement and the
			// reaper, so register_agent fails closed rather than resurrecting
			// a retired identity under the same key.
			s.spire.duplicateOnRegister = true
			s.spire.vanishOnLookup = true
			return s.callExpectingError(t, mcp.ToolRegisterAgent, map[string]any{
				"agent_type": testAgentType, "task_id": testTaskID, "idempotency_key": "vanished",
				"repo": testRepo, "branch": testBranch,
			})
		},
	},
	{
		tool: mcp.ToolRegisterAgent, class: mcp.ClassDuplicateRequest, verdict: reachable,
		runID: runIDAbsent,
		drive: func(t *testing.T, s *stack) wireError {
			s.registerRun(t, "reused-key")
			// The same key, a different request. ADR-0004: the caller is
			// refused rather than handed an answer to a question it did not
			// ask. Real Postgres, real UNIQUE index.
			return s.callExpectingError(t, mcp.ToolRegisterAgent, map[string]any{
				"agent_type": "other-agent", "task_id": testTaskID, "idempotency_key": "reused-key",
				"repo": testRepo, "branch": testBranch,
			})
		},
	},
	{
		tool: mcp.ToolRegisterAgent, class: mcp.ClassInvariantViolation, verdict: reachable,
		runID: runIDAbsent,
		drive: func(t *testing.T, s *stack) wireError {
			// agent_type is a component of the run's SPIFFE ID, so doc 02 §5's
			// identifier grammar applies. Refused before any dependency is
			// consulted, which is why there is no run to name.
			return s.callExpectingError(t, mcp.ToolRegisterAgent, map[string]any{
				"agent_type": "Not An Identifier!", "task_id": testTaskID, "idempotency_key": "bad-type",
			})
		},
	},

	// -----------------------------------------------------------------------
	// get_credential(run_id, audience)
	// -----------------------------------------------------------------------
	{
		tool: mcp.ToolGetCredential, class: mcp.ClassAttestationFailed, verdict: unreachable,
		why: "get_credential's two SPIRE calls are RequireActiveRun (the admin entry API) and " +
			"MintJWTSVID (the admin SVID API). Neither classifier can produce ATTESTATION_FAILED: " +
			"credentialMintCodes maps PermissionDenied to INVARIANT_VIOLATION, and " +
			"TestMCP006TheMintPathNeverProducesAttestationFailed sweeps every gRPC code through the " +
			"SHIPPED minter to prove it.",
	},
	{
		tool: mcp.ToolGetCredential, class: mcp.ClassIdentityUnavailable, verdict: reachable,
		// FINDING: the mint path classifies with an empty run id
		// (credentialMintError("", err) in get_credential.go), so the one
		// class a caller is most likely to retry arrives without the run it
		// belongs to. IP §4 makes run_id optional, so this is legal — it is
		// asserted here as the observed behaviour, not endorsed.
		runID: runIDAbsent,
		drive: func(t *testing.T, s *stack) wireError {
			run := s.registerRun(t, "cred-ident-down")
			s.conn.failWith(codes.Unavailable, "spire-server is not accepting connections")
			return s.callExpectingError(t, mcp.ToolGetCredential, map[string]any{
				"run_id": run.RunID, "audience": mcp.AudienceSigstore,
			})
		},
	},
	{
		tool: mcp.ToolGetCredential, class: mcp.ClassCredentialExpired, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			run := s.registerRun(t, "cred-expired")
			// SPIRE hands back a token whose validity window has already
			// closed. IP §6.2: never sign with an expired credential, never
			// extend a TTL to help — so it is refused rather than released.
			s.conn.set(func(f *fakeConn) { f.expiry = time.Now().Add(-time.Minute) })
			return s.callExpectingError(t, mcp.ToolGetCredential, map[string]any{
				"run_id": run.RunID, "audience": mcp.AudienceSigstore,
			})
		},
	},
	{
		tool: mcp.ToolGetCredential, class: mcp.ClassAudienceMismatch, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			run := s.registerRun(t, "cred-audience")
			// IP §4: "audience not in the allowlist (`sigstore` initially)".
			return s.callExpectingError(t, mcp.ToolGetCredential, map[string]any{
				"run_id": run.RunID, "audience": "github",
			})
		},
	},
	{
		tool: mcp.ToolGetCredential, class: mcp.ClassLedgerUnavailable, verdict: reachable,
		runID: runIDPresent, deadLedger: true,
		drive: func(t *testing.T, s *stack) wireError {
			return s.callExpectingError(t, mcp.ToolGetCredential, map[string]any{
				"run_id": deadLedgerRunID, "audience": mcp.AudienceSigstore,
			})
		},
	},
	{
		tool: mcp.ToolGetCredential, class: mcp.ClassSigningUnavailable, verdict: unreachable,
		why: "get_credential mints a JWT-SVID; it never reaches Fulcio. IP §1 puts Fulcio downstream " +
			"of the credential, in sign_commit — RM-033 (#41).",
	},
	{
		tool: mcp.ToolGetCredential, class: mcp.ClassTransparencyUnavailable, verdict: unreachable,
		why: "get_credential mints a token and records the issuance; it never reaches Rekor. " +
			"CredentialConfig has no transparency dependency to be down. IP §6.3's case belongs to " +
			"sign_commit, RM-033 (#41).",
	},
	{
		tool: mcp.ToolGetCredential, class: mcp.ClassRunNotFound, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			return s.callExpectingError(t, mcp.ToolGetCredential, map[string]any{
				"run_id": unknownRunID, "audience": mcp.AudienceSigstore,
			})
		},
	},
	{
		tool: mcp.ToolGetCredential, class: mcp.ClassRunAlreadyRetired, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			run := s.registerRun(t, "cred-retired")
			s.retireRun(t, run.RunID)
			// IP §6.2: retirement is effective immediately, with no
			// cached-credential grace path through the MCP.
			return s.callExpectingError(t, mcp.ToolGetCredential, map[string]any{
				"run_id": run.RunID, "audience": mcp.AudienceSigstore,
			})
		},
	},
	{
		tool: mcp.ToolGetCredential, class: mcp.ClassDuplicateRequest, verdict: unreachable,
		why: "ADR-0004 forbids get_credential an idempotency_key, now or ever: IP §6.2 requires an " +
			"expired SVID to be re-fetched, so a repeat call is a second issuance and its own " +
			"auditable fact. With no key there is no claim to conflict with, and CredentialConfig " +
			"holds no idempotency store. Asserted on the advertised input schema by " +
			"TestMCP006AToolWithNoIdempotencyKeyCannotReachDuplicateRequest.",
	},
	{
		tool: mcp.ToolGetCredential, class: mcp.ClassInvariantViolation, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			run := s.registerRun(t, "cred-wrong-identity")
			// SPIRE returns a credential belonging to another run. I2 and
			// IP §6.2: a credential is bound to one run, and what came back is
			// checked against what was asked for before anything is released.
			s.conn.set(func(f *fakeConn) {
				f.id = "spiffe://" + testTrustDomain + "/agent/" + testAgentType + "/" + testTaskID + "/" + unknownRunID
			})
			return s.callExpectingError(t, mcp.ToolGetCredential, map[string]any{
				"run_id": run.RunID, "audience": mcp.AudienceSigstore,
			})
		},
	},

	// -----------------------------------------------------------------------
	// record_event(run_id, event_type, payload_digest, idempotency_key)
	// -----------------------------------------------------------------------
	{
		tool: mcp.ToolRecordEvent, class: mcp.ClassAttestationFailed, verdict: unreachable,
		why: "RecordEventConfig has three members — a run directory, the ledger and the idempotency " +
			"store — and not one of them is a SPIRE client. record_event never attests anything.",
	},
	{
		tool: mcp.ToolRecordEvent, class: mcp.ClassIdentityUnavailable, verdict: unreachable,
		why: "same reason: no SPIRE dependency. record_event learns a run's identity by reading the " +
			"`run_registered` the ledger already holds, so SPIRE being down cannot stop it recording.",
	},
	{
		tool: mcp.ToolRecordEvent, class: mcp.ClassCredentialExpired, verdict: unreachable,
		why: "no credential is presented to record_event and none is minted by it: RecordEventConfig " +
			"has no minter, and IP §4's four arguments carry no token. There is nothing whose " +
			"validity window could have passed.",
	},
	{
		tool: mcp.ToolRecordEvent, class: mcp.ClassAudienceMismatch, verdict: unreachable,
		why: "IP §4 gives record_event four arguments and none is an audience; it presents no " +
			"credential to a relying party, so there is no audience to be mismatched. Asserted on " +
			"the advertised input schema by TestMCP006OnlyGetCredentialTakesAnAudience.",
	},
	{
		tool: mcp.ToolRecordEvent, class: mcp.ClassLedgerUnavailable, verdict: reachable,
		runID: runIDAbsent, deadLedger: true,
		drive: func(t *testing.T, s *stack) wireError {
			// IP §6.4, verbatim: "Postgres down at any record_event →
			// LEDGER_UNAVAILABLE."
			return s.callExpectingError(t, mcp.ToolRecordEvent, map[string]any{
				"run_id": deadLedgerRunID, "event_type": "bash",
				"payload_digest": digestA, "idempotency_key": "after-outage",
			})
		},
	},
	{
		tool: mcp.ToolRecordEvent, class: mcp.ClassSigningUnavailable, verdict: unreachable,
		why: "record_event writes a `tool_call` event by reference (ADR-0021) and signs nothing. " +
			"RecordEventConfig has no Fulcio dependency to be down; IP §6.3's case belongs to " +
			"sign_commit, RM-033 (#41).",
	},
	{
		tool: mcp.ToolRecordEvent, class: mcp.ClassTransparencyUnavailable, verdict: unreachable,
		why: "record_event never reaches Rekor: it appends to the innsegl chain, and it is the " +
			"SEGMENT that is anchored (RM-020's Rekor work), asynchronously and not on this path. " +
			"IP §6.3's case belongs to sign_commit, RM-033 (#41).",
	},
	{
		tool: mcp.ToolRecordEvent, class: mcp.ClassRunNotFound, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			return s.callExpectingError(t, mcp.ToolRecordEvent, map[string]any{
				"run_id": unknownRunID, "event_type": "bash",
				"payload_digest": digestA, "idempotency_key": "unknown-run",
			})
		},
	},
	{
		tool: mcp.ToolRecordEvent, class: mcp.ClassRunAlreadyRetired, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			run := s.registerRun(t, "record-retired")
			s.retireRun(t, run.RunID)
			// I4: a retired run's history stays readable; it stops growing.
			return s.callExpectingError(t, mcp.ToolRecordEvent, map[string]any{
				"run_id": run.RunID, "event_type": "bash",
				"payload_digest": digestA, "idempotency_key": "record-after-retire",
			})
		},
	},
	{
		tool: mcp.ToolRecordEvent, class: mcp.ClassDuplicateRequest, verdict: reachable,
		runID: runIDAbsent,
		drive: func(t *testing.T, s *stack) wireError {
			run := s.registerRun(t, "record-dupe-setup")
			var out struct {
				EventID       string `json:"event_id"`
				ChainPosition int64  `json:"chain_position"`
			}
			s.callExpectingSuccess(t, mcp.ToolRecordEvent, map[string]any{
				"run_id": run.RunID, "event_type": "bash",
				"payload_digest": digestA, "idempotency_key": "record-dupe",
			}, &out)
			// The same key, a different body.
			return s.callExpectingError(t, mcp.ToolRecordEvent, map[string]any{
				"run_id": run.RunID, "event_type": "bash",
				"payload_digest": digestB, "idempotency_key": "record-dupe",
			})
		},
	},
	{
		tool: mcp.ToolRecordEvent, class: mcp.ClassInvariantViolation, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			// ADR-0021: event_type names the AGENT TOOL that was invoked.
			// Spelling one of doc 02 §3's own event types must fail loudly —
			// recording it would put a string confusable with an event type
			// into an append-only chain forever.
			return s.callExpectingError(t, mcp.ToolRecordEvent, map[string]any{
				"run_id": unknownRunID, "event_type": event.EventTypeRunRegistered,
				"payload_digest": digestA, "idempotency_key": "event-type-collision",
			})
		},
	},

	// -----------------------------------------------------------------------
	// sign_commit(run_id, repo, staged_ref, message, task_ref, idempotency_key)
	//
	// RM-071 (#94): the tripwire below fired the day RM-033 bound sign_commit,
	// and these eleven cells are the answer.
	//
	//	MissingTools() = []; sign_commit is bound, so its eleven matrix cells
	//	must stop being deferred and start being decided (RM-033, #41)
	//
	// RM-033's own reading of three cells (ATTESTATION_FAILED and
	// AUDIENCE_MISMATCH unreachable, the other nine reachable) is CONFIRMED by
	// every cell below, by measurement rather than by adoption — each why or
	// drive states the code path that was actually read.
	//
	// # Fakes versus the real Sigstore stack, argued once here
	//
	// test/contract has no Sigstore. SIGNING_UNAVAILABLE and
	// TRANSPARENCY_UNAVAILABLE are reached below by handing the fake
	// SignCommitSigner (fakeSCSigner, sign_commit_test.go) the exact sentinel
	// errors internal/signing defines for a dead Fulcio/Rekor — the same two
	// sentinels test/failure's SIG-002 and SIG-003 have already measured a REAL
	// blocked Fulcio and Rekor to actually raise. What is proved here is
	// narrower than what SIG-002/003 prove, and the two claims are kept
	// distinct on purpose:
	//
	//   - "the tool maps this dependency failure onto this class" — proved
	//     HERE, through the real transport, mcp.New, and the exported
	//     ConfigureSignCommit seam, driving signCommitService.signingError's
	//     shipped classification switch for real. Only the boundary the
	//     signer sits behind is a double.
	//   - "the real dependency can produce that failure" — already proved by
	//     SIG-002/SIG-003 against a real Fulcio and Rekor, in test/failure.
	//
	// A fake that returned Errorf(ClassSigningUnavailable, ...) directly would
	// be the manufacture RM-028's rule forbids — it would test nothing but
	// itself. A fake that returns internal/signing's own sentinel and lets the
	// tool's own code decide the class is the same move ADR-0026 already made
	// for ATTESTATION_FAILED: mcp.NewSPIREMinter, the shipped classifier, over
	// a faked grpc.ClientConnInterface. Reachability here is honest about
	// which of the two claims above it is making, and does not pretend to be
	// the other one.
	{
		tool: mcp.ToolSignCommit, class: mcp.ClassAttestationFailed, verdict: unreachable,
		why: "RM-033's reading, confirmed. sign_commit's only path to SPIRE is IssueForSigning, " +
			"which is SignCommitThroughGetCredential calling the SHIPPED get_credential in " +
			"process — the same admin SVID mint path get_credential's own ATTESTATION_FAILED cell " +
			"already reaches, and TestMCP006TheMintPathNeverProducesAttestationFailed already " +
			"sweeps every gRPC code through the shipped minter to prove it never produces this " +
			"class. sign_commit holds no spire.Client of its own and calls no Workload API, which " +
			"is where attestation happens (SPI-002's territory, not an MCP tool's). " +
			"TestMCP006SignCommitsCredentialPathNeverProducesAttestationFailed " +
			"(sign_commit_test.go) re-runs the same sweep DRIVING SIGN_COMMIT ITSELF rather than " +
			"get_credential, because sign_commit's own request path runs four gates " +
			"get_credential does not — the task claim, the workspace, the staged tree, the " +
			"pre-Phase-A Sigstore probe — before the credential is ever touched, and a claim " +
			"about this tool is only honest once measured through this tool.",
	},
	{
		tool: mcp.ToolSignCommit, class: mcp.ClassIdentityUnavailable, verdict: reachable,
		// FINDING, inherited rather than new: sign_commit's only route to
		// IDENTITY_UNAVAILABLE is IssueForSigning -> get_credential's mint
		// path, and src.prime returns get_credential's *mcp.Error unchanged.
		// get_credential's own cell already carries no run_id
		// (credentialMintError("", err)), so the same empty run_id reappears
		// here — it is get_credential's finding surfacing through a second
		// tool, not a second one.
		runID: runIDAbsent,
		drive: func(t *testing.T, s *stack) wireError {
			run := s.registerRun(t, "sc-ident-down-register")
			repo, tree := s.signCommitRepo(t)
			s.conn.failWith(codes.Unavailable, "spire-server is not accepting connections")
			got := s.callExpectingError(t, mcp.ToolSignCommit, signCommitArgs(run.RunID, repo, tree, "sc-ident-down"))
			// Mutation guard: IP §6.1 requires the abort BEFORE Phase A. A
			// regression that moved the credential fetch after the intent
			// append would still return this class — the check above would
			// not catch it — but would leave a commit_intent behind for a
			// signature that was never attempted. This line is what catches
			// that.
			if n := s.countEvents(t, run.RunID, event.EventTypeCommitIntent); n != 0 {
				t.Errorf("%d commit_intent events for a credential failure that IP §6.1 "+
					"requires to abort BEFORE Phase A", n)
			}
			return got
		},
	},
	{
		tool: mcp.ToolSignCommit, class: mcp.ClassCredentialExpired, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			run := s.registerRun(t, "sc-cred-expired-register")
			repo, tree := s.signCommitRepo(t)
			// IP §6.2: never sign with an expired credential. The same fake
			// SPIRE connection get_credential's own cell uses, hit through
			// sign_commit's IssueForSigning -> get_credential path.
			s.conn.set(func(f *fakeConn) { f.expiry = time.Now().Add(-time.Minute) })
			got := s.callExpectingError(t, mcp.ToolSignCommit, signCommitArgs(run.RunID, repo, tree, "sc-cred-expired"))
			if n := s.countEvents(t, run.RunID, event.EventTypeCommitIntent); n != 0 {
				t.Errorf("%d commit_intent events for a credential failure that IP §6.1 "+
					"requires to abort BEFORE Phase A", n)
			}
			return got
		},
	},
	{
		tool: mcp.ToolSignCommit, class: mcp.ClassAudienceMismatch, verdict: unreachable,
		why: "RM-033's reading, confirmed. IP §4 gives sign_commit no audience argument, and its " +
			"advertised input schema carries none — asserted by " +
			"TestMCP006OnlyGetCredentialTakesAnAudience, which now includes sign_commit. " +
			"Structurally, not only by schema: SignCommitThroughGetCredential.IssueForSigning " +
			"always requests mcp.AudienceSigstore, a constant none of sign_commit's six " +
			"arguments can influence, so even the credential fetch it makes internally has no " +
			"caller-controlled audience to mismatch.",
	},
	{
		tool: mcp.ToolSignCommit, class: mcp.ClassLedgerUnavailable, verdict: reachable,
		// sign_commit's idempotency claim (ADR-0004/ADR-0017) wraps the WHOLE
		// tool, the same way register_agent's and record_event's do — so a
		// dead Postgres is found at IdempotencyStore.claim, before
		// resolveRun ever runs. That is why this cell carries no run_id,
		// exactly the reason register_agent's and record_event's own
		// LEDGER_UNAVAILABLE cells do not either, and unlike get_credential's
		// and retire_agent's, which have no idempotency wrapper in the way.
		runID: runIDAbsent, deadLedger: true,
		drive: func(t *testing.T, s *stack) wireError {
			return s.callExpectingError(t, mcp.ToolSignCommit, map[string]any{
				"run_id": deadLedgerRunID, "repo": scPlaceholderRepo, "staged_ref": scPlaceholderStagedRef,
				"message": "fix(contract): ledger outage probe", "task_ref": testTaskID,
				"idempotency_key": "sc-after-outage",
			})
		},
	},
	{
		tool: mcp.ToolSignCommit, class: mcp.ClassSigningUnavailable, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			run := s.registerRun(t, "sc-fulcio-down-register")
			repo, tree := s.signCommitRepo(t)
			// The fake signer stands in for gitsign refusing because Fulcio
			// died between the pre-Phase-A probe and Phase B — the exact
			// sentinel internal/signing raises for it, letting
			// signCommitService.signingError's SHIPPED switch decide the
			// class. See the block comment above this section.
			s.scSigner.failWith(fmt.Errorf("gitsign: %w", signing.ErrSigningUnavailable))
			got := s.callExpectingError(t, mcp.ToolSignCommit, signCommitArgs(run.RunID, repo, tree, "sc-fulcio-down"))
			// Mutation guard: this must be a PHASE B failure and not a
			// coincidence from an earlier gate. If some other gate produced
			// this class for an unrelated reason, the signer would never run
			// and no intent would exist — both are checked.
			if n := s.scSigner.callCount(); n != 1 {
				t.Errorf("the signer ran %d times, want exactly 1: this cell is about a Phase B "+
					"failure, not an earlier gate", n)
			}
			if n := s.countEvents(t, run.RunID, event.EventTypeCommitIntent); n != 1 {
				t.Errorf("%d commit_intent events, want exactly 1: the intent is what IP §6.5 "+
					"leaves for the reconciler when Phase B fails", n)
			}
			if n := s.countEvents(t, run.RunID, event.EventTypeCommitRecorded); n != 0 {
				t.Errorf("%d commit_recorded events for a commit that was never signed", n)
			}
			return got
		},
	},
	{
		tool: mcp.ToolSignCommit, class: mcp.ClassTransparencyUnavailable, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			run := s.registerRun(t, "sc-rekor-down-register")
			repo, tree := s.signCommitRepo(t)
			s.scSigner.failWith(fmt.Errorf("gitsign: %w", signing.ErrTransparencyUnavailable))
			got := s.callExpectingError(t, mcp.ToolSignCommit, signCommitArgs(run.RunID, repo, tree, "sc-rekor-down"))
			if n := s.scSigner.callCount(); n != 1 {
				t.Errorf("the signer ran %d times, want exactly 1: this cell is about a Phase B "+
					"failure, not an earlier gate", n)
			}
			if n := s.countEvents(t, run.RunID, event.EventTypeCommitIntent); n != 1 {
				t.Errorf("%d commit_intent events, want exactly 1: the intent is what IP §6.5 "+
					"leaves for the reconciler when Phase B fails", n)
			}
			if n := s.countEvents(t, run.RunID, event.EventTypeCommitRecorded); n != 0 {
				t.Errorf("%d commit_recorded events for a commit that was never signed", n)
			}
			return got
		},
	},
	{
		tool: mcp.ToolSignCommit, class: mcp.ClassRunNotFound, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			// resolveRun fails before Workspace is ever touched, so the
			// repo/staged_ref below name nothing real and never have to.
			return s.callExpectingError(t, mcp.ToolSignCommit, map[string]any{
				"run_id": unknownRunID, "repo": scPlaceholderRepo, "staged_ref": scPlaceholderStagedRef,
				"message": "fix(contract): unknown run probe", "task_ref": testTaskID,
				"idempotency_key": "sc-unknown-run",
			})
		},
	},
	{
		tool: mcp.ToolSignCommit, class: mcp.ClassRunAlreadyRetired, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			run := s.registerRun(t, "sc-retired")
			s.retireRun(t, run.RunID)
			return s.callExpectingError(t, mcp.ToolSignCommit, map[string]any{
				"run_id": run.RunID, "repo": scPlaceholderRepo, "staged_ref": scPlaceholderStagedRef,
				"message": "fix(contract): retired run probe", "task_ref": testTaskID,
				"idempotency_key": "sc-retired-call",
			})
		},
	},
	{
		tool: mcp.ToolSignCommit, class: mcp.ClassDuplicateRequest, verdict: reachable,
		runID: runIDAbsent,
		drive: func(t *testing.T, s *stack) wireError {
			run := s.registerRun(t, "sc-dupe-setup")
			repo, tree := s.signCommitRepo(t)
			args := signCommitArgs(run.RunID, repo, tree, "sc-dupe")

			var out struct {
				CommitSHA string `json:"commit_sha"`
			}
			s.callExpectingSuccess(t, mcp.ToolSignCommit, args, &out)
			if out.CommitSHA == "" {
				t.Fatal("the first call produced no commit_sha; the duplicate this case is " +
					"about would prove nothing")
			}

			// The same key, a different request (IP §6.6: two different
			// messages under one key are two different commits).
			args["message"] = "fix(contract): a different message under the same key"
			got := s.callExpectingError(t, mcp.ToolSignCommit, args)

			// Mutation guard: ADR-0017's whole point is that the replay does
			// not sign a second commit. If it did, the class check above
			// would not catch it — DUPLICATE_REQUEST would still come back —
			// but the chain would hold two commit_intent/commit_recorded
			// pairs instead of one.
			if n := s.countEvents(t, run.RunID, event.EventTypeCommitIntent); n != 1 {
				t.Errorf("%d commit_intent events after a duplicate request, want exactly 1: "+
					"a replay that re-executed would sign a second commit (IP §6.6)", n)
			}
			if n := s.countEvents(t, run.RunID, event.EventTypeCommitRecorded); n != 1 {
				t.Errorf("%d commit_recorded events after a duplicate request, want exactly 1", n)
			}
			return got
		},
	},
	{
		tool: mcp.ToolSignCommit, class: mcp.ClassInvariantViolation, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			// Refused by signCommitCheckRequest before any dependency is
			// touched — an empty message can never be signed (IP §4) — so
			// run_id is echoed back verbatim and need not name a real run,
			// the same reason register_agent's own INVARIANT_VIOLATION cell
			// needs no dependency either.
			return s.callExpectingError(t, mcp.ToolSignCommit, map[string]any{
				"run_id": scInvariantRunID, "repo": scPlaceholderRepo, "staged_ref": scPlaceholderStagedRef,
				"message": "", "task_ref": testTaskID, "idempotency_key": "sc-empty-message",
			})
		},
	},

	// -----------------------------------------------------------------------
	// retire_agent(run_id)
	// -----------------------------------------------------------------------
	{
		tool: mcp.ToolRetireAgent, class: mcp.ClassAttestationFailed, verdict: unreachable,
		why: "retire_agent's one SPIRE call is RetireRun on the admin entry API, whose classifier " +
			"(classifyAdmin) has no ATTESTATION_FAILED case. Deleting an entry attests nothing.",
	},
	{
		tool: mcp.ToolRetireAgent, class: mcp.ClassIdentityUnavailable, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			run := s.registerRun(t, "retire-spire-down")
			s.spire.failRetire = &spire.Error{
				Class: spire.ClassIdentityUnavailable, Op: "retire_agent",
				Message: "connection refused", Retryable: true,
			}
			// ADR-0018: the record lands first, so this reports an INCOMPLETE
			// retirement — the run is retired as far as every MCP path is
			// concerned, and the entry is left for a retry or the reaper.
			return s.callExpectingError(t, mcp.ToolRetireAgent, map[string]any{"run_id": run.RunID})
		},
	},
	{
		tool: mcp.ToolRetireAgent, class: mcp.ClassCredentialExpired, verdict: unreachable,
		why: "IP §4 gives retire_agent one argument, a run_id, and RetireAgentConfig has no minter. " +
			"No credential reaches it and none is issued by it, so there is nothing whose validity " +
			"window could have passed.",
	},
	{
		tool: mcp.ToolRetireAgent, class: mcp.ClassAudienceMismatch, verdict: unreachable,
		why: "IP §4 gives retire_agent one argument, a run_id. It presents no credential to a relying " +
			"party, so there is no audience to be mismatched. Asserted on the advertised input " +
			"schema by TestMCP006OnlyGetCredentialTakesAnAudience.",
	},
	{
		tool: mcp.ToolRetireAgent, class: mcp.ClassLedgerUnavailable, verdict: reachable,
		runID: runIDPresent, deadLedger: true,
		drive: func(t *testing.T, s *stack) wireError {
			return s.callExpectingError(t, mcp.ToolRetireAgent, map[string]any{"run_id": deadLedgerRunID})
		},
	},
	{
		tool: mcp.ToolRetireAgent, class: mcp.ClassSigningUnavailable, verdict: unreachable,
		why: "retire_agent appends `run_retired` and deletes a SPIRE entry. RetireAgentConfig has no " +
			"Fulcio dependency to be down; IP §6.3's case belongs to sign_commit, RM-033 (#41).",
	},
	{
		tool: mcp.ToolRetireAgent, class: mcp.ClassTransparencyUnavailable, verdict: unreachable,
		why: "retire_agent never reaches Rekor; segment anchoring is asynchronous and is not on any " +
			"tool call path. IP §6.3's case belongs to sign_commit, RM-033 (#41).",
	},
	{
		tool: mcp.ToolRetireAgent, class: mcp.ClassRunNotFound, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			return s.callExpectingError(t, mcp.ToolRetireAgent, map[string]any{"run_id": unknownRunID})
		},
	},
	{
		tool: mcp.ToolRetireAgent, class: mcp.ClassRunAlreadyRetired, verdict: unreachable,
		why: "IP §4 makes this the one tool that must NOT report it: \"Idempotent: retiring a retired " +
			"run returns success with the original timestamp\", which doc 07 MCP-009 restates as the " +
			"parenthesised carve-out. retire_agent reads run.Retired() and SKIPS the append rather " +
			"than refusing. Asserted by TestMCP006RetireAgentIsIdempotentAndNeverReportsRunAlreadyRetired.",
	},
	{
		tool: mcp.ToolRetireAgent, class: mcp.ClassDuplicateRequest, verdict: unreachable,
		why: "ADR-0004: retire_agent accepts no idempotency_key and `run_retired` carries none — " +
			"\"a run retires once; a separate key would invent a way for two retirements of one run " +
			"to disagree\". RetireAgentConfig holds no idempotency store, so there is no claim to " +
			"conflict with. Asserted on the advertised input schema by " +
			"TestMCP006AToolWithNoIdempotencyKeyCannotReachDuplicateRequest.",
	},
	{
		tool: mcp.ToolRetireAgent, class: mcp.ClassInvariantViolation, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			// The run directory answers with an identity that is not this
			// run's. retire_agent checks the answer rather than trusting it,
			// because a directory that named another run's identity would
			// otherwise be a way to delete an entry that is not this run's.
			const forged = "run-ffffffffffffffffffffffffffffffff"
			s.appendRaw(t, event.Fields{
				event.FieldSchemaVersion:  event.SchemaVersion,
				event.FieldEventType:      event.EventTypeRunRegistered,
				event.FieldSource:         event.SourceMCP,
				event.FieldRunID:          forged,
				event.FieldSpiffeID:       "spiffe://" + testTrustDomain + "/agent/" + testAgentType + "/" + testTaskID + "/" + unknownRunID,
				event.FieldIdempotencyKey: "forged-directory",
				event.FieldAgentType:      testAgentType,
				event.FieldTaskRef:        testTaskID,
				event.FieldRepo:           testRepo,
				event.FieldBranch:         testBranch,
			})
			return s.callExpectingError(t, mcp.ToolRetireAgent, map[string]any{"run_id": forged})
		},
	},

	// -----------------------------------------------------------------------
	// describe_workspace(cwd)
	//
	// RM-126 (#205), E11. The tool answers what repository, worktree, branch
	// and task a path names. It is a PURE DERIVATION: it reads git plumbing on
	// a local filesystem, returns the answer, and writes nothing anywhere.
	//
	// One fact decides ten of these eleven. DescribeWorkspaceConfig has two
	// members and both of them are directories — the host root and the mount
	// it corresponds to. There is no SPIRE client, no ledger, no idempotency
	// store, no credential, no Fulcio and no Rekor; IP §4 gives the tool one
	// argument and it is a path. Nine of the eleven classes name a dependency
	// or an argument this tool does not have, and RUN_NOT_FOUND and
	// RUN_ALREADY_RETIRED name a run it is never told about — this is the tool
	// a harness calls BEFORE it has an identity, because its answer is what
	// register_agent's `repo` and `branch` are built from.
	//
	// So exactly one class is reachable, and that is the finding rather than a
	// gap: a tool with no dependencies has no dependency outage to report, and
	// IP §4's closed vocabulary leaves INVARIANT_VIOLATION as the only thing
	// it can say when a caller asks something it cannot answer. Every refusal
	// in workspace.go is that class, which is also why none was invented for
	// it — the vocabulary is a protected surface (doc 08 §3).
	// -----------------------------------------------------------------------
	{
		tool: mcp.ToolDescribeWorkspace, class: mcp.ClassAttestationFailed, verdict: unreachable,
		why: "DescribeWorkspaceConfig holds two directories and nothing else: the host root and " +
			"the mount it corresponds to. There is no SPIRE client and no Workload API on this " +
			"path — the tool describes a filesystem, and a filesystem does not attest.",
	},
	{
		tool: mcp.ToolDescribeWorkspace, class: mcp.ClassIdentityUnavailable, verdict: unreachable,
		why: "the same absence: no SPIRE dependency of any kind. This is the tool a harness calls " +
			"BEFORE it has an identity — its answer is what register_agent's repo and branch " +
			"arguments are built from — so SPIRE being unreachable cannot stop it answering.",
	},
	{
		tool: mcp.ToolDescribeWorkspace, class: mcp.ClassCredentialExpired, verdict: unreachable,
		why: "no credential is presented, minted or held. doc 01 §4 gives describe_workspace one " +
			"argument and it is a path; there is nothing here carrying a validity window whose " +
			"end could have passed, and no run token either — the tool authenticates nothing.",
	},
	{
		tool: mcp.ToolDescribeWorkspace, class: mcp.ClassAudienceMismatch, verdict: unreachable,
		why: "the tool presents no credential to a relying party, so there is no audience to be " +
			"mismatched, and its single argument is not one. Asserted on the advertised input " +
			"schema by TestMCP006OnlyGetCredentialTakesAnAudience.",
	},
	{
		tool: mcp.ToolDescribeWorkspace, class: mcp.ClassLedgerUnavailable, verdict: unreachable,
		why: "a pure derivation: it appends no event, resolves no run and holds neither a ledger " +
			"nor an idempotency store in its configuration. It is the one tool on the surface " +
			"that answers identically with Postgres gone, which is why it has no dead-ledger cell.",
	},
	{
		tool: mcp.ToolDescribeWorkspace, class: mcp.ClassSigningUnavailable, verdict: unreachable,
		why: "describe_workspace signs nothing and has no Fulcio in its configuration. Every " +
			"external call it makes is local read-only git plumbing — `worktree list`, " +
			"`symbolic-ref`, `rev-parse`, `remote get-url` — and none of them reaches a CA.",
	},
	{
		tool: mcp.ToolDescribeWorkspace, class: mcp.ClassTransparencyUnavailable, verdict: unreachable,
		why: "no Rekor dependency, and nothing on this path is published anywhere: the answer is " +
			"derived from the filesystem, returned to the caller and not recorded. There is no " +
			"transparency entry for it to be missing.",
	},
	{
		tool: mcp.ToolDescribeWorkspace, class: mcp.ClassRunNotFound, verdict: unreachable,
		why: "the tool takes no run_id. It runs before any run exists — a harness that knows only " +
			"its own cwd calls this first and register_agent second — so there is no run for it " +
			"to look up and fail to find.",
	},
	{
		tool: mcp.ToolDescribeWorkspace, class: mcp.ClassRunAlreadyRetired, verdict: unreachable,
		why: "the same absent argument, for the same reason: no run is named, resolved or written " +
			"to, so none can be found already retired. I4 protects a retired run's history from " +
			"growing, and this tool appends nothing to any run's history at all.",
	},
	{
		tool: mcp.ToolDescribeWorkspace, class: mcp.ClassDuplicateRequest, verdict: unreachable,
		why: "the tool takes no idempotency_key, and ADR-0004 requires one on exactly the tools " +
			"whose call has an effect. This one has none: the same cwd answers the same twice, " +
			"so a repeated call is not a replay and cannot key a request it did not name.",
	},
	{
		tool: mcp.ToolDescribeWorkspace, class: mcp.ClassInvariantViolation, verdict: reachable,
		runID: runIDAbsent,
		drive: func(t *testing.T, s *stack) wireError {
			// THE ONLY CLASS THIS TOOL CAN PRODUCE, driven through the refusal
			// it exists for: a cwd outside the directory the deployment mounts.
			//
			// A harness reports a path on its OWN machine, and the translation
			// onto this process's mount is the one thing the container cannot
			// work out for itself. Every way it can fail — the host root unset,
			// the path outside it, the tree not a working tree, the repository
			// with no `origin` — is a refusal rather than a guess, because a
			// guessed translation describes the wrong repository confidently
			// and the answer is on its way into an append-only record.
			//
			// run_id is ABSENT and not empty: the failure is scoped to a path,
			// there is no run to scope it to, and doc 02 §1 distinguishes the
			// two states.
			return s.callExpectingError(t, mcp.ToolDescribeWorkspace, map[string]any{
				"cwd": filepath.Join(s.projects, "..", "outside-the-mount"),
			})
		},
	},

	// -----------------------------------------------------------------------
	// observe_tool_call(run_id, tool, body, run_token?)
	//
	// RM-127 (#206), E11. The tool takes an observed call WITH its body, digests
	// and stores the body on the operator's own volume, and appends the
	// `tool_call` by reference. Two consequences decide most of these eleven.
	//
	// It holds no credential and reaches no remote service. ObserveToolCallConfig
	// has four members — a run directory, the ledger, the idempotency store and
	// a body volume — and a run-token secret; there is no SPIRE client, no
	// minter, no Fulcio and no Rekor. Five of the eleven classes name a
	// dependency this tool does not have.
	//
	// And it writes to TWO stores, not one. That is why LEDGER_UNAVAILABLE is
	// driven below through the volume rather than through Postgres: a broken
	// volume is a failure no other tool on the surface can produce, and the
	// class it returns is the whole of I3's converse — a body that could not be
	// kept must not be recorded as observed.
	// -----------------------------------------------------------------------
	{
		tool: mcp.ToolObserveToolCall, class: mcp.ClassAttestationFailed, verdict: unreachable,
		why: "ObserveToolCallConfig has no SPIRE client of any kind: a run directory, the ledger, " +
			"the idempotency store and a body volume. observe_tool_call attests nothing — it " +
			"records what a harness ALREADY observed, after the fact.",
	},
	{
		tool: mcp.ToolObserveToolCall, class: mcp.ClassIdentityUnavailable, verdict: unreachable,
		why: "same reason: no SPIRE dependency. The run's identity is read off the `run_registered` " +
			"the ledger already holds, so SPIRE being down cannot stop an observation being " +
			"stored and recorded.",
	},
	{
		tool: mcp.ToolObserveToolCall, class: mcp.ClassCredentialExpired, verdict: unreachable,
		why: "no credential is presented and none is minted. The optional run_token is an HMAC " +
			"over the run id (runtoken.go) and carries no validity window at all, so there is " +
			"nothing here whose expiry could have passed — a wrong token is RUN_NOT_FOUND.",
	},
	{
		tool: mcp.ToolObserveToolCall, class: mcp.ClassAudienceMismatch, verdict: unreachable,
		why: "doc 01 §4 gives observe_tool_call four arguments and none is an audience; it presents " +
			"no credential to a relying party, so there is no audience to be mismatched. Asserted " +
			"on the advertised input schema by TestMCP006OnlyGetCredentialTakesAnAudience.",
	},
	{
		tool: mcp.ToolObserveToolCall, class: mcp.ClassLedgerUnavailable, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			// The BODY VOLUME is the second store this tool writes to, and the
			// only one of the two that is not Postgres. IP §4's vocabulary is
			// closed (doc 08 §3), so there is no BODY_STORE_UNAVAILABLE to add
			// and this is the class that carries it: a mount that came back
			// clears it, which is exactly what retryable tells the caller.
			//
			// What the cell pins is the refusal, not the message: a volume
			// this tool cannot write to must stop the call, because a
			// `tool_call` naming a digest whose body never landed is a
			// permanent claim about evidence that never existed (I3).
			//
			// A dead Postgres reaches the same class here as it does for
			// record_event, one gate earlier — the idempotency claim is taken
			// before the run is resolved — and the dead-ledger group below
			// pins that shape. This drive is the half of the class only this
			// tool has.
			run := s.registerRun(t, "observe-volume-gone")
			observeOnBlockedVolume(t, s)
			return s.callExpectingError(t, mcp.ToolObserveToolCall, map[string]any{
				"run_id": run.RunID, "tool": "Edit", "body": observedBody,
			})
		},
	},
	{
		tool: mcp.ToolObserveToolCall, class: mcp.ClassSigningUnavailable, verdict: unreachable,
		why: "observe_tool_call signs nothing: it writes a body to a local volume and appends a " +
			"`tool_call` by reference. There is no Fulcio dependency in its configuration to be " +
			"down; IP §6.3's case belongs to sign_commit.",
	},
	{
		tool: mcp.ToolObserveToolCall, class: mcp.ClassTransparencyUnavailable, verdict: unreachable,
		why: "observe_tool_call never reaches Rekor. It appends to the innsegl chain, and it is the " +
			"SEGMENT that is anchored, asynchronously and not on this path; the stored body is " +
			"evidence held locally and is deliberately published nowhere (doc 05).",
	},
	{
		tool: mcp.ToolObserveToolCall, class: mcp.ClassRunNotFound, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			// The same refusal a bad run_token produces, which is the point of
			// it: a run_id is public, so the two must be indistinguishable.
			return s.callExpectingError(t, mcp.ToolObserveToolCall, map[string]any{
				"run_id": unknownRunID, "tool": "Edit", "body": observedBody,
			})
		},
	},
	{
		tool: mcp.ToolObserveToolCall, class: mcp.ClassRunAlreadyRetired, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			run := s.registerRun(t, "observe-retired")
			s.retireRun(t, run.RunID)
			// I4: a retired run's history stays readable; it stops growing.
			// An observation arriving after the retirement is refused rather
			// than appended late.
			return s.callExpectingError(t, mcp.ToolObserveToolCall, map[string]any{
				"run_id": run.RunID, "tool": "Edit", "body": observedBody,
			})
		},
	},
	{
		tool: mcp.ToolObserveToolCall, class: mcp.ClassDuplicateRequest, verdict: reachable,
		runID: runIDAbsent,
		drive: func(t *testing.T, s *stack) wireError {
			// A REPLAY is not this class and must never be: doc 01 §4 makes the
			// tool idempotent on (run_id, digest), so the same body observed
			// twice returns the stored reply and appends nothing (IP §6.6).
			// That is the same reading record_event's cell takes — its replay
			// returns the original event id too — and in both tools the class
			// is reached the other way: one key presented for a request that is
			// not the one it named.
			//
			// Here the key is DERIVED from (run_id, digest) rather than
			// supplied, so the caller cannot present it against anything by
			// choice. It still happens, and this is how: the same body under
			// the same run, reported as a different tool. The key is
			// necessarily the same and the fingerprint is not, and answering
			// with the first call's reply would attest a tool this caller never
			// named.
			run := s.registerRun(t, "observe-dupe-setup")
			var out struct {
				Digest string `json:"digest"`
				Stored bool   `json:"stored"`
			}
			s.callExpectingSuccess(t, mcp.ToolObserveToolCall, map[string]any{
				"run_id": run.RunID, "tool": "Edit", "body": observedBody,
			}, &out)
			if !out.Stored {
				t.Fatalf("the setup call did not store the body: %+v", out)
			}
			return s.callExpectingError(t, mcp.ToolObserveToolCall, map[string]any{
				"run_id": run.RunID, "tool": "Bash", "body": observedBody,
			})
		},
	},
	{
		tool: mcp.ToolObserveToolCall, class: mcp.ClassInvariantViolation, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			// IP E4 at this tool's own narrowest point. `tool` names the agent
			// tool that was observed and becomes doc 02 §3's `tool_name`, under
			// record_event's grammar; `body` is where a body goes, and it goes
			// to the volume and nowhere else. A body sent where the name
			// belongs is refused before the run is ever looked up — which is
			// why an unknown run id here is not the failure that comes back.
			return s.callExpectingError(t, mcp.ToolObserveToolCall, map[string]any{
				"run_id": unknownRunID, "tool": observedBody, "body": observedBody,
			})
		},
	},

	// -----------------------------------------------------------------------
	// observe_session(session_id, phase, cwd, agent_type?, task?)
	//
	// RM-128 (#207), E11. The eighth and last tool of IP §4's surface, and the
	// only one that is a COMPOSITION: a start resolves the workspace through
	// describe_workspace and mints the run through register_agent; a stop ends
	// it through retire_agent. All three are the shipped tools called in
	// process, so this tool's error surface is very nearly theirs.
	//
	// Two facts decide all eleven, and they pull in opposite directions.
	//
	// THE START PATH INHERITS register_agent's CLASSES, unchanged — this tool
	// rewraps nothing, because IP §4's vocabulary is closed (doc 08 §3) and a
	// second wording for one failure sends a shim author to the wrong file. So
	// four classes that would be absurd for a tool "about sessions" are
	// reachable here for exactly the reasons they are reachable for
	// register_agent, and each cell below drives them the same way.
	//
	// THE STOP PATH PRODUCES NO CLASS AT ALL. IP §4: "a stop never blocks."
	// A refused stop was answered by a harness with nine repeated invocations,
	// and an MCP tool's equivalent of the shim's exit 2 is an error result — so
	// every failure on that path comes back as a SUCCESSFUL reply carrying the
	// class and the message in `detail`. Nothing a stop meets appears on this
	// side of the matrix, which is why the unreachable cells below keep saying
	// "and the stop path cannot raise it either".
	//
	// It is also the tool's own second store. The session-to-run mapping lives
	// on a local volume, so LEDGER_UNAVAILABLE is driven through that volume
	// rather than through Postgres, the same half of the class observe_tool_call
	// has and no other tool on the surface can produce.
	// -----------------------------------------------------------------------
	{
		tool: mcp.ToolObserveSession, class: mcp.ClassAttestationFailed, verdict: unreachable,
		why: "the start path reaches SPIRE only through register_agent, and internal/spire's " +
			"classifyAdmin has no path to ATTESTATION_FAILED — the class is raised by " +
			"classifyWorkload on the Workload API, which no MCP tool calls. The stop path " +
			"reaches SPIRE only to DELETE an entry, and raises nothing at all: every failure " +
			"there is reported in the reply. Same finding as register_agent's own cell.",
	},
	{
		tool: mcp.ToolObserveSession, class: mcp.ClassIdentityUnavailable, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			// IP §6.1's headline case, met through a session start: the run is
			// minted by register_agent, so spire-server being down stops a
			// session getting an identity exactly as it stops an agent getting
			// one. A START MAY REFUSE — IP §6.1 admits no attributed work
			// without an identity, and this is the refusal that enforces it.
			worktree := s.worktree
			s.spire.failRegister = &spire.Error{
				Class: spire.ClassIdentityUnavailable, Op: "register_agent",
				Message: "connection refused", Retryable: true,
			}
			return s.callExpectingError(t, mcp.ToolObserveSession, map[string]any{
				"session_id": "ident-down", "phase": mcp.ObserveSessionPhaseStart, "cwd": worktree,
			})
		},
	},
	{
		tool: mcp.ToolObserveSession, class: mcp.ClassCredentialExpired, verdict: unreachable,
		why: "no credential is presented and none is minted. What a start returns is a " +
			"credential HANDLE — the run's SPIFFE ID, the expiry SPIRE granted its entry, and " +
			"the derived run token — and none of those is checked against a clock here; " +
			"get_credential is where a credential is issued, and this tool never calls it.",
	},
	{
		tool: mcp.ToolObserveSession, class: mcp.ClassAudienceMismatch, verdict: unreachable,
		why: "doc 01 §4 gives observe_session five arguments and none is an audience; it " +
			"presents no credential to a relying party, so there is nothing to be mismatched. " +
			"Asserted on the advertised input schema by TestMCP006OnlyGetCredentialTakesAnAudience.",
	},
	{
		tool: mcp.ToolObserveSession, class: mcp.ClassLedgerUnavailable, verdict: reachable,
		runID: runIDAbsent,
		drive: func(t *testing.T, s *stack) wireError {
			// THE MARKER VOLUME, which is this tool's own second store and the
			// one of the two that is not Postgres. IP §4's vocabulary is closed
			// (doc 08 §3), so there is no MARKER_STORE_UNAVAILABLE to add and
			// this is the class that carries it: a mount that came back clears
			// it, which is what retryable tells the caller.
			//
			// What the cell pins is the REFUSAL. A session whose mapping was
			// never written is a run no stop will ever find — the reference
			// shim measured that as three runs still Active seventeen hours
			// later — so a start that cannot record the mapping refuses rather
			// than handing back an identity nothing can retire.
			//
			// run_id is ABSENT here and not empty: the volume is checked before
			// anything is registered, so there is no run to scope the failure
			// to and doc 02 §1 distinguishes the two states. Registered-and-
			// unmapped is the other half of the same class, and it carries a
			// run id; it is driven in internal/mcp, where the partial file name
			// it needs is reachable.
			//
			// A dead Postgres reaches the same class one gate later, inside
			// register_agent, and the dead-ledger group pins that shape there.
			sessionOnBlockedMarkers(t)
			worktree := s.worktree
			return s.callExpectingError(t, mcp.ToolObserveSession, map[string]any{
				"session_id": "markers-gone", "phase": mcp.ObserveSessionPhaseStart, "cwd": worktree,
			})
		},
	},
	{
		tool: mcp.ToolObserveSession, class: mcp.ClassSigningUnavailable, verdict: unreachable,
		why: "observe_session signs nothing and has no Fulcio in any of the three configurations " +
			"it composes. It begins and ends the session a commit is later signed under; the " +
			"signing is sign_commit's, and so is IP §6.3's case.",
	},
	{
		tool: mcp.ToolObserveSession, class: mcp.ClassTransparencyUnavailable, verdict: unreachable,
		why: "no Rekor dependency on either path. The events a session causes — run_registered " +
			"and run_retired — go into the innsegl chain, and it is the SEGMENT that is " +
			"anchored, asynchronously and not while a harness is waiting for its identity.",
	},
	{
		tool: mcp.ToolObserveSession, class: mcp.ClassRunNotFound, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			// NOT the missing session. A stop for a session that never started
			// is required to SUCCEED with the terminal state (IP §4), because a
			// shim cannot guarantee ordering and a refusal would be answered
			// with a retry storm — so that, the obvious reading of this class
			// for this tool, is a BUG here rather than a case.
			//
			// The class survives anyway, from register_agent: classifyAdmin
			// maps codes.NotFound to RUN_NOT_FOUND, and a registration whose
			// attested PARENT node is gone is exactly that. SPIRE has nothing
			// to hang the session's entry off.
			worktree := s.worktree
			s.spire.failRegister = &spire.Error{
				Class: spire.ClassRunNotFound, Op: "register_agent",
				Message: "no such parent entry " + testParentID, Retryable: false,
			}
			return s.callExpectingError(t, mcp.ToolObserveSession, map[string]any{
				"session_id": "no-parent", "phase": mcp.ObserveSessionPhaseStart, "cwd": worktree,
			})
		},
	},
	{
		tool: mcp.ToolObserveSession, class: mcp.ClassRunAlreadyRetired, verdict: reachable,
		runID: runIDPresent,
		drive: func(t *testing.T, s *stack) wireError {
			// Neither of the two paths this tool owns can produce it. A stop
			// for a retired session answers with the original instant, and a
			// START for one answers with the terminal state rather than
			// re-registering — which is not politeness: a run id is a pure
			// function of (agent_type, task, key), so re-deriving would name
			// the SAME retired run and hand back an identity that can no
			// longer sign (#213's collision, from this tool's side).
			//
			// It survives from register_agent's fail-closed branch: SPIRE
			// reports an existing entry and then holds none, which only
			// retirement and the reaper cause, so it refuses rather than
			// resurrecting an identity somebody chose to destroy.
			worktree := s.worktree
			s.spire.duplicateOnRegister = true
			s.spire.vanishOnLookup = true
			return s.callExpectingError(t, mcp.ToolObserveSession, map[string]any{
				"session_id": "vanished", "phase": mcp.ObserveSessionPhaseStart, "cwd": worktree,
			})
		},
	},
	{
		tool: mcp.ToolObserveSession, class: mcp.ClassDuplicateRequest, verdict: reachable,
		runID: runIDAbsent,
		drive: func(t *testing.T, s *stack) wireError {
			// A DUPLICATE START IS NOT THIS CLASS and must never be: IP §6.6
			// requires the same run back, never a second identity, and the
			// derived key is what delivers it. The caller cannot present that
			// key against another request by choice either — it is derived from
			// the session id, exactly so that one session cannot be recorded
			// twice under two keys.
			//
			// It still happens, and this is the way: the mapping is lost while
			// the ledger keeps the registration — a container recreated without
			// its marker volume — and the session then starts again describing
			// itself differently. The key is necessarily the same and the
			// fingerprint is not, and answering with the first call's reply
			// would hand this caller a run registered as something it did not
			// ask for.
			//
			// run_id is absent because the idempotency store refuses before any
			// run is resolved (ADR-0017 §3).
			markers, worktree := s.markerDir, s.worktree
			var first struct {
				RunID string `json:"run_id"`
			}
			s.callExpectingSuccess(t, mcp.ToolObserveSession, map[string]any{
				"session_id": "lost-mapping", "phase": mcp.ObserveSessionPhaseStart, "cwd": worktree,
			}, &first)
			if first.RunID == "" {
				t.Fatalf("the setup start registered no run: %+v", first)
			}
			if err := os.RemoveAll(markers); err != nil {
				t.Fatalf("losing the marker volume: %v", err)
			}
			return s.callExpectingError(t, mcp.ToolObserveSession, map[string]any{
				"session_id": "lost-mapping", "phase": mcp.ObserveSessionPhaseStart,
				"cwd": worktree, "agent_type": "reviewer",
			})
		},
	},
	{
		tool: mcp.ToolObserveSession, class: mcp.ClassInvariantViolation, verdict: reachable,
		runID: runIDAbsent,
		drive: func(t *testing.T, s *stack) wireError {
			// The one argument the tool switches on. A phase that is neither
			// `start` nor `stop` is not a session event this tool can act on,
			// and guessing which was meant would either register a run nobody
			// asked for or retire one that is still working.
			//
			// It does not touch the never-block rule: a malformed phase is not
			// a stop, whatever it was meant to be, so there is nothing to
			// retire and no terminal state to report. run_id is ABSENT, because
			// the refusal happens before any run exists.
			worktree := s.worktree
			return s.callExpectingError(t, mcp.ToolObserveSession, map[string]any{
				"session_id": "bad-phase", "phase": "restart", "cwd": worktree,
			})
		},
	},
}

// ---------------------------------------------------------------------------
// The three ingestion tools' fixtures (RM-126/127/128, #205/#206/#207).
//
// The WORKING configuration of all three now lives in the stack (harness_test.go,
// stackIngestion), because #211 wired them into `innsegl serve` and a contract
// stack that did not wire them could no longer claim to be the shipped path.
// What is left here is the opposite: two volumes that genuinely do not work,
// installed by the one cell each that is about a volume failing.
//
// The distinction matters and is the whole of #211's third part. A HOSTILE
// configuration is a fixture a cell needs; a MISSING one is a tool nobody
// wired, and a cell that met the second while believing it had the first would
// pass on an INVARIANT_VIOLATION from the config gate and prove nothing about
// the tool. Three helpers here used to be the only way any of these tools
// could be reached at all; TestMCP060 now refuses any bound tool that answers
// its own unwired gate, so a cell cannot quietly return to that state.
// ---------------------------------------------------------------------------

// observedBody is a tool-call body of the kind a harness forwards: a file
// write, carrying the file's own contents. doc 05 keeps these on the operator's
// machine, which is why the cells above also send it where a tool NAME belongs
// — a body has exactly one destination and the ledger is not it.
const observedBody = `{"tool_name":"Edit","tool_input":` +
	`{"file_path":"/w/a.go","new_string":"apiKey := \"redacted\""}}`

// observeOnBlockedVolume configures observe_tool_call against a volume that
// genuinely cannot be written to: the run directory's parent is a regular
// file, so MkdirAll fails whatever uid the tests run as. Nothing here is
// stubbed — the same reason the dead-ledger cells kill a real Postgres.
func observeOnBlockedVolume(t *testing.T, s *stack) {
	t.Helper()
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("the volume is not mounted"), 0o600); err != nil {
		t.Fatalf("preparing the blocked volume: %v", err)
	}
	observeConfigured(t, s, filepath.Join(blocked, "bodies"))
}

// observeConfigured installs one body volume over the stack's own, for the
// life of the cell that asked for it.
func observeConfigured(t *testing.T, s *stack, bodyDir string) {
	t.Helper()
	restore, err := mcp.ConfigureObserveToolCall(mcp.ObserveToolCallConfig{
		Runs: ledgerRuns{store: s.store}, Ledger: s.store, Idempotency: s.idem,
		BodyDir: bodyDir,
	})
	if err != nil {
		t.Fatalf("ConfigureObserveToolCall: %v", err)
	}
	t.Cleanup(restore)
}

// sessionOnBlockedMarkers configures observe_session against a volume that
// genuinely cannot be used: the marker directory's parent is a regular file,
// so MkdirAll fails whatever uid the tests run as.
//
// observe_session is a COMPOSITION — it resolves the workspace through
// describe_workspace, mints the run through register_agent and ends it through
// retire_agent, all in process, through the package state ADR-0016 §5 fixes as
// the seam. So the stack's own configurations are the ones it runs on, and the
// marker volume is the only thing a fixture here has to say anything about.
func sessionOnBlockedMarkers(t *testing.T) {
	t.Helper()
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("the volume is not mounted"), 0o600); err != nil {
		t.Fatalf("preparing the blocked marker volume: %v", err)
	}
	observeSessionConfigured(t, filepath.Join(blocked, "sessions"))
}

// observeSessionConfigured installs one marker volume over the stack's own,
// for the life of the cell that asked for it.
func observeSessionConfigured(t *testing.T, markerDir string) {
	t.Helper()
	restore, err := mcp.ConfigureObserveSession(mcp.ObserveSessionConfig{MarkerDir: markerDir})
	if err != nil {
		t.Fatalf("ConfigureObserveSession: %v", err)
	}
	t.Cleanup(restore)
}

// deadLedgerRunID is the run registered on the dead-ledger stack while
// Postgres was still up, so that the reads that fail afterwards are reads for
// a run that genuinely exists.
var deadLedgerRunID string

// ---------------------------------------------------------------------------
// MCP-006.
// ---------------------------------------------------------------------------

// shippedTools is the tool names that actually have a registered binder, which
// is what makes a deferred cell honest or dishonest (RM-131, #210). It is read
// from a real server rather than written down, so a tool that stopped
// registering itself shows up here as unbound instead of being assumed present.
func shippedTools(t *testing.T) []mcp.ToolName {
	t.Helper()
	srv, err := mcp.New(mcp.Config{Version: "v0.0.0-contract"})
	if err != nil {
		t.Fatalf("mcp.New: %v", err)
	}
	return srv.BoundTools()
}

// TestMCP006TheMatrixIsExactlyToolsTimesClasses keeps the matrix honest before
// anything is run against it: 8 × 11, every pair once, no pair missing, and
// every non-reachable cell carrying the reason it is not.
func TestMCP006TheMatrixIsExactlyToolsTimesClasses(t *testing.T) {
	tools, classes := mcp.ToolNames(), mcp.Classes()
	if want := len(tools) * len(classes); len(matrix) != want {
		t.Fatalf("matrix has %d cells, IP §4 has %d tools × %d classes = %d",
			len(matrix), len(tools), len(classes), want)
	}
	// EVERY NAME ON THE SURFACE HAS A BINDER, which is what makes the eighty-
	// eight verdicts below verdicts about code that runs.
	//
	// This is the positive form of a check RM-131 (#210) needed the negative
	// of: while three names had no implementation, the `deferred` verdict
	// described them and this loop refused it on any tool that DID bind. #207
	// bound the eighth, so the state that verdict described cannot exist, and
	// the honest assertion is the direct one. A ninth name advertised ahead of
	// its implementation fails here.
	bound := map[mcp.ToolName]bool{}
	for _, n := range shippedTools(t) {
		bound[n] = true
	}
	for _, tool := range tools {
		if !bound[tool] {
			t.Errorf("%s is on IP §4's surface and registers no binder; every cell below it "+
				"would be a verdict about code that does not run", tool)
		}
	}
	seen := map[string]bool{}
	for _, c := range matrix {
		key := string(c.tool) + "/" + string(c.class)
		if seen[key] {
			t.Errorf("%s appears twice in the matrix", key)
		}
		seen[key] = true
		if !c.tool.Valid() {
			t.Errorf("%q is not one of the eight IP §4 tool names", c.tool)
		}
		if !c.class.Valid() {
			t.Errorf("%q is not one of the eleven IP §4 error classes", c.class)
		}
		switch c.verdict {
		case reachable:
			if c.drive == nil {
				t.Errorf("%s is marked reachable with no input that reaches it", key)
			}
			if c.why != "" {
				t.Errorf("%s is marked reachable and also carries a why", key)
			}
		case unreachable:
			if c.drive != nil {
				t.Errorf("%s is marked unreachable and carries an input", key)
			}
			if len(c.why) < 40 {
				t.Errorf("%s is marked unreachable with no explanation; the finding IS the value", key)
			}
		}
	}
	for _, tool := range tools {
		for _, class := range classes {
			if !seen[string(tool)+"/"+string(class)] {
				t.Errorf("the matrix has no cell for %s × %s", tool, class)
			}
		}
	}
	if len(ip4Retryable) != len(classes) {
		t.Fatalf("the retryability table has %d rows, IP §4 has %d classes", len(ip4Retryable), len(classes))
	}
	for _, class := range classes {
		if _, ok := ip4Retryable[class]; !ok {
			t.Errorf("the retryability table has no row for %s", class)
		}
	}
}

// TestMCP006EveryReachableClassIsReachedThroughTheShippedTool is the matrix.
//
// Each cell drives the REAL tool over the REAL transport against a REAL
// Postgres and asserts the IP §4 error that comes back: the class, the
// retryable flag from the hand-written table above, run_id's presence under
// doc 02 §1's absent-versus-empty rule, and that no fifth field appeared.
func TestMCP006EveryReachableClassIsReachedThroughTheShippedTool(t *testing.T) {
	requirePG(t)

	assert := func(t *testing.T, c cell, got wireError) {
		t.Helper()
		rule := ip4Retryable[c.class]
		if got.Class != string(c.class) {
			t.Fatalf("error_class = %q, want %q — the matrix says this input reaches %s (%s)",
				got.Class, c.class, c.class, got.Message)
		}
		if got.Retryable != rule.retryable {
			t.Errorf("retryable = %v, want %v — %s", got.Retryable, rule.retryable, rule.source)
		}
		switch c.runID {
		case runIDAbsent:
			if got.RunIDSeen {
				t.Errorf("run_id present as %q; doc 02 §1 distinguishes absent from empty and this "+
					"failure is not scoped to a run", got.RunID)
			}
		case runIDPresent:
			if !got.RunIDSeen {
				t.Errorf("run_id absent; this failure names a run and IP §4 carries it")
			} else if got.RunID == "" {
				t.Errorf("run_id present and empty; doc 02 §1 allows absent, never empty")
			}
		}
		if got.Message == "" {
			t.Errorf("message is empty; an operator receives a class and nothing else")
		}
		if len(got.Extra) > 0 {
			t.Errorf("wire error carries %v; IP §4 names four fields and no more", got.Extra)
		}
	}

	for _, c := range matrix {
		if c.verdict != reachable || c.deadLedger {
			continue
		}
		t.Run(fmt.Sprintf("%s/%s", c.tool, c.class), func(t *testing.T) {
			assert(t, c, c.drive(t, newStack(t)))
		})
	}

	// IP §6.4's Postgres outage: one container, brought up, proven working,
	// then SIGKILLed. Every dead-ledger cell runs against that one corpse,
	// because a stack cannot be built once the database it opens is gone.
	t.Run("LEDGER_UNAVAILABLE/real-postgres-outage", func(t *testing.T) {
		s, victim := newDeadLedgerStack(t)
		t.Logf("killed %s; every call below meets a Postgres that is no longer there", victim.id[:12])
		for _, c := range matrix {
			if c.verdict != reachable || !c.deadLedger {
				continue
			}
			t.Run(string(c.tool), func(t *testing.T) {
				assert(t, c, c.drive(t, s))
			})
		}
	})
}

// newDeadLedgerStack builds a working stack on a dedicated Postgres, proves it
// works, and then kills the database out from under it.
//
// The tool calls that follow meet a process that went away, not a pool that
// was closed politely — IP §6.4's "Postgres down", not a tidy shutdown.
func newDeadLedgerStack(t *testing.T) (*stack, *pgContainer) {
	t.Helper()
	requirePG(t)

	ctx := testCtx(t, 3*time.Minute)
	victim, err := startPG(ctx)
	if err != nil {
		t.Fatalf("starting a Postgres to kill: %v", err)
	}
	t.Cleanup(func() {
		if rerr := victim.remove(); rerr != nil {
			t.Logf("warning: removing the killed container: %v", rerr)
		}
	})

	s := newStackOn(t, victim.dsn(postgresDB))

	// While it is up: a real registration, so the reads that fail afterwards
	// are reads for a run that genuinely exists and the outage is the only
	// thing that changed.
	run := s.registerRun(t, "before-the-outage")
	deadLedgerRunID = run.RunID

	if err := victim.kill(ctx); err != nil {
		t.Fatalf("killing Postgres: %v", err)
	}
	settleOutage(t, s)
	return s, victim
}

// settleOutage drains the connections the two pools were holding when the
// postmaster died, so that what the matrix asserts afterwards is a SETTLED
// outage and not a race with a stale socket.
//
// FORMER FINDING (RM-028, #36; fixed by RM-067, #87): the two states used to
// classify differently. Once no stale connection was left, every new dial was
// refused and both internal/ledger's classify and internal/mcp's
// classifyStorage reported LEDGER_UNAVAILABLE **retryable**, which is the
// value ADR-0016 requires of a dependency outage. On the FIRST call after the
// kill the server could still deliver `SQLSTATE 57P01: terminating connection
// due to unexpected postmaster exit`, and classifyStorage sent every SQLSTATE
// that was not a constraint violation to LEDGER_UNAVAILABLE with
// retryable=**false** — "the database answered, but not usefully" — while
// internal/ledger, over the same database, got the same condition right. One
// outage, two layers, opposite advice to the caller: precisely "a false on a
// dependency outage turns a thirty-second Postgres restart into a failed run"
// (ADR-0016). RM-067 made classifyStorage apply the same SQLSTATE-class rule
// internal/ledger.classify does, so this is no longer a *transitional*
// disagreement tolerated on the way to a settled state — every iteration
// below, settled or not, is now asserted to agree, and this function fails
// loudly the moment one does not.
//
// The drain loop itself stays: reaching the state where every new dial is
// refused is still useful groundwork for the matrix that runs after this, and
// costs nothing now that it is also a live regression check rather than a
// tolerated log line.
func settleOutage(t *testing.T, s *stack) {
	t.Helper()
	ctx := testCtx(t, time.Minute)

	// Bounded by the pools' size, not by a clock: a pool holds a finite number
	// of connections and each one surfaces its death exactly once.
	const drain = 64
	assertAgrees := func(layer string, err error) {
		t.Helper()
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) {
			return
		}
		ce := mcp.Classify(err)
		t.Logf("%s answered the outage with SQLSTATE %s (%s) — %s retryable=%v",
			layer, pgErr.Code, pgErr.Message, ce.Class, ce.Retryable)
		if ce.Class != mcp.ClassLedgerUnavailable || !ce.Retryable {
			t.Fatalf("RM-067 (#87): %s reported SQLSTATE %s as %s retryable=%v; a Postgres "+
				"outage must classify LEDGER_UNAVAILABLE retryable=true on every call, settled "+
				"or not (ADR-0016)", layer, pgErr.Code, ce.Class, ce.Retryable)
		}
	}
	for i := 0; i < drain; i++ {
		_, err := s.store.Head(ctx)
		if err == nil {
			t.Fatalf("the ledger still answers after the container was killed")
		}
		assertAgrees("internal/ledger", err)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) {
			break
		}
	}
	for i := 0; i < drain; i++ {
		_, _, err := s.idem.Lookup(ctx, "settle-the-outage")
		if err == nil {
			t.Fatalf("the idempotency store still answers after the container was killed")
		}
		assertAgrees("internal/mcp idempotency store", err)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) {
			break
		}
	}
}

// TestMCP006AnInputTheSchemaRefusesNeverReachesTheTool.
//
// FINDING: IP §4 says "All tools return structured errors", but arguments the
// advertised input schema refuses are rejected by the TRANSPORT before any
// tool runs, and that refusal carries no `error_class` — it is an MCP protocol
// error with text content and no structured content. That is correct
// behaviour for the SDK and it is not one of the eleven classes; it is
// recorded here so the matrix's silence about it is deliberate. A caller
// switching on `error_class` must handle a tool error that has none.
func TestMCP006AnInputTheSchemaRefusesNeverReachesTheTool(t *testing.T) {
	requirePG(t)
	s := newStack(t)

	for _, tool := range []mcp.ToolName{
		mcp.ToolRegisterAgent, mcp.ToolGetCredential, mcp.ToolRecordEvent, mcp.ToolSignCommit, mcp.ToolRetireAgent,
	} {
		t.Run(string(tool), func(t *testing.T) {
			res := s.call(t, tool, map[string]any{})
			if !res.IsError {
				t.Fatalf("%s with no arguments succeeded", tool)
			}
			if res.StructuredContent != nil {
				// If this ever starts carrying the IP §4 object, the matrix
				// gains a row and the battery stops skipping these inputs.
				got := decodeWireError(t, tool, res)
				t.Fatalf("%s with no arguments now returns the IP §4 object %+v; "+
					"the matrix has to account for it", tool, got)
			}
			if len(res.Content) == 0 {
				t.Errorf("%s: a refusal with neither structured content nor text is illegible", tool)
			}
		})
	}
}

// TestMCP006NoToolProducesAClassTheMatrixCallsUnreachable is the other half of
// exhaustiveness.
//
// The matrix proves each reachable cell reachable. This proves the unreachable
// ones unreachable in the only way a test can: a battery of malformed, hostile
// and boundary inputs against every tool, asserting that whatever class comes
// back is one the matrix already accounts for. A tool that grew a new class —
// or a class that quietly moved between tools — fails here rather than being
// discovered in production.
func TestMCP006NoToolProducesAClassTheMatrixCallsUnreachable(t *testing.T) {
	requirePG(t)
	s := newStack(t)
	live := s.registerRun(t, "battery-live")
	retired := s.registerRun(t, "battery-retired")
	s.retireRun(t, retired.RunID)

	long := strings.Repeat("x", 4096)

	// THE THREE INGESTION TOOLS ARE CONFIGURED BY THE STACK, and this test no
	// longer installs anything (#211).
	//
	// It did, and had to, for as long as `cmd/innsegl/servewiring.go` wired
	// five of the eight: three helpers installed a configuration here so the
	// rows below would meet a working tool, and each carried a doc comment
	// saying, in as many words, that a battery which forgot to call it would
	// pass vacuously. That is a note about a landmine, not a guard against one.
	// The wiring now installs all three in the entry point and the stack does
	// the same, so there is nothing left here to forget — and TestMCP060 fails
	// if a bound tool is ever unconfigured again.
	dwProjects, dwWorktree := s.projects, s.worktree

	battery := map[mcp.ToolName][]map[string]any{
		mcp.ToolRegisterAgent: {
			{},
			{"agent_type": "", "task_id": "", "idempotency_key": ""},
			{"agent_type": testAgentType, "task_id": testTaskID, "idempotency_key": ""},
			{"agent_type": long, "task_id": testTaskID, "idempotency_key": "long-type"},
			{"agent_type": testAgentType, "task_id": long, "idempotency_key": "long-task"},
			{"agent_type": testAgentType, "task_id": testTaskID, "idempotency_key": long},
			{"agent_type": "../../etc", "task_id": testTaskID, "idempotency_key": "traversal"},
			{"agent_type": testAgentType, "task_id": "JIRA-118", "idempotency_key": "battery-live"},
		},
		mcp.ToolGetCredential: {
			{},
			{"run_id": "", "audience": ""},
			{"run_id": live.RunID, "audience": ""},
			{"run_id": live.RunID, "audience": "SIGSTORE"},
			{"run_id": live.RunID, "audience": " sigstore"},
			{"run_id": long, "audience": mcp.AudienceSigstore},
			{"run_id": "spiffe://innsegl.dev/agent/a/b/c", "audience": mcp.AudienceSigstore},
			{"run_id": unknownRunID, "audience": mcp.AudienceSigstore},
			{"run_id": retired.RunID, "audience": mcp.AudienceSigstore},
		},
		mcp.ToolRecordEvent: {
			{},
			{"run_id": "", "event_type": "", "payload_digest": "", "idempotency_key": ""},
			{"run_id": live.RunID, "event_type": "", "payload_digest": "", "idempotency_key": "k1"},
			{"run_id": live.RunID, "event_type": "bash", "payload_digest": "not-a-digest", "idempotency_key": "k2"},
			{"run_id": live.RunID, "event_type": long, "payload_digest": "", "idempotency_key": "k3"},
			{"run_id": live.RunID, "event_type": "{\"body\":\"smuggled\"}", "payload_digest": "", "idempotency_key": "k4"},
			{"run_id": live.RunID, "event_type": event.EventTypeToolCall, "payload_digest": "", "idempotency_key": "k5"},
			{"run_id": unknownRunID, "event_type": "bash", "payload_digest": digestA, "idempotency_key": "k6"},
			{"run_id": retired.RunID, "event_type": "bash", "payload_digest": digestA, "idempotency_key": "k7"},
			{"run_id": live.RunID, "event_type": "bash", "payload_digest": digestA, "idempotency_key": long},
		},
		mcp.ToolSignCommit: {
			{},
			{"run_id": "", "repo": "", "staged_ref": "", "message": "", "task_ref": "", "idempotency_key": ""},
			{"run_id": live.RunID, "repo": "not-a-repo", "staged_ref": scPlaceholderStagedRef,
				"message": "m", "task_ref": testTaskID, "idempotency_key": "sc-battery-1"},
			{"run_id": live.RunID, "repo": scPlaceholderRepo, "staged_ref": "--evil",
				"message": "m", "task_ref": testTaskID, "idempotency_key": "sc-battery-2"},
			{"run_id": live.RunID, "repo": scPlaceholderRepo, "staged_ref": scPlaceholderStagedRef,
				"message": long, "task_ref": testTaskID, "idempotency_key": "sc-battery-3"},
			{"run_id": live.RunID, "repo": scPlaceholderRepo, "staged_ref": scPlaceholderStagedRef,
				"message": "m", "task_ref": long, "idempotency_key": "sc-battery-4"},
			{"run_id": live.RunID, "repo": scPlaceholderRepo, "staged_ref": scPlaceholderStagedRef,
				"message": "m", "task_ref": "", "idempotency_key": "sc-battery-5"},
			{"run_id": unknownRunID, "repo": scPlaceholderRepo, "staged_ref": scPlaceholderStagedRef,
				"message": "m", "task_ref": testTaskID, "idempotency_key": "sc-battery-6"},
			{"run_id": retired.RunID, "repo": scPlaceholderRepo, "staged_ref": scPlaceholderStagedRef,
				"message": "m", "task_ref": testTaskID, "idempotency_key": "sc-battery-7"},
			{"run_id": live.RunID, "repo": "../../etc", "staged_ref": scPlaceholderStagedRef,
				"message": "m", "task_ref": testTaskID, "idempotency_key": "sc-battery-8"},
			{"run_id": "Run 42", "repo": scPlaceholderRepo, "staged_ref": scPlaceholderStagedRef,
				"message": "m", "task_ref": testTaskID, "idempotency_key": "sc-battery-9"},
		},
		mcp.ToolRetireAgent: {
			{},
			{"run_id": ""},
			{"run_id": long},
			{"run_id": unknownRunID},
			{"run_id": "Run-42"},
			{"run_id": "../../etc/passwd"},
		},
		// Every way a path can be wrong, plus one that is right. The last row
		// is the one that keeps the rest honest: it SUCCEEDS, which is how
		// this entry shows the tool was reachable and configured and that the
		// refusals above are refusals of the input rather than of the fixture.
		mcp.ToolDescribeWorkspace: {
			{},
			{"cwd": ""},
			{"cwd": "relative/path"},
			{"cwd": long},
			{"cwd": "/etc"},
			{"cwd": "../../etc/passwd"},
			{"cwd": filepath.Join(dwProjects, "..", "outside-the-mount")},
			{"cwd": filepath.Join(dwProjects, "no-such-directory")},
			{"cwd": dwProjects},
			{"cwd": dwWorktree},
		},
		// Every way a session call can be wrong, and three that are right. The
		// last three keep the rest honest: a stop for a session nobody started
		// SUCCEEDS with the terminal state, and a start followed by its own
		// stop succeeds twice — so this entry shows the tool was reachable and
		// configured, and that the refusals above are refusals of the input.
		mcp.ToolObserveSession: {
			{},
			{"session_id": "", "phase": "", "cwd": ""},
			{"session_id": "battery-session", "phase": "", "cwd": dwWorktree},
			{"session_id": "battery-session", "phase": "restart", "cwd": dwWorktree},
			{"session_id": long, "phase": mcp.ObserveSessionPhaseStart, "cwd": dwWorktree},
			{"session_id": "../../etc/passwd", "phase": mcp.ObserveSessionPhaseStart, "cwd": dwWorktree},
			{"session_id": "battery-no-cwd", "phase": mcp.ObserveSessionPhaseStart},
			{"session_id": "battery-outside", "phase": mcp.ObserveSessionPhaseStart, "cwd": "/etc"},
			{"session_id": "battery-relative", "phase": mcp.ObserveSessionPhaseStart, "cwd": "relative/path"},
			{"session_id": "battery-bad-type", "phase": mcp.ObserveSessionPhaseStart,
				"cwd": dwWorktree, "agent_type": "Not An Identifier!"},
			{"session_id": "battery-bad-task", "phase": mcp.ObserveSessionPhaseStart,
				"cwd": dwWorktree, "task": long},
			{"session_id": "battery-never-started", "phase": mcp.ObserveSessionPhaseStop},
			{"session_id": "battery-live", "phase": mcp.ObserveSessionPhaseStart, "cwd": dwWorktree},
			{"session_id": "battery-live", "phase": mcp.ObserveSessionPhaseStop},
		},
		mcp.ToolObserveToolCall: {
			{},
			{"run_id": "", "tool": "", "body": ""},
			{"run_id": live.RunID, "tool": "", "body": "{}"},
			{"run_id": live.RunID, "tool": "Edit", "body": ""},
			{"run_id": live.RunID, "tool": long, "body": "{}"},
			{"run_id": live.RunID, "tool": "Edit", "body": long},
			{"run_id": "../../etc", "tool": "Edit", "body": "{}"},
			{"run_id": "run-no-such-run-0000000000000000", "tool": "Edit", "body": "{}"},
			{"run_id": retired.RunID, "tool": "Edit", "body": "{}"},
			{"run_id": live.RunID, "tool": "Edit", "body": "{\"file\":\"a\"}"},
		},
	}

	// MUTATION GUARD, ONE FOR EVERY TOOL RATHER THAN ONE FOR SIGN_COMMIT.
	//
	// A tool whose rows are ALL refused by the transport's own schema
	// validation (see TestMCP006AnInputTheSchemaRefusesNeverReachesTheTool)
	// never reaches the tool's own code at all, and the closure claim below
	// would hold for it for no reason — the vacuous-pass shape this whole file
	// is written against. It was written for sign_commit, whose long argument
	// list makes it the easiest to strand behind the schema; #211 generalised
	// it, because the same hole is one careless row away for any of the eight
	// and a guard that names one tool only guards one tool.
	reached := map[mcp.ToolName]bool{}

	// observe_session keeps a guard of its own, and it is the sharper kind:
	// three of its rows must SUCCEED — a stop for a session nobody started, and
	// a start with its own stop. A tool that only ever refuses can be a tool
	// refusing its inputs or a tool refusing to run at all, and only a success
	// tells the two apart.
	sawObserveSessionSuccess := false

	// NO TOOL IS SKIPPED. RM-131 (#210) put three names on the surface ahead of
	// their implementations and this loop skipped what did not ship, because a
	// tool with no binder cannot be driven at all — the transport answers
	// `unknown tool`, which s.call turns into a transport failure rather than
	// an IP §4 class. #205, #206 and #207 bound all three, so the skip is gone
	// and every one of the eight is driven. That the skip existed at all is
	// recorded here rather than in a deleted line: it is the shape a future
	// addition would need again, and the count assertion above is what refuses
	// it in the meantime.
	for _, tool := range mcp.ToolNames() {
		inputs, ok := battery[tool]
		if !ok {
			t.Fatalf("the battery has no entry for %s; every SHIPPED tool must be "+
				"driven by this closure test", tool)
		}
		allowed := reachableClasses(tool)
		for i, args := range inputs {
			t.Run(fmt.Sprintf("%s/%d", tool, i), func(t *testing.T) {
				res := s.call(t, tool, args)
				if !res.IsError {
					// A success is not a class; the matrix is about failures.
					reached[tool] = true
					if tool == mcp.ToolObserveSession {
						sawObserveSessionSuccess = true
					}
					return
				}
				if res.StructuredContent == nil {
					// The transport's own schema validation refused the
					// arguments before the tool ran, so there is no IP §4
					// class to check. See
					// TestMCP006AnInputTheSchemaRefusesNeverReachesTheTool.
					return
				}
				got := decodeWireError(t, tool, res)
				// MCP-060. A tool answering its own "advertised and never
				// wired" gate answers it to EVERY input, and the matrix calls
				// INVARIANT_VIOLATION reachable for every tool — so a row
				// meeting one would pass while proving nothing at all. That
				// was the literal state of three of these tools until #211,
				// and it is the reason this check is here rather than in the
				// commit message.
				if unconfiguredRefusal(got.Message) {
					t.Fatalf("%s is not configured on this stack, so this row measured the "+
						"fixture and not the tool: %s", tool, got.Message)
				}
				reached[tool] = true
				if !slices.Contains(allowed, mcp.Class(got.Class)) {
					t.Fatalf("%s(%v) produced %s, which the matrix calls unreachable for this tool.\n"+
						"Either the matrix is wrong or the tool grew a class: %s",
						tool, args, got.Class, got.Message)
				}
				assertNotWidened(t, got)
			})
		}
	}

	for _, tool := range mcp.ToolNames() {
		if !reached[tool] {
			t.Errorf("every %s row in the battery was refused by the transport's own schema "+
				"validation; none of them reached the tool's own code, so this test's closure "+
				"claim for %s was never actually exercised", tool, tool)
		}
	}
	if !sawObserveSessionSuccess {
		t.Fatal("every observe_session row in the battery was refused, including the stop for a " +
			"session nobody started and the start/stop pair that must both succeed. That is what " +
			"an UNCONFIGURED tool looks like — one INVARIANT_VIOLATION to every input — so this " +
			"test's closure claim for observe_session held for the fixture, not for the tool")
	}
}

// assertNotWidened is ADR-0016 §2 applied to an outcome nobody reasoned about
// cell by cell: a layer closer to the failure may NARROW `retryable`, never
// widen it. So a class whose IP §4 default is false must never arrive true,
// and a class whose default is true may legitimately arrive false — which is
// what get_credential does for an unrecognised gRPC code ("unrecognised is not
// the same as transient: do not spin").
func assertNotWidened(t *testing.T, got wireError) {
	t.Helper()
	rule, known := ip4Retryable[mcp.Class(got.Class)]
	if !known {
		t.Fatalf("error_class %q is outside IP §4's closed vocabulary", got.Class)
	}
	if got.Retryable && !rule.retryable {
		t.Errorf("retryable = true for %s, which IP §4 makes non-retryable — no layer may widen "+
			"the class default (ADR-0016 §2): %s\n%s", got.Class, rule.source, got.Message)
	}
}

// reachableClasses returns the classes the matrix says this tool can produce.
func reachableClasses(tool mcp.ToolName) []mcp.Class {
	var out []mcp.Class
	for _, c := range matrix {
		if c.tool == tool && c.verdict == reachable {
			out = append(out, c.class)
		}
	}
	return out
}

// TestMCP006TheMintPathNeverProducesAttestationFailed sweeps every gRPC status
// code through the SHIPPED minter — mcp.NewSPIREMinter over a faked connection
// — and asserts what get_credential does with each.
//
// This is the assertion behind the ATTESTATION_FAILED row of the matrix. The
// class exists for a workload that failed to attest (IP §6.1), and attestation
// happens at the Workload API, which no MCP tool calls. Nothing here is a
// mocked classifier: mcp's own credentialMintCodes decides every answer below.
func TestMCP006TheMintPathNeverProducesAttestationFailed(t *testing.T) {
	requirePG(t)
	s := newStack(t)
	run := s.registerRun(t, "mint-sweep")

	allowed := reachableClasses(mcp.ToolGetCredential)
	// codes.OK is not a failure; the sweep starts at Canceled and runs past
	// the last code the gRPC package defines, so an unrecognised code is
	// covered too.
	for code := codes.Code(1); code <= codes.Code(20); code++ {
		t.Run(code.String(), func(t *testing.T) {
			s.conn.failWith(code, "sweep")
			got := s.callExpectingError(t, mcp.ToolGetCredential, map[string]any{
				"run_id": run.RunID, "audience": mcp.AudienceSigstore,
			})
			if got.Class == string(mcp.ClassAttestationFailed) {
				t.Fatalf("MintJWTSVID answering %s reached the caller as ATTESTATION_FAILED. "+
					"The matrix says no MCP tool can produce that class; either the mapping changed "+
					"or the matrix is now wrong.", code)
			}
			if !slices.Contains(allowed, mcp.Class(got.Class)) {
				t.Fatalf("MintJWTSVID answering %s produced %s, which the matrix calls unreachable "+
					"for get_credential: %s", code, got.Class, got.Message)
			}
			assertNotWidened(t, got)
		})
	}
}

// TestMCP006RetireAgentIsIdempotentAndNeverReportsRunAlreadyRetired is the
// negative assertion behind the one cell IP §4 explicitly carves out.
//
// IP §4: "Idempotent: retiring a retired run returns success with the original
// timestamp." doc 07 MCP-009 restates it. So retire_agent is the one tool for
// which RUN_ALREADY_RETIRED is a BUG, and the second call must succeed with
// the instant the first one recorded — not merely with some instant.
func TestMCP006RetireAgentIsIdempotentAndNeverReportsRunAlreadyRetired(t *testing.T) {
	requirePG(t)
	s := newStack(t)
	run := s.registerRun(t, "retire-twice")

	first := s.retireRun(t, run.RunID)
	if first.RetiredAt == "" {
		t.Fatalf("retire_agent returned no retired_at")
	}
	if s.spire.hasEntry(run.RunID) {
		t.Errorf("the SPIRE entry survived retirement")
	}

	for i := 2; i <= 4; i++ {
		again := s.retireRun(t, run.RunID)
		if again.RetiredAt != first.RetiredAt {
			t.Fatalf("retirement %d returned retired_at %q, want the original %q",
				i, again.RetiredAt, first.RetiredAt)
		}
	}

	// And exactly one `run_retired` is on the chain: idempotent means one
	// record, not one reply over many records.
	if got := s.countEvents(t, run.RunID, event.EventTypeRunRetired); got != 1 {
		t.Errorf("the chain holds %d run_retired events for %s, want exactly 1", got, run.RunID)
	}
}

// TestMCP006AToolWithNoIdempotencyKeyCannotReachDuplicateRequest is the
// negative assertion behind the DUPLICATE_REQUEST cells of get_credential and
// retire_agent.
//
// ADR-0004 forbids both of them a key. That is not a fact about the code's
// current shape but about the advertised contract, so it is asserted against
// the input schema the server publishes: a key that is not on the wire cannot
// be reused, and a tool with no key holds no idempotency store to conflict in.
func TestMCP006AToolWithNoIdempotencyKeyCannotReachDuplicateRequest(t *testing.T) {
	requirePG(t)
	s := newStack(t)

	want := map[mcp.ToolName]bool{
		mcp.ToolRegisterAgent: true,
		mcp.ToolGetCredential: false,
		mcp.ToolRecordEvent:   true,
		mcp.ToolSignCommit:    true,
		mcp.ToolRetireAgent:   false,
	}
	for tool, takesKey := range want {
		properties := s.inputProperties(t, tool)
		_, has := properties["idempotency_key"]
		if has != takesKey {
			t.Errorf("%s advertises idempotency_key = %v, IP §4 and ADR-0004 say %v (properties: %v)",
				tool, has, takesKey, slices.Sorted(mapKeys(properties)))
		}
		canDuplicate := slices.Contains(reachableClasses(tool), mcp.ClassDuplicateRequest)
		if canDuplicate != takesKey {
			t.Errorf("the matrix says %s can%s reach DUPLICATE_REQUEST, but it does%s take a key",
				tool, negate(canDuplicate), negate(takesKey))
		}
	}
}

// TestMCP006OnlyGetCredentialTakesAnAudience is the negative assertion behind
// the AUDIENCE_MISMATCH cells. IP §4 puts the allowlist on get_credential and
// nowhere else; a tool with no audience argument has nothing to mismatch.
func TestMCP006OnlyGetCredentialTakesAnAudience(t *testing.T) {
	requirePG(t)
	s := newStack(t)

	for _, tool := range []mcp.ToolName{
		mcp.ToolRegisterAgent, mcp.ToolGetCredential, mcp.ToolRecordEvent, mcp.ToolSignCommit, mcp.ToolRetireAgent,
	} {
		properties := s.inputProperties(t, tool)
		_, has := properties["audience"]
		want := tool == mcp.ToolGetCredential
		if has != want {
			t.Errorf("%s advertises audience = %v, IP §4 says %v (properties: %v)",
				tool, has, want, slices.Sorted(mapKeys(properties)))
		}
		canMismatch := slices.Contains(reachableClasses(tool), mcp.ClassAudienceMismatch)
		if canMismatch != want {
			t.Errorf("the matrix says %s can%s reach AUDIENCE_MISMATCH, but it does%s take an audience",
				tool, negate(canMismatch), negate(want))
		}
	}
}

// TestMCP006SignCommitIsBoundAndItsElevenCellsAreDecided is
// TestMCP006SignCommitIsDeferredNotForgotten, inverted (RM-071, #94).
//
// That test asserted the eleven cells stayed blank while sign_commit did not
// exist, and was written to FAIL the day RM-033 bound it — RM-028's tripwire:
//
//	MissingTools() = []; sign_commit is bound, so its eleven matrix cells
//	must stop being deferred and start being decided (RM-033, #41)
//
// The tripwire fired and this issue is the answer. What is asserted now is
// the opposite fact, permanently: sign_commit is advertised, not missing, and
// none of its eleven cells carries the verdict that stood in for "not decided
// yet" — a verdict that no longer exists in this package (see the removal
// note on the verdict type above) precisely so this can never regress
// silently.
func TestMCP006SignCommitIsBoundAndItsElevenCellsAreDecided(t *testing.T) {
	requirePG(t)
	s := newStack(t)

	if got := s.server.MissingTools(); slices.Contains(got, mcp.ToolSignCommit) {
		t.Fatalf("MissingTools() = %v includes sign_commit; its eleven matrix cells were "+
			"decided against a tool this run cannot even reach", got)
	}
	if got := s.server.BoundTools(); !slices.Contains(got, mcp.ToolSignCommit) {
		t.Fatalf("BoundTools() = %v does not include sign_commit", got)
	}

	n := 0
	for _, c := range matrix {
		if c.tool != mcp.ToolSignCommit {
			continue
		}
		n++
		if c.verdict != reachable && c.verdict != unreachable {
			t.Errorf("%s/%s carries verdict %d, which is neither reachable nor unreachable",
				c.tool, c.class, c.verdict)
		}
	}
	if n != len(mcp.Classes()) {
		t.Fatalf("the matrix carries %d sign_commit cells, want one per class (%d)", n, len(mcp.Classes()))
	}
}

// ---------------------------------------------------------------------------
// MCP-010.
// ---------------------------------------------------------------------------

// TestMCP010UnknownRunIDYieldsRunNotFound. doc 07 MCP-010, against every tool
// that takes a run_id.
//
// Two shapes of "unknown", because they are answered by different gates and
// the difference is visible on the wire: a run_id that cannot name a run is
// refused before any dependency is consulted and carries no run_id, while one
// that could have named a run is looked up and carries the id that was asked
// for.
func TestMCP010UnknownRunIDYieldsRunNotFound(t *testing.T) {
	requirePG(t)
	s := newStack(t)

	takesRunID := []struct {
		tool mcp.ToolName
		args func(runID string) map[string]any
	}{
		{mcp.ToolGetCredential, func(runID string) map[string]any {
			return map[string]any{"run_id": runID, "audience": mcp.AudienceSigstore}
		}},
		{mcp.ToolRecordEvent, func(runID string) map[string]any {
			return map[string]any{"run_id": runID, "event_type": "bash",
				"payload_digest": digestA, "idempotency_key": "mcp010-" + runID}
		}},
		{mcp.ToolRetireAgent, func(runID string) map[string]any {
			return map[string]any{"run_id": runID}
		}},
	}

	for _, tc := range takesRunID {
		t.Run(string(tc.tool)+"/absent", func(t *testing.T) {
			got := s.callExpectingError(t, tc.tool, tc.args(unknownRunID))
			if got.Class != string(mcp.ClassRunNotFound) {
				t.Fatalf("error_class = %s, doc 07 MCP-010 says RUN_NOT_FOUND (%s)", got.Class, got.Message)
			}
			if got.Retryable {
				t.Errorf("retryable = true; %s", ip4Retryable[mcp.ClassRunNotFound].source)
			}
			if got.RunID != unknownRunID {
				t.Errorf("run_id = %q, want the id that was asked for, %q", got.RunID, unknownRunID)
			}
		})
		t.Run(string(tc.tool)+"/malformed", func(t *testing.T) {
			got := s.callExpectingError(t, tc.tool, tc.args("Not A Run Id"))
			if got.Class != string(mcp.ClassRunNotFound) {
				t.Fatalf("error_class = %s, want RUN_NOT_FOUND: a run id that cannot name a run "+
					"names no run (%s)", got.Class, got.Message)
			}
			if got.RunIDSeen {
				t.Errorf("run_id present as %q; the argument is not a run id, so echoing it as one "+
					"would put a caller-supplied string where IP §4 promises a run", got.RunID)
			}
		})
	}

	// register_agent takes no run_id, so MCP-010 does not apply to it — and
	// the matrix says so.
	if slices.Contains(reachableClasses(mcp.ToolRegisterAgent), mcp.ClassRunNotFound) {
		properties := s.inputProperties(t, mcp.ToolRegisterAgent)
		if _, has := properties["run_id"]; has {
			t.Errorf("register_agent advertises a run_id; IP §4 gives it three arguments and none is one")
		}
	}
}

// TestMCP010RunNotFoundIsSPIRESAnswerRunAlreadyRetiredIsTheLedgersRecord is
// RM-025's finding, asserted as a distinction rather than accepted as an
// either/or.
//
// The two classes describe different facts and are decided by different gates:
//
//   - RUN_ALREADY_RETIRED is the LEDGER's `run_retired` record. It survives
//     forever (I4), and it is what makes retirement effective immediately
//     (IP §6.2), because it is true the instant the append commits.
//   - RUN_NOT_FOUND is SPIRE holding no registration entry. A deleted entry
//     with no `run_retired` behind it — a reaper, an operator, the deletion
//     half of a retirement whose record never landed — is not a retirement,
//     and must not be reported as one.
//
// A run in the first state and a run in the second are distinguishable on the
// wire, and this asserts they are, in both directions.
func TestMCP010RunNotFoundIsSPIRESAnswerRunAlreadyRetiredIsTheLedgersRecord(t *testing.T) {
	requirePG(t)
	s := newStack(t)

	// A: retired through the tool. Ledger record present, entry deleted.
	retired := s.registerRun(t, "distinction-retired")
	s.retireRun(t, retired.RunID)
	if s.spire.hasEntry(retired.RunID) {
		t.Fatalf("retirement left the SPIRE entry in place; the two states are not distinct")
	}
	if got := s.countEvents(t, retired.RunID, event.EventTypeRunRetired); got != 1 {
		t.Fatalf("the chain holds %d run_retired events for the retired run, want 1", got)
	}

	// B: entry deleted behind the MCP's back. No ledger record at all.
	orphaned := s.registerRun(t, "distinction-orphaned")
	s.spire.deleteEntry(orphaned.RunID)
	if got := s.countEvents(t, orphaned.RunID, event.EventTypeRunRetired); got != 0 {
		t.Fatalf("the chain holds %d run_retired events for the orphaned run, want 0", got)
	}

	args := map[string]any{"run_id": retired.RunID, "audience": mcp.AudienceSigstore}
	gotRetired := s.callExpectingError(t, mcp.ToolGetCredential, args)
	if gotRetired.Class != string(mcp.ClassRunAlreadyRetired) {
		t.Errorf("a run the LEDGER records as retired reached the caller as %s; "+
			"RUN_ALREADY_RETIRED is the ledger's record and nothing else can stand in for it (%s)",
			gotRetired.Class, gotRetired.Message)
	}
	if gotRetired.RunID != retired.RunID {
		t.Errorf("run_id = %q, want %q", gotRetired.RunID, retired.RunID)
	}

	args = map[string]any{"run_id": orphaned.RunID, "audience": mcp.AudienceSigstore}
	gotOrphaned := s.callExpectingError(t, mcp.ToolGetCredential, args)
	if gotOrphaned.Class != string(mcp.ClassRunNotFound) {
		t.Errorf("a run whose SPIRE entry was deleted with no `run_retired` reached the caller as %s; "+
			"a deleted entry is not a retirement and must not be reported as one (%s)",
			gotOrphaned.Class, gotOrphaned.Message)
	}
	if gotOrphaned.RunID != orphaned.RunID {
		t.Errorf("run_id = %q, want %q", gotOrphaned.RunID, orphaned.RunID)
	}

	if gotRetired.Class == gotOrphaned.Class {
		t.Fatalf("both states reached the caller as %s; the distinction RM-025 found is gone",
			gotRetired.Class)
	}

	// record_event is asked the same question and must give the same two
	// answers: MCP-009 is about every tool agreeing, from one run directory.
	gotRetired = s.callExpectingError(t, mcp.ToolRecordEvent, map[string]any{
		"run_id": retired.RunID, "event_type": "bash", "payload_digest": digestA,
		"idempotency_key": "distinction-a",
	})
	if gotRetired.Class != string(mcp.ClassRunAlreadyRetired) {
		t.Errorf("record_event against the retired run = %s, want RUN_ALREADY_RETIRED (%s)",
			gotRetired.Class, gotRetired.Message)
	}
	// The orphaned run is LIVE as far as the ledger is concerned, and
	// record_event asks SPIRE nothing — so it records, and that is correct:
	// I4 says a run's history is the ledger's, and no entry was ever the
	// authority for whether a tool call happened.
	var recorded struct {
		EventID       string `json:"event_id"`
		ChainPosition int64  `json:"chain_position"`
	}
	s.callExpectingSuccess(t, mcp.ToolRecordEvent, map[string]any{
		"run_id": orphaned.RunID, "event_type": "bash", "payload_digest": digestA,
		"idempotency_key": "distinction-b",
	}, &recorded)
	if recorded.EventID == "" || recorded.ChainPosition <= 0 {
		t.Errorf("record_event returned %+v for a run whose entry is gone but whose record is live",
			recorded)
	}
}

// ---------------------------------------------------------------------------
// MCP-001..005 — the documented result shape, for the four tools that exist.
// ---------------------------------------------------------------------------

// TestMCP001to005ValidInputYieldsTheDocumentedResultShape asserts the exact
// member set of each success reply against IP §4. Exact, not "at least": a
// fifth member is how something that is not in the contract reaches a caller.
func TestMCP001to005ValidInputYieldsTheDocumentedResultShape(t *testing.T) {
	requirePG(t)
	s := newStack(t)

	shapes := []struct {
		tool mcp.ToolName
		args map[string]any
		want []string
	}{
		{mcp.ToolRegisterAgent, map[string]any{
			"agent_type": testAgentType, "task_id": testTaskID, "idempotency_key": "shape-register",
			"repo": testRepo, "branch": testBranch,
		}, []string{"expires_at", "run_id", "spiffe_id"}},
	}

	for _, sh := range shapes {
		t.Run(string(sh.tool), func(t *testing.T) {
			assertResultShape(t, s, sh.tool, sh.args, sh.want)
		})
	}

	// The remaining three need the run the first one made.
	run := s.registerRun(t, "shape-run")
	t.Run(string(mcp.ToolGetCredential), func(t *testing.T) {
		assertResultShape(t, s, mcp.ToolGetCredential, map[string]any{
			"run_id": run.RunID, "audience": mcp.AudienceSigstore,
		}, []string{"expires_at", "jwt_svid"})
	})
	t.Run(string(mcp.ToolRecordEvent), func(t *testing.T) {
		assertResultShape(t, s, mcp.ToolRecordEvent, map[string]any{
			"run_id": run.RunID, "event_type": "bash", "payload_digest": digestA,
			"idempotency_key": "shape-record",
		}, []string{"chain_position", "event_id"})
	})
	t.Run(string(mcp.ToolRetireAgent), func(t *testing.T) {
		assertResultShape(t, s, mcp.ToolRetireAgent,
			map[string]any{"run_id": run.RunID}, []string{"retired_at"})
	})
}

func assertResultShape(t *testing.T, s *stack, tool mcp.ToolName, args map[string]any, want []string) {
	t.Helper()
	res := s.call(t, tool, args)
	if res.IsError {
		t.Fatalf("%s(%v) failed: %+v", tool, args, decodeWireError(t, tool, res))
	}
	body, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("%s: structuredContent is %T, want the documented result object", tool, res.StructuredContent)
	}
	got := slices.Sorted(mapKeys(body))
	if !slices.Equal(got, want) {
		t.Fatalf("%s result members = %v, IP §4 says %v", tool, got, want)
	}
	for _, k := range got {
		if v, isString := body[k].(string); isString && v == "" {
			t.Errorf("%s result member %q is the empty string; doc 02 §1 has no empty placeholders", tool, k)
		}
	}
}

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

func mapKeys(m map[string]any) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func negate(b bool) string {
	if b {
		return ""
	}
	return " not"
}

// inputProperties returns the advertised JSON-Schema properties of one tool's
// arguments, read off tools/list the way a client reads them.
func (s *stack) inputProperties(t *testing.T, tool mcp.ToolName) map[string]any {
	t.Helper()
	res, err := s.session.ListTools(testCtx(t, 30*time.Second), nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	for _, advertised := range res.Tools {
		if advertised.Name != string(tool) {
			continue
		}
		return schemaProperties(t, advertised)
	}
	t.Fatalf("tools/list does not advertise %s", tool)
	return nil
}

// schemaProperties reads the advertised argument names out of a tool's input
// schema the way a client does: off the JSON, not off a Go type.
func schemaProperties(t *testing.T, tool *sdk.Tool) map[string]any {
	t.Helper()
	if tool.InputSchema == nil {
		t.Fatalf("%s advertises no input schema", tool.Name)
	}
	raw, err := json.Marshal(tool.InputSchema)
	if err != nil {
		t.Fatalf("%s: re-encoding the input schema: %v", tool.Name, err)
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("%s: input schema %s is not a JSON Schema object: %v", tool.Name, raw, err)
	}
	out := make(map[string]any, len(schema.Properties))
	for name, member := range schema.Properties {
		out[name] = member
	}
	return out
}

// countEvents counts the events of one type on the chain for one run.
func (s *stack) countEvents(t *testing.T, runID, eventType string) int {
	t.Helper()
	ctx := testCtx(t, 30*time.Second)
	head, err := s.store.Head(ctx)
	if err != nil {
		t.Fatalf("ledger head: %v", err)
	}
	if head.IsEmpty() {
		return 0
	}
	records, err := s.store.Events(ctx, 1, head.Position)
	if err != nil {
		t.Fatalf("reading the chain: %v", err)
	}
	n := 0
	for _, rec := range records {
		id, isRun := rec[event.FieldRunID].(string)
		kind, isType := rec[event.FieldEventType].(string)
		if isRun && isType && id == runID && kind == eventType {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// MCP-060 — no tool passes the closure test for want of configuration.
// ---------------------------------------------------------------------------

// unconfiguredRefusal reports whether an IP §4 error is a tool's own
// "I was advertised and never wired" gate rather than a verdict about the
// input it was handed.
//
// Every one of the eight has such a gate and reaches it BEFORE it looks at
// anything the caller sent, which is what makes an unconfigured tool so
// dangerous to a matrix: it answers one INVARIANT_VIOLATION to every input,
// the matrix calls INVARIANT_VIOLATION reachable for every tool, and so every
// hostile row passes while proving nothing whatever about the tool. That is
// the vacuous pass this whole file is written against, and for three tools it
// was the actual state of the repository until #211.
//
// Seven of the eight say it in the same words. describe_workspace says it by
// naming the value it was never given, because its configuration is not a
// dependency it holds but a fact about the deployment it was never told.
func unconfiguredRefusal(message string) bool {
	for _, gate := range []string{
		"bound but not configured",
		"advertised but not wired",
		mcp.EnvHostProjects + " is unset",
	} {
		if strings.Contains(message, gate) {
			return true
		}
	}
	return false
}

// TestMCP060EveryToolTheStackBindsIsAlsoConfigured.
//
// The stack this package builds is the shipped wiring: the shipped Configure
// functions, a real chain, a real idempotency store and the real transport.
// Until #211 it wired five of the eight, and the three E11 tools could only be
// reached by a test installing their configuration itself — which meant a cell
// that forgot to was measuring its fixture, and a battery that forgot to would
// pass for every tool it never actually reached.
//
// So this drives one input at every tool the server BINDS — read off the
// server rather than written down, so a tool that starts binding tomorrow is
// covered the day it does — and asserts that what comes back is a verdict
// about the input and never the tool's own unwired gate. It is the contract
// half of the start-up refusal `innsegl serve` now makes (MCP-058): one
// refuses to start, this one refuses to pass.
func TestMCP060EveryToolTheStackBindsIsAlsoConfigured(t *testing.T) {
	requirePG(t)
	s := newStack(t)
	run := s.registerRun(t, "mcp060-live")
	doomed := s.registerRun(t, "mcp060-doomed")

	// An absolute path that is deliberately NOT under this stack's projects
	// root. A configured describe_workspace answers it with "that tree is
	// outside the mount", which is a verdict about the input; an unconfigured
	// one never gets that far, because the host root is checked first.
	outside := t.TempDir()

	probe := map[mcp.ToolName]map[string]any{
		mcp.ToolRegisterAgent: {
			"agent_type": testAgentType, "task_id": testTaskID,
			"idempotency_key": "mcp060-register", "repo": testRepo, "branch": testBranch,
		},
		mcp.ToolGetCredential: {"run_id": run.RunID, "audience": mcp.AudienceSigstore},
		mcp.ToolRecordEvent: {
			"run_id": run.RunID, "event_type": "bash",
			"payload_digest": digestA, "idempotency_key": "mcp060-record",
		},
		mcp.ToolSignCommit: {
			"run_id": run.RunID, "repo": scPlaceholderRepo, "staged_ref": scPlaceholderStagedRef,
			"message": "m", "task_ref": testTaskID, "idempotency_key": "mcp060-sign",
		},
		mcp.ToolRetireAgent:       {"run_id": doomed.RunID},
		mcp.ToolDescribeWorkspace: {"cwd": outside},
		mcp.ToolObserveToolCall:   {"run_id": run.RunID, "tool": "Edit", "body": observedBody},
		mcp.ToolObserveSession: {
			"session_id": "mcp060-session", "phase": mcp.ObserveSessionPhaseStop,
		},
	}

	bound := s.server.BoundTools()
	if len(bound) != len(mcp.ToolNames()) {
		t.Fatalf("the stack binds %d tools (%v), and IP §4 has %d", len(bound), bound, len(mcp.ToolNames()))
	}
	for _, tool := range bound {
		args, ok := probe[tool]
		if !ok {
			t.Fatalf("no probe for %s; a tool this package serves and never drives is a tool "+
				"whose configuration nobody has checked", tool)
		}
		t.Run(string(tool), func(t *testing.T) {
			res := s.call(t, tool, args)
			if !res.IsError {
				return // a success is proof enough: an unconfigured tool has none.
			}
			if res.StructuredContent == nil {
				t.Fatalf("%s refused the probe before the tool ran; this case needs an input "+
					"that reaches the tool's own gates", tool)
			}
			got := decodeWireError(t, tool, res)
			if unconfiguredRefusal(got.Message) {
				t.Fatalf("%s is bound and NOT configured by the stack: %s\n"+
					"Every matrix cell below it would be a verdict about the fixture rather "+
					"than about the tool (#211).", tool, got.Message)
			}
		})
	}
}
