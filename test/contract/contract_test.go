// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc/codes"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/mcp"
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
type verdict int

const (
	// reachable: an input a caller can send drives the SHIPPED tool to this
	// class. drive produces it.
	reachable verdict = iota
	// unreachable: no input can. IP §4 lists the class for every tool, so this
	// is a finding about the document, not a hole in the tests. why says which
	// dependency or argument the tool does not have.
	unreachable
	// deferred: the tool does not exist yet (sign_commit, RM-033, #41).
	deferred
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
	// why explains an unreachable or deferred cell. It is the finding.
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

// matrix is every tool of IP §4 against every class of IP §4: 5 × 11 = 55.
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
	// -----------------------------------------------------------------------
	{tool: mcp.ToolSignCommit, class: mcp.ClassAttestationFailed, verdict: deferred},
	{tool: mcp.ToolSignCommit, class: mcp.ClassIdentityUnavailable, verdict: deferred},
	{tool: mcp.ToolSignCommit, class: mcp.ClassCredentialExpired, verdict: deferred},
	{tool: mcp.ToolSignCommit, class: mcp.ClassAudienceMismatch, verdict: deferred},
	{tool: mcp.ToolSignCommit, class: mcp.ClassLedgerUnavailable, verdict: deferred},
	{tool: mcp.ToolSignCommit, class: mcp.ClassSigningUnavailable, verdict: deferred},
	{tool: mcp.ToolSignCommit, class: mcp.ClassTransparencyUnavailable, verdict: deferred},
	{tool: mcp.ToolSignCommit, class: mcp.ClassRunNotFound, verdict: deferred},
	{tool: mcp.ToolSignCommit, class: mcp.ClassRunAlreadyRetired, verdict: deferred},
	{tool: mcp.ToolSignCommit, class: mcp.ClassDuplicateRequest, verdict: deferred},
	{tool: mcp.ToolSignCommit, class: mcp.ClassInvariantViolation, verdict: deferred},

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
			})
			return s.callExpectingError(t, mcp.ToolRetireAgent, map[string]any{"run_id": forged})
		},
	},
}

// deadLedgerRunID is the run registered on the dead-ledger stack while
// Postgres was still up, so that the reads that fail afterwards are reads for
// a run that genuinely exists.
var deadLedgerRunID string

// ---------------------------------------------------------------------------
// MCP-006.
// ---------------------------------------------------------------------------

// TestMCP006TheMatrixIsExactlyToolsTimesClasses keeps the matrix honest before
// anything is run against it: 5 × 11, every pair once, no pair missing, and
// every non-reachable cell carrying the reason it is not.
func TestMCP006TheMatrixIsExactlyToolsTimesClasses(t *testing.T) {
	tools, classes := mcp.ToolNames(), mcp.Classes()
	if want := len(tools) * len(classes); len(matrix) != want {
		t.Fatalf("matrix has %d cells, IP §4 has %d tools × %d classes = %d",
			len(matrix), len(tools), len(classes), want)
	}
	seen := map[string]bool{}
	for _, c := range matrix {
		key := string(c.tool) + "/" + string(c.class)
		if seen[key] {
			t.Errorf("%s appears twice in the matrix", key)
		}
		seen[key] = true
		if !c.tool.Valid() {
			t.Errorf("%q is not one of the five IP §4 tool names", c.tool)
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
		case deferred:
			if c.tool != mcp.ToolSignCommit {
				t.Errorf("%s is deferred, but only sign_commit is (RM-033, #41)", key)
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
		mcp.ToolRegisterAgent, mcp.ToolGetCredential, mcp.ToolRecordEvent, mcp.ToolRetireAgent,
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
		mcp.ToolRetireAgent: {
			{},
			{"run_id": ""},
			{"run_id": long},
			{"run_id": unknownRunID},
			{"run_id": "Run-42"},
			{"run_id": "../../etc/passwd"},
		},
	}

	for _, tool := range mcp.ToolNames() {
		inputs, ok := battery[tool]
		if !ok {
			continue // sign_commit — RM-033.
		}
		allowed := reachableClasses(tool)
		for i, args := range inputs {
			t.Run(fmt.Sprintf("%s/%d", tool, i), func(t *testing.T) {
				res := s.call(t, tool, args)
				if !res.IsError {
					return // A success is not a class; the matrix is about failures.
				}
				if res.StructuredContent == nil {
					// The transport's own schema validation refused the
					// arguments before the tool ran, so there is no IP §4
					// class to check. See
					// TestMCP006AnInputTheSchemaRefusesNeverReachesTheTool.
					return
				}
				got := decodeWireError(t, tool, res)
				if !slices.Contains(allowed, mcp.Class(got.Class)) {
					t.Fatalf("%s(%v) produced %s, which the matrix calls unreachable for this tool.\n"+
						"Either the matrix is wrong or the tool grew a class: %s",
						tool, args, got.Class, got.Message)
				}
				assertNotWidened(t, got)
			})
		}
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
		mcp.ToolRegisterAgent, mcp.ToolGetCredential, mcp.ToolRecordEvent, mcp.ToolRetireAgent,
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

// TestMCP006SignCommitIsDeferredNotForgotten.
//
// Eleven cells of this matrix are blank because sign_commit does not exist
// (RM-033, #41). That is only acceptable while it is TRUE, so it is asserted:
// the server reports the tool as missing rather than advertising it. The day
// RM-033 binds it, this test fails and the matrix has to grow its eleven rows
// instead of quietly carrying eleven lies.
func TestMCP006SignCommitIsDeferredNotForgotten(t *testing.T) {
	requirePG(t)
	s := newStack(t)

	if got := s.server.MissingTools(); !slices.Contains(got, mcp.ToolSignCommit) {
		// PENDING, not silently skipped. RM-033 (#41) bound sign_commit, so the
		// eleven cells this matrix deferred must now be decided — that is RM-071
		// (#94). Reported on every run so it cannot be forgotten, the same way
		// scripts/branch-coverage.sh reports an unimplemented surface.
		t.Logf("PENDING: sign_commit is bound and its eleven matrix cells are not " +
			"yet decided. Tracked as RM-071 (#94). This is a coverage gap, not a pass.")
	}
	if got := s.server.BoundTools(); slices.Contains(got, mcp.ToolSignCommit) {
		t.Logf("PENDING: BoundTools() = %v includes sign_commit; the eleven cells "+
			"below are still marked deferred and no longer describe the surface.", got)
	}
	// Still marked deferred, deliberately. Changing them without driving the calls
	// would be the lie this test exists to prevent — eleven verdicts asserted from
	// nothing. RM-071 (#94) decides them by measurement.
	for _, c := range matrix {
		if c.tool == mcp.ToolSignCommit && c.verdict != deferred {
			t.Errorf("%s/%s is not marked deferred; RM-071 (#94) has not landed, so a "+
				"verdict here would be asserted rather than measured", c.tool, c.class)
		}
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
