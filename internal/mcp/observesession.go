// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/event"
)

// observe_session — RM-128 (#207), E11. doc 01 §4:
//
//	observe_session(session_id, phase, cwd, agent_type?, task?) → the run.
//	phase=start resolves the workspace, registers the run and returns its
//	credential handle, recording the session-id → run-id mapping inside the
//	MCP; phase=stop retires the run found by session id.
//
// The eighth and last tool of IP §4's surface, and the one that finishes what
// RM-131 (#210) opened.
//
// # What this replaces
//
// Two harness events and a directory of files. The reference shim's
// SessionStart derived a workspace, registered a run and wrote
// `$RUNS_DIR/session-<session_id>`; its SessionEnd read that file, retired the
// run and removed it; SubagentStart and SubagentStop did the same around an
// agent id. Every one of those steps is work a second harness would have to
// reimplement identically, and the file layout most of all — a shim that wrote
// its marker a line out of order would retire the wrong run, or none.
//
// So the bookkeeping moves in here. A shim now reads its own event and forwards
// three values; nothing about which files exist, or what is on which line of
// them, is any harness's business.
//
// # This tool composes the other three; it re-derives nothing
//
// The workspace comes from describe_workspace, the run from register_agent,
// the retirement from retire_agent — the SHIPPED tools, installed through
// their own Configure functions and called in process. That is
// SignCommitThroughGetCredential's move (sign_commit.go) and it is made for
// the same reason: one derivation of what a workspace is, one definition of
// what a run is, one gate that refuses a retired one. A second registration
// path here would be a second thing that can disagree about any of them, and
// E11's whole rule is that a derivation exists once.
//
// It follows that this file has no SPIRE client, no ledger and no idempotency
// store of its own. Its one dependency is the volume the markers live on.
//
// # A stop NEVER blocks, and that decides the shape of the whole tool
//
// Measured before this existed: a harness answered a refused stop with nine
// repeated invocations before giving up. An MCP tool's equivalent of the
// shim's `exit 2` is an error result, so every failure on the stop path is
// returned as a REPLY that says what went wrong — the class and the message,
// in `detail` — and never as a refusal. The ledger being gone, SPIRE refusing
// the deletion, the marker being unreadable, this tool not being wired at all:
// all of them come back as a successful call carrying bad news.
//
// A start may refuse, and must. IP §6.1 requires attributed work to be
// impossible without an identity, and a session handed no run has none; the
// classes it returns are register_agent's and describe_workspace's own, since
// IP §4's vocabulary is closed and protected (doc 08 §3) and this tool adds
// nothing to it.
//
// # The marker outlives the retirement
//
// The shim deleted its marker on the way into a stop and measured what that
// cost: when the retirement then failed, the run was never retired AND the
// only record of it was gone, so nothing could retry — three runs registered
// one afternoon were still Active seventeen hours later. It was fixed there by
// deleting the marker only after a successful retirement. This goes one step
// further and keeps it afterwards too, with the instant written into it.
//
// That is not tidiness. A run id is a pure function of (agent_type, task,
// idempotency_key), so a start for a session id that has already been stopped
// would DERIVE THE SAME RUN ID; register_agent would replay its recorded reply
// and correctly refuse to resurrect the identity, and the caller would be
// handed a run that cannot get a credential or sign. A retired marker is what
// lets this tool report the terminal state instead. #213 is the same collision
// reached through the by-tree pointer, and is not fixed here.
//
// The limit of that, stated rather than discovered: the marker knows about a
// retirement THIS TOOL performed. A run retired by a direct retire_agent call
// leaves a marker that still reads live, and a start for that session replays
// into the same dead identity. Closing it would mean holding a run directory
// here and asking it on every start, which is the second definition of "what
// is a run" this file exists not to have. #213 owns that class of problem.
//
// # What does not change
//
// The event schema. doc 02 §3 has no member for a harness session id and gains
// none: the recorded link from a session to its run is the idempotency key,
// which register_agent already writes into `run_registered`. E11 is additive
// by construction — new tools, no new fields.

func init() { RegisterTool(ToolObserveSession, bindObserveSession) }

// The two phases of IP §4's `phase` argument. They are this tool's own
// vocabulary rather than a protected surface (doc 08 §3 protects tool names,
// error classes and the schema), and they are exported because a shim written
// in Go should spell them from one place.
const (
	// ObserveSessionPhaseStart is the harness event that begins a session.
	ObserveSessionPhaseStart = "start"
	// ObserveSessionPhaseStop is the one that ends it.
	ObserveSessionPhaseStop = "stop"
)

// MaxObserveSessionIDBytes bounds a harness session id.
//
// doc 02 §2 bounds an idempotency_key at 128 bytes and this tool derives one
// from the session id (see observeSessionKey), so the id has to fit inside
// that with the prefix. 64 is longer than any session id a harness has been
// observed to emit — a UUID is 36, a ULID 26 — and leaves the key half its
// budget spare.
const MaxObserveSessionIDBytes = 64

const (
	// observeSessionDefaultAgentType is the shim's own default for the
	// operator's session, kept verbatim so a deployment's existing rows and
	// this tool's new ones describe the same thing.
	observeSessionDefaultAgentType = "session"

	// observeSessionKeyPrefix makes the derived key legible in a ledger row.
	// The key is the only recorded link from a session back to its run, so it
	// is deliberately readable rather than a digest.
	observeSessionKeyPrefix = "session-"

	// observeSessionDirMode and observeSessionMarkerMode keep the markers to
	// the operator. A marker names a run a caller could then sign under, so
	// nothing needs group or world access to it.
	observeSessionDirMode    os.FileMode = 0o700
	observeSessionMarkerMode os.FileMode = 0o600
)

// observeSessionIDPattern is deliberately NOT doc 02 §5's identifier grammar.
//
// A session id is a foreign harness's string, verbatim, and it is neither an
// identity component nor a path segment — the marker's file name is a digest
// of it, and the SPIFFE ID is built from agent_type and task. Holding it to
// [a-z0-9][a-z0-9-]{0,62} would refuse an uppercase or underscored id for no
// benefit, and E11 exists precisely so that a harness other than the reference
// one can participate.
//
// What it still refuses is everything that could make a session id act like
// something else: it must begin with an alphanumeric, so `.` and `..` are out,
// and it admits no separator, space or control byte.
var observeSessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// observeSessionIn is doc 01 §4's argument list, verbatim.
type observeSessionIn struct {
	// SessionID is the harness's own id for this session. It is what a stop
	// finds the run by, so the caller never has to have kept the run id.
	SessionID string `json:"session_id"`
	// Phase is `start` or `stop`.
	Phase string `json:"phase"`
	// CWD is the caller's working directory AS THE CALLER SEES IT — a host
	// path, which describe_workspace translates. Required on a start that has
	// nothing recorded yet; unread on a stop, which knows the session already.
	CWD string `json:"cwd,omitempty"`
	// AgentType is what kind of agent this session is. Absent, it is
	// observeSessionDefaultAgentType.
	AgentType string `json:"agent_type,omitempty"`
	// Task is the caller's task reference. Absent, it is the task
	// describe_workspace folds out of the branch.
	Task string `json:"task,omitempty"`
}

// observeSessionOut is doc 01 §4's "the run": the identity, the workspace it
// works in, and where the session is in its lifetime.
type observeSessionOut struct {
	// SessionID and Phase echo the call, so a reply read on its own says which
	// session it is about.
	SessionID string `json:"session_id"`
	Phase     string `json:"phase"`
	// Known says this deployment holds a run for the session. False only on a
	// stop for a session it never saw start — which is not an error, because a
	// shim cannot guarantee ordering.
	Known bool `json:"known"`
	// Registered says THIS call created the run. A duplicate start answers
	// false and returns the same run: IP §6.6, never a second identity.
	Registered bool `json:"registered"`
	// Retired says the run is retired. It is set by a stop that retired it, by
	// a later stop, and by a start for a session that has already ended.
	Retired bool `json:"retired"`
	// RunID is the run this session is, empty when there is none.
	RunID string `json:"run_id,omitempty"`
	// SPIFFEID, ExpiresAt and RunToken are the credential handle IP §4 says a
	// start returns. RunToken is present only where the deployment configures
	// a run-token secret, and is recomputed by register_agent on every reply
	// rather than stored anywhere.
	SPIFFEID  string `json:"spiffe_id,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	RunToken  string `json:"run_token,omitempty"`
	// AgentType and Task are what the run was registered as.
	AgentType string `json:"agent_type,omitempty"`
	Task      string `json:"task,omitempty"`
	// Repo, Worktree and Branch are describe_workspace's answer, carried
	// through so a shim needs one call rather than two. Worktree is relative
	// to the repository and empty for the repository's own tree, which is
	// exactly sign_commit's `worktree` argument (MCP-029).
	Repo     string `json:"repo,omitempty"`
	Worktree string `json:"worktree,omitempty"`
	Branch   string `json:"branch,omitempty"`
	// RetiredAt is doc 02 §1's instant, present iff Retired. A second stop is
	// answered with the ORIGINAL one (IP §4).
	RetiredAt string `json:"retired_at,omitempty"`
	// Detail is why a call did not do the whole of what it was asked.
	//
	// It exists because a stop never refuses. A failure that would be an error
	// class on any other tool is a successful reply here carrying that class
	// and its message, so a harness can log it without being tempted to retry
	// into a storm.
	Detail string `json:"detail,omitempty"`
}

// observeSessionMarker is the mapping, one file per session.
//
// # Why the shim's line format is not ported
//
// observe_tool_call ported its layout byte for byte because two other readers
// re-derive the path and the name from a digest in the chain; a layout off by
// one character there produces a run whose every body reads as missing. This
// has no second reader by design — the marker moving INSIDE the MCP is the
// point of the issue — so the encoding is chosen for what the MCP needs, which
// is a record that gains a field without every reader having to count lines.
//
// What IS ported is the substance: what a marker records (the run, and enough
// of the workspace to answer a stop without re-deriving anything), and when it
// is written and kept.
type observeSessionMarker struct {
	SessionID string `json:"session_id"`
	RunID     string `json:"run_id"`
	SPIFFEID  string `json:"spiffe_id"`
	ExpiresAt string `json:"expires_at"`
	AgentType string `json:"agent_type"`
	Task      string `json:"task"`
	Repo      string `json:"repo"`
	Worktree  string `json:"worktree"`
	Branch    string `json:"branch"`
	// RetiredAt is empty while the session is live. Set, it is the instant the
	// ledger stamped on `run_retired`, and it is what a second stop and a
	// start-after-stop are answered with.
	RetiredAt string `json:"retired_at,omitempty"`
}

// reply renders a marker as the tool's result.
func (m observeSessionMarker) reply(phase string, registered bool, detail string) observeSessionOut {
	return observeSessionOut{
		SessionID:  m.SessionID,
		Phase:      phase,
		Known:      true,
		Registered: registered,
		Retired:    m.RetiredAt != "",
		RunID:      m.RunID,
		SPIFFEID:   m.SPIFFEID,
		ExpiresAt:  m.ExpiresAt,
		AgentType:  m.AgentType,
		Task:       m.Task,
		Repo:       m.Repo,
		Worktree:   m.Worktree,
		Branch:     m.Branch,
		RetiredAt:  m.RetiredAt,
		Detail:     detail,
	}
}

// ObserveSessionConfig is what observe_session runs on. Install it with
// ConfigureObserveSession before serving.
//
// One member, because this tool composes the other three rather than holding
// their dependencies a second time. describe_workspace, register_agent and
// retire_agent are configured separately and reached in process; a deployment
// that has not installed them meets their own refusals, by name.
type ObserveSessionConfig struct {
	// MarkerDir is the local volume the session → run mapping lives on.
	// Required.
	//
	// Required rather than optional for the reason the shim measured: a
	// session whose mapping was never written is a run nothing will ever
	// retire, and an operator discovers that as a list of runs still Active a
	// day later. A deployment with nowhere to put the mapping must not serve
	// this tool at all.
	MarkerDir string
}

// observeSessionService is the configured tool.
type observeSessionService struct{ markerDir string }

// observeSessionActive holds the installed configuration.
//
// Package state because ADR-0016 §5 fixes the seam: a tool file registers its
// own binder from its own init and the binder receives only the *Server, so
// there is nowhere else for a tool's dependencies to be handed in.
var (
	observeSessionMu     sync.RWMutex
	observeSessionActive *observeSessionService
)

// ConfigureObserveSession installs the marker volume and returns a function
// restoring whatever was installed before.
//
// Both refusals are made here rather than at the first call, so an operator
// finds out at start-up rather than when a harness does.
func ConfigureObserveSession(cfg ObserveSessionConfig) (func(), error) {
	switch {
	case cfg.MarkerDir == "":
		return nil, observeSessionMisconfigured(
			"no marker volume: the session-to-run mapping has nowhere to live, so every stop " +
				"would find nothing and every run would stay Active until the reaper took it (IP §6.7)")
	case !filepath.IsAbs(cfg.MarkerDir):
		return nil, observeSessionMisconfigured(fmt.Sprintf(
			"the marker volume %q is relative; it would resolve against whatever directory "+
				"this process happens to be in, and the mapping every stop depends on would "+
				"move with it", cfg.MarkerDir))
	}

	svc := &observeSessionService{markerDir: cfg.MarkerDir}
	observeSessionMu.Lock()
	defer observeSessionMu.Unlock()
	previous := observeSessionActive
	observeSessionActive = svc
	return func() {
		observeSessionMu.Lock()
		defer observeSessionMu.Unlock()
		observeSessionActive = previous
	}, nil
}

// observeSessionMisconfigured names a dependency the tool cannot run without.
func observeSessionMisconfigured(detail string) error {
	return Errorf(ClassInvariantViolation, "", "observe_session configuration: %s", detail)
}

func bindObserveSession(s *Server) error {
	return Bind(s, &sdk.Tool{
		Name: string(ToolObserveSession),
		Description: "Begin or end one harness session. `start` resolves the workspace, registers " +
			"the run and returns its credential handle, recording which run this session id " +
			"names; `stop` retires the run found by that session id, so the caller never has to " +
			"have kept it. A duplicate start returns the same run. A stop for a session that " +
			"never started, or one already stopped, succeeds with the terminal state — a stop " +
			"never refuses.",
	}, observeSession)
}

func observeSession(ctx context.Context, _ *sdk.CallToolRequest, in observeSessionIn) (observeSessionOut, error) {
	observeSessionMu.RLock()
	svc := observeSessionActive
	observeSessionMu.RUnlock()
	if svc == nil {
		// Alert-level: a bound tool with no dependencies behind it is a defect
		// in the wiring, and IP §4 has no "internal error" class (ADR-0016).
		//
		// This is the ONE failure a stop reports as a refusal rather than as a
		// reply, and it has to be: with no marker volume there is no marker to
		// answer from, so there is no terminal state to return. It is also not
		// a state a running deployment can reach — it is the state a
		// deployment is in before it is wired at all.
		return observeSessionOut{}, Errorf(ClassInvariantViolation, "",
			"%s is bound but not configured; no session can be recorded or ended (I3)",
			ToolObserveSession)
	}

	sessionID, err := observeSessionCheckID(in.SessionID)
	if err != nil {
		return observeSessionOut{}, err
	}

	switch in.Phase {
	case ObserveSessionPhaseStart:
		return svc.start(ctx, sessionID, in)
	case ObserveSessionPhaseStop:
		return svc.stop(ctx, sessionID)
	default:
		return observeSessionOut{}, observeSessionPhaseError(in.Phase)
	}
}

// start is the shim's SessionStart and SubagentStart, in one path.
//
// The marker is consulted FIRST, and it decides three things: whether the
// session has already ended (report, do not resurrect), whether it is already
// running (replay its own agent_type and task), and, when there is none,
// nothing at all — in which case the workspace is derived and the arguments
// are taken as given.
func (c *observeSessionService) start(ctx context.Context, sessionID string, in observeSessionIn) (observeSessionOut, error) {
	// THE VOLUME BEFORE THE MARKER, so that "this deployment's marker volume
	// is not there" and "this session's marker is not readable" are told
	// apart. The first is a dependency outage and a retry clears it; the
	// second is a defect a retry repeats. A single read would report both as
	// whichever class was written here first.
	if err := os.MkdirAll(c.markerDir, observeSessionDirMode); err != nil {
		return observeSessionOut{}, observeSessionVolumeUnusable(err)
	}

	marker, found, err := observeSessionReadMarker(c.markerDir, sessionID)
	if err != nil {
		// A start cannot shrug this off the way a stop does. Continuing would
		// register a SECOND run for a session that may already have one, and
		// the marker is the only thing that would have said so. The file is
		// left where it is, for an operator to look at.
		return observeSessionOut{}, Errorf(ClassInvariantViolation, "",
			"the marker for session %q cannot be read: %v. Registering over it would give one "+
				"session a second identity, so nothing was written and nothing was registered",
			sessionID, err)
	}
	if found && marker.RetiredAt != "" {
		// THE TERMINAL STATE, and not a refusal: the reference shim's
		// SessionStart never blocks, because refusing the operator's own
		// session stops them working on their own machine. See the note on
		// the derived run id at the top of this file for why re-registering
		// here would hand back a dead identity rather than a new one.
		return marker.reply(ObserveSessionPhaseStart, false, observeSessionRetiredDetail(marker)), nil
	}

	agentType, task := in.AgentType, in.Task
	repo, worktree, branch := marker.Repo, marker.Worktree, marker.Branch
	if found {
		// A SESSION IS REGISTERED ONCE, AND ITS TASK IS FIXED THEN. Re-deriving
		// the workspace on every start would let a session that moved between
		// worktrees present a different task under the same key, which the
		// idempotency store refuses as DUPLICATE_REQUEST — an ordinary second
		// start turning into a refusal. So a session already recorded replays
		// its own values.
		agentType, task = marker.AgentType, marker.Task
	} else {
		// describe_workspace, not a second copy of its derivation (E11's
		// rule). Its refusals come back unchanged, because a second wording
		// for one failure sends a shim author to the wrong file.
		ws, wsErr := describeWorkspace(ctx, nil, describeWorkspaceIn{CWD: in.CWD})
		if wsErr != nil {
			return observeSessionOut{}, wsErr
		}
		repo, worktree, branch = ws.Repo, ws.Worktree, ws.Branch
		if agentType == "" {
			agentType = observeSessionDefaultAgentType
		}
		if task == "" {
			task = ws.Task
		}
	}

	// register_agent, in process. The key is derived from the session id, so
	// two starts for one session are one registration — and that guarantee is
	// the ledger's UNIQUE idempotency_key and register_agent's derived run id,
	// not this tool's marker. Calling it again on a duplicate start is also
	// what HEALS a SPIRE entry the reaper withdrew, and what recomputes the
	// run token, which is never at rest anywhere.
	reg, err := registerAgent(ctx, nil, registerAgentIn{
		AgentType:      agentType,
		TaskID:         task,
		IdempotencyKey: observeSessionKey(sessionID),
		Repo:           repo,
		Branch:         branch,
	})
	if err != nil {
		return observeSessionOut{}, err
	}

	next := observeSessionMarker{
		SessionID: sessionID,
		RunID:     reg.RunID,
		SPIFFEID:  reg.SPIFFEID,
		ExpiresAt: reg.ExpiresAt,
		AgentType: agentType,
		Task:      task,
		Repo:      repo,
		Worktree:  worktree,
		Branch:    branch,
	}
	if err := observeSessionWriteMarker(c.markerDir, next); err != nil {
		// THE ASYMMETRY WITH STOP. A stop that cannot write its marker has
		// already retired the run, so the write is bookkeeping. A start that
		// cannot write one has registered a run nothing will ever find again,
		// because the mapping is the only route from a session id back to it.
		// So it refuses — retryably, and the retry converges: the registration
		// replays under the same key and the marker is written the second time.
		return observeSessionOut{}, observeSessionMappingNotWritten(reg.RunID, err)
	}

	out := next.reply(ObserveSessionPhaseStart, !found, "")
	// Off the reply and never out of the marker: a token at rest is a token
	// that can be read off a disk. register_agent recomputes it from the
	// deployment secret on every call, replays included.
	out.RunToken = reg.RunToken
	return out, nil
}

// stop is the shim's SessionEnd and SubagentStop.
//
// NOTHING HERE EVER REFUSES. Every return below is a successful reply, and the
// ones that did not finish say so in `detail`. See the note at the top of the
// file for the measurement that decided it.
func (c *observeSessionService) stop(ctx context.Context, sessionID string) (observeSessionOut, error) {
	unknown := func(detail string) observeSessionOut {
		return observeSessionOut{SessionID: sessionID, Phase: ObserveSessionPhaseStop, Detail: detail}
	}

	marker, found, err := observeSessionReadMarker(c.markerDir, sessionID)
	if err != nil {
		return unknown(fmt.Sprintf(
			"the marker for this session cannot be read: %v. Nothing was retired, and the file "+
				"is left in place: a stop that deleted what it could not use would lose the run "+
				"id for good", err)), nil
	}
	if !found {
		// IP §4: a stop for a session that never started is not an error. A
		// shim cannot guarantee ordering — a stop can arrive for a session
		// whose start never reached this deployment, or reached a previous
		// container — and there is nothing for a retry to converge on.
		return unknown(
			"no run is recorded for this session, so there was nothing to retire. That is not a " +
				"failure: a start may never have reached this deployment, and a stop that " +
				"refused would be answered with a retry storm rather than a start"), nil
	}
	if marker.RetiredAt != "" {
		// IP §4's idempotency, answered from the instant the ledger stamped on
		// the first retirement rather than from a clock read now.
		return marker.reply(ObserveSessionPhaseStop, false, observeSessionRetiredDetail(marker)), nil
	}

	// retire_agent, in process: one retirement path, one gate, one
	// `run_retired`. It is itself idempotent, so a marker this tool failed to
	// update does not cost a second event.
	reply, err := retireAgent(ctx, nil, retireAgentIn{RunID: marker.RunID})
	if err != nil {
		return marker.reply(ObserveSessionPhaseStop, false, observeSessionStopFailed(err)), nil
	}

	marker.RetiredAt = reply.RetiredAt
	detail := ""
	if err := observeSessionWriteMarker(c.markerDir, marker); err != nil {
		// The run IS retired — the ledger says so and that is what counts — so
		// this is reported and moved past. The consequence is bounded: the
		// next stop for this session retires an already-retired run, which
		// retire_agent answers with the original instant and no second event.
		detail = fmt.Sprintf(
			"the run was retired at %s and the marker could not be updated: %v. The retirement "+
				"stands; a later stop for this session will be answered with the same instant",
			reply.RetiredAt, err)
	}
	return marker.reply(ObserveSessionPhaseStop, false, detail), nil
}

// observeSessionCheckID holds a harness session id to what it may be.
//
// Neither refusal reaches a dependency: a malformed id costs one length
// comparison and one match, registers nothing and writes nothing.
func observeSessionCheckID(s string) (string, error) {
	switch {
	case s == "":
		return "", Errorf(ClassInvariantViolation, "",
			"session_id is required: it is what a stop finds the run by, and a session with no "+
				"id is a run nothing can ever retire")
	case len(s) > MaxObserveSessionIDBytes:
		// Length first, so an enormous argument is refused on its size without
		// a regexp being run over it.
		return "", Errorf(ClassInvariantViolation, "",
			"session_id is %d bytes and this tool accepts at most %d; the idempotency key it "+
				"derives is bounded at %d (doc 02 §2)",
			len(s), MaxObserveSessionIDBytes, event.MaxIdempotencyKeyBytes)
	case !observeSessionIDPattern.MatchString(s):
		return "", Errorf(ClassInvariantViolation, "",
			"session_id must match %s. It is a harness's own id and is deliberately not held to "+
				"doc 02 §5's identifier grammar — an uppercase or underscored id is a real "+
				"harness's id — but it may not look like a path or carry a separator",
			observeSessionIDPattern)
	}
	return s, nil
}

// observeSessionPhaseError names the one argument this tool switches on.
//
// A malformed phase is not a stop, whatever it was meant to be, so refusing it
// does not touch the never-block rule: there is nothing here to retire and no
// terminal state to report.
func observeSessionPhaseError(phase string) error {
	if phase == "" {
		return Errorf(ClassInvariantViolation, "",
			"phase is required: it is %q or %q, and a call that says neither is not a session "+
				"event this tool can act on",
			ObserveSessionPhaseStart, ObserveSessionPhaseStop)
	}
	return Errorf(ClassInvariantViolation, "",
		"phase %q is neither %q nor %q; guessing which was meant would either register a run "+
			"nobody asked for or retire one that is still working",
		phase, ObserveSessionPhaseStart, ObserveSessionPhaseStop)
}

// observeSessionRetiredDetail says the session is over, in the one wording a
// start and a later stop both use.
func observeSessionRetiredDetail(m observeSessionMarker) string {
	return fmt.Sprintf(
		"session %q ended at %s and run %s was retired then; retirement is effective "+
			"immediately and terminal (IP §6.2, I4). A new session needs a new session id: "+
			"re-registering under this one would derive the same run and hand back an "+
			"identity that can no longer sign",
		m.SessionID, m.RetiredAt, m.RunID)
}

// observeSessionStopFailed renders a failed retirement as news rather than as
// a refusal.
//
// The class and the message are carried verbatim out of the error the shipped
// retire_agent raised, so a reader of this field sees the same vocabulary
// every other tool uses — it is simply arriving in a successful reply, because
// a stop that refused was measured producing nine repeated invocations.
func observeSessionStopFailed(err error) string {
	classified := Classify(err)
	return fmt.Sprintf(
		"the run was not retired — %s: %s. The marker is kept, so a later stop for this "+
			"session retries with the same run id, and RM-017's reaper expires the identity as "+
			"run_expired if nothing does (IP §6.7). This call did not refuse: a stop that blocks "+
			"is answered by a harness with a retry storm, not with a fix",
		classified.Class, classified.Message)
}

// The two ways the marker volume can stop a start, both LEDGER_UNAVAILABLE and
// both retryable.
//
// IP §4's vocabulary is closed and protected (doc 08 §3), so there is no
// MARKER_STORE_UNAVAILABLE to add and this tool does not invent one. Of the
// eleven, this is the one that gives the caller the instruction the situation
// warrants — a mount that came back or a disk that was freed clears it, and a
// retry is what should happen. It is the same reading observe_tool_call
// records for its own body volume, and ADR-0017 for the idempotency store's
// in-flight case.
//
// They are two functions rather than one with a parameter because the ADVICE
// differs, and the advice is the useful half: one of them has registered a run
// and one has not.

// observeSessionVolumeUnusable reports a marker volume that is not there at
// all. Nothing has been registered at this point, so there is nothing to say
// about a run.
func observeSessionVolumeUnusable(cause error) error {
	return classifyAs(ClassLedgerUnavailable, "",
		"the session marker volume cannot be used: "+cause.Error()+
			". Nothing was registered: a run whose mapping cannot be written is a run no stop "+
			"will ever find, and it would stay Active until the reaper took it (IP §6.7)",
		true, "the session marker volume", cause)
}

// observeSessionMappingNotWritten reports a run that exists and a mapping to
// it that does not.
func observeSessionMappingNotWritten(runID string, cause error) error {
	return classifyAs(ClassLedgerUnavailable, runID,
		"the session's run was registered and the mapping to it could not be written: "+
			cause.Error()+". Retry: the registration replays under the same key and names the "+
			"same run, so nothing is registered twice and the mapping lands on the second call",
		true, "the session marker volume", cause)
}

// observeSessionKey derives the idempotency key for one session.
//
// doc 01 §4 gives this tool no idempotency_key argument, and ADR-0004 requires
// the KEY on the `run_registered` register_agent appends. Deriving it from the
// session id satisfies both, and it takes the choice away from the caller —
// which matters twice over: a caller choosing keys could register one session
// twice under two keys, and this key is the ONLY recorded link from a session
// back to its run, since doc 02 §3 has no member for a session id.
//
// The prefix is the reference shim's own, verbatim, so a deployment's existing
// rows and this tool's new ones are read the same way.
func observeSessionKey(sessionID string) string {
	return observeSessionKeyPrefix + sessionID
}

// observeSessionMarkerName is the file one session's marker lives in.
//
// A DIGEST, not the session id. Two reasons, and the second is the one that
// bites: a caller's string must never be able to name a path, and two session
// ids differing only in case must not collide into one marker — which they
// would on the case-insensitive filesystem the operator's own machine usually
// has, giving two sessions one run.
func observeSessionMarkerName(sessionID string) string {
	sum := sha256.Sum256([]byte(sessionID))
	return hex.EncodeToString(sum[:])
}

// observeSessionPartialName is the name one marker's bytes are written under
// before they are moved onto the marker's own. See observeSessionWriteMarker
// for why the write is not in place, and why this is derived rather than
// randomised.
func observeSessionPartialName(sessionID string) string {
	return "." + observeSessionMarkerName(sessionID) + ".part"
}

// observeSessionReadMarker returns one session's marker, and whether there is
// one.
//
// An absent marker is NOT an error: it is the ordinary state of a session this
// deployment has not seen, and both callers act on it. Anything else — an
// unreadable file, bytes that are not a marker — is, because a start must not
// register over a mapping it could not read.
func observeSessionReadMarker(dir, sessionID string) (observeSessionMarker, bool, error) {
	raw, err := os.ReadFile(filepath.Join(dir, observeSessionMarkerName(sessionID)))
	if errors.Is(err, fs.ErrNotExist) {
		return observeSessionMarker{}, false, nil
	}
	if err != nil {
		return observeSessionMarker{}, false, err
	}
	var marker observeSessionMarker
	if err := json.Unmarshal(raw, &marker); err != nil {
		return observeSessionMarker{}, false, fmt.Errorf("it is not a session marker: %w", err)
	}
	return marker, true, nil
}

// observeSessionWriteMarker writes one session's marker.
//
// Not in place: the bytes go to a temporary name in the same directory and are
// moved onto the final one. A torn marker reads as corrupt, and a start
// refuses on a corrupt marker — so an interrupted write must leave no file at
// all rather than one that strands a session until an operator deletes it.
//
// The temporary name is derived from the marker's own name rather than
// randomised. Two writers for one session are two calls for one session id,
// and the worst they can do to each other is write the same bytes twice.
func observeSessionWriteMarker(dir string, marker observeSessionMarker) error {
	// The marshal error is dropped, deliberately, and a test holds the ground
	// it would have covered.
	//
	// json.Marshal cannot fail for a struct of plain strings, so ANY branch on
	// it is one no input can drive. Folding it into the next condition does not
	// fix that — it only moves the undriveable half onto `err == nil`, which is
	// what IP §2's branch floor caught here. A dead error path is dead wherever
	// it is written.
	//
	// What the branch was protecting against is this type growing a member that
	// does not encode. That is a change to the struct, so it is caught by a test
	// over the struct — TestObserveSessionMarkerAlwaysEncodes — rather than by a
	// runtime path that would have to stay uncovered forever to exist at all.
	//nolint:errcheck // No value of this type can produce an error; see above.
	raw, _ := json.Marshal(marker)

	if err := os.MkdirAll(dir, observeSessionDirMode); err != nil {
		return fmt.Errorf("preparing the marker volume: %w", err)
	}

	final := filepath.Join(dir, observeSessionMarkerName(marker.SessionID))
	partial := filepath.Join(dir, observeSessionPartialName(marker.SessionID))
	if err := os.WriteFile(partial, raw, observeSessionMarkerMode); err != nil {
		return fmt.Errorf("writing the marker: %w", err)
	}
	if err := os.Rename(partial, final); err != nil {
		// Leaving the partial behind would put a run id on the operator's disk
		// under a name nothing opens. The removal's own failure is not
		// reported over it: the caller's problem is the write that did not land.
		_ = os.Remove(partial)
		return fmt.Errorf("moving the marker into place: %w", err)
	}
	return nil
}
