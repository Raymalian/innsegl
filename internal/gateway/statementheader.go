// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"sync"
)

// RM-313: a session never gets stuck on a statement the core does not have.
//
// The session hook states each session's workspace to the client service,
// which forwards the statement to the core and keeps the newest one per
// (session, agent). It attaches that statement to every model request it
// forwards, in StatementHeader. The core's registry (workspaceregistry.go)
// is in memory, so after a core restart it is empty; the header refills it,
// and a restart mid-turn costs nothing.
//
// A header statement is used only when the registry has none for that
// agent: what the hook stated to this core always wins. It is validated
// exactly as the session-workspace endpoint validates its body, and admitted
// by the same rule: the installation's scope, with first use, and the
// session's pin.
//
// What the core still cannot record is forwarded, never refused: a request
// with no statement at all, and a repository the installation may not
// record. Each is reported once per (session, agent) as an UnrecordedFinding.
// Only the client-certificate guard and the session pin refuse.

// StatementHeader carries the client service's cached statement on a model
// request: the statement's JSON body, base64url without padding. The proxy
// never forwards it upstream.
const StatementHeader = "X-Innsegl-Statement"

// StatementVerdict is how a statement is admitted.
type StatementVerdict int

const (
	// StatementRefused: the caller may not state this session (another
	// installation's session).
	StatementRefused StatementVerdict = iota
	// StatementAdmitted: recorded as stated.
	StatementAdmitted
	// StatementOutOfScope: the session is the caller's, but the stated
	// repository is not one it may record. The session runs unrecorded.
	StatementOutOfScope
)

// HeaderStatements reads and admits the statement a request carries in
// StatementHeader.
type HeaderStatements interface {
	// Decode answers the statement r carries for id's session, and the agent
	// it names ("" for the main agent). ok is false when the header is
	// absent, malformed, or names another session or agent.
	Decode(r *http.Request, id Identification) (agentID string, st StatedWorkspace, ok bool)
	// Admit decides a decoded statement as the session-workspace endpoint
	// decides its body.
	Admit(ctx context.Context, sessionID string, st StatedWorkspace) (StatementVerdict, error)
}

// UnrecordedReason names why a forwarded request was not recorded.
type UnrecordedReason string

const (
	// UnrecordedNoStatement: no statement for the session, from the hook or
	// the header.
	UnrecordedNoStatement UnrecordedReason = "no-statement"
	// UnrecordedOutOfScope: the stated repository is not one the
	// installation may record.
	UnrecordedOutOfScope UnrecordedReason = "out-of-scope"
)

// UnrecordedFinding is a request the core forwarded without recording it.
type UnrecordedFinding struct {
	SessionID, AgentID, Installation, Repo string
	Reason                                 UnrecordedReason
}

// findingKey is one finding's identity: reported once.
type findingKey struct {
	sessionID, agentID string
	reason             UnrecordedReason
}

// reportedFindings bounds the set of findings already reported.
type reportedFindings struct {
	mu    sync.Mutex
	max   int
	order []findingKey
	seen  map[findingKey]bool
}

func newReportedFindings(capacity int) *reportedFindings {
	return &reportedFindings{max: capacity, seen: make(map[findingKey]bool)}
}

// first reports whether k is new, and remembers it.
func (r *reportedFindings) first(k findingKey) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen[k] {
		return false
	}
	if len(r.order) >= r.max && len(r.order) > 0 {
		delete(r.seen, r.order[0])
		r.order = r.order[1:]
	}
	r.order = append(r.order, k)
	r.seen[k] = true
	return true
}
