// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"innsegl.dev/innsegl/internal/gateway"
)

// maxStatementHeaderBytes bounds the encoded header: the endpoint's own body
// bound, base64 encoded.
var maxStatementHeaderBytes = base64.RawURLEncoding.EncodedLen(4 * maxWorkingDirectoryBytes)

// headerStatements is the identity guard's reader of the statement the
// client service attaches to a model request (gateway.StatementHeader,
// RM-313). It decodes the same body the session-workspace endpoint takes,
// validates it with the same rule, and admits it with the same callers.
type headerStatements struct{ callers sessionCallers }

var _ gateway.HeaderStatements = headerStatements{}

// Decode answers the statement r carries for id. The statement must name
// id's session, and either no agent (the session's own statement, which a
// subagent's request may carry when the subagent stated none) or id's agent.
func (h headerStatements) Decode(r *http.Request, id gateway.Identification) (string, gateway.StatedWorkspace, bool) {
	raw := r.Header.Get(gateway.StatementHeader)
	if raw == "" || len(raw) > maxStatementHeaderBytes {
		return "", gateway.StatedWorkspace{}, false
	}
	body, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", gateway.StatedWorkspace{}, false
	}
	var in sessionWorkspaceStatement
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&in); err != nil || !in.valid() {
		return "", gateway.StatedWorkspace{}, false
	}
	if in.SessionID != id.SessionID || (in.AgentID != "" && in.AgentID != id.AgentID) {
		return "", gateway.StatedWorkspace{}, false
	}
	return in.AgentID, in.stated(), true
}

// Admit decides the statement as the endpoint decides its body.
func (h headerStatements) Admit(ctx context.Context, sessionID string, st gateway.StatedWorkspace) (gateway.StatementVerdict, error) {
	return h.callers.admitStatement(ctx, sessionID, st)
}

// logUnrecorded is the identity guard's finding sink: one warning per
// (session, agent, reason) for a request forwarded without being recorded.
func logUnrecorded(log *serveLog) func(gateway.UnrecordedFinding) {
	return func(f gateway.UnrecordedFinding) {
		log.warn("finding: a model request was forwarded unrecorded",
			"reason", string(f.Reason), "session_id", f.SessionID, "agent_id", f.AgentID,
			"installation_id", f.Installation, "repo", f.Repo)
	}
}
