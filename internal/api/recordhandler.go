// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"innsegl.dev/innsegl/internal/event"
)

// recordhandler.go wires the run page's two routes (E19, #395–#397):
//
//	GET /api/v1/runs/{run_id}/record
//	GET /api/v1/runs/{run_id}/steps/{n}/diff
//
// # Why this is not a field on ServerConfig
//
// server.go is another issue's file (the login gate) and is not edited
// here. Server's fields are private to package api, so the handlers below —
// same package, different file — reach s.store and s.prover directly; what
// server.go does NOT give this file is anywhere to put the two settings
// NewServer's own ServerConfig has no member for: the snapshot store's root
// directory and the git binary to read it with. Those arrive the same way
// internal/mcp's own observe_tool_call and agent-message recorder arrive at
// a seam nothing else was built to carry (observeActive,
// agentMessageActive): a package-level Configure/restore pair, called
// BEFORE NewServer by whatever wires this process together
// (cmd/innsegl/apiwiring.go, which this issue DOES own and edits).
//
// registerRecordRoutes reads that package state ONCE, when it runs, and
// closes over it in a *recordServer — never a second Server field, and
// never read again per request.

// RecordConfig is what ConfigureRecordRoutes installs.
type RecordConfig struct {
	// SnapshotDir is the gateway's own snapshot store root —
	// internal/gateway/snapshot.go's SnapshotConfig.StoreRoot, mounted
	// read-only into this process (deploy/compose/innsegl.workrepo.yml: the
	// SAME /agentlog volume ServerConfig.LogDir already reads, subdirectory
	// "gateway-snapshots"). Empty disables every snapshot-derived member of
	// the record: steps and files still come from the ledger and the
	// retained bodies, tree_before/tree_after stay empty, and the diff route
	// answers "no snapshot store is configured" rather than guessing.
	SnapshotDir string
	// GitPath is the git binary this file reads the snapshot store and the
	// served repositories with. Empty means the same PATH lookup
	// NewProver's own GitPath falls back to.
	GitPath string
}

var (
	recordConfigMu sync.RWMutex
	recordConfig   RecordConfig
)

// ConfigureRecordRoutes installs cfg for every *Server registerRecordRoutes
// is called on afterward, and returns a function restoring whatever was
// installed before — the same shape mcp.ConfigureAgentMessageRecorder
// already gives its own callers, for a test that wants to hold this state
// still without leaking it into the next one.
func ConfigureRecordRoutes(cfg RecordConfig) func() {
	recordConfigMu.Lock()
	defer recordConfigMu.Unlock()
	previous := recordConfig
	recordConfig = cfg
	return func() {
		recordConfigMu.Lock()
		defer recordConfigMu.Unlock()
		recordConfig = previous
	}
}

func currentRecordConfig() RecordConfig {
	recordConfigMu.RLock()
	defer recordConfigMu.RUnlock()
	return recordConfig
}

// recordServer is this file's own read surface: s.store and s.prover,
// reached once at registration time, plus the snapshot-store settings
// ConfigureRecordRoutes installed. A distinct type rather than more methods
// directly on *Server for the reason above — nothing here can be a Server
// field — and it costs nothing: every method needs exactly these three
// things and no request-scoped state ever lives on it.
type recordServer struct {
	store  *Store
	prover *Prover
	logDir string
	cfg    snapshotStoreConfig
}

// registerRecordRoutes adds this issue's two routes to s's own mux. Called
// once, after NewServer's own routes (server.go, another issue's file) —
// the supervisor wires the call in; see this file's own package comment.
func (s *Server) registerRecordRoutes() {
	cfg := currentRecordConfig()
	rs := &recordServer{
		store:  s.store,
		prover: s.prover,
		logDir: s.logDir,
		cfg:    snapshotStoreConfig{root: cfg.SnapshotDir, gitPath: cfg.GitPath},
	}
	s.mux.HandleFunc("GET /api/v1/runs/{run_id}/record", rs.handleRunRecord)
	s.mux.HandleFunc("GET /api/v1/runs/{run_id}/steps/{n}/diff", rs.handleStepDiff)
}

// runIDFromPath validates a {run_id} path value against doc 02 §5's
// identifier grammar — the ONE place either handler trusts a run id it read
// out of a request, before it becomes a SQL parameter, a directory name
// under the body store, or part of a snapshot-store lookup.
func runIDFromPath(r *http.Request) (string, error) {
	runID := r.PathValue("run_id")
	if err := event.ValidateIdentifier(runID); err != nil {
		return "", fmt.Errorf("%w: %q is not a run id: %w", ErrBadRequest, runID, err)
	}
	return runID, nil
}

// handleRunRecord answers GET /api/v1/runs/{run_id}/record.
func (rs *recordServer) handleRunRecord(w http.ResponseWriter, r *http.Request) {
	runID, err := runIDFromPath(r)
	if err != nil {
		writeProblem(w, err)
		return
	}
	rec, err := rs.buildRunRecord(r.Context(), runID)
	if err != nil {
		writeProblem(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

// handleStepDiff answers GET /api/v1/runs/{run_id}/steps/{n}/diff.
func (rs *recordServer) handleStepDiff(w http.ResponseWriter, r *http.Request) {
	runID, err := runIDFromPath(r)
	if err != nil {
		writeProblem(w, err)
		return
	}
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil || n < 1 {
		writeProblem(w, fmt.Errorf("%w: step %q is not a positive step number",
			ErrBadRequest, r.PathValue("n")))
		return
	}
	diff, err := rs.buildStepDiff(r.Context(), runID, n)
	if err != nil {
		writeProblem(w, err)
		return
	}
	writeJSON(w, http.StatusOK, diff)
}
