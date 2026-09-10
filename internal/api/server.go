// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// The HTTP surface, and why the method guard is the first thing in it.
//
// FD P6: "Read-only means read-only. No mutating action exists anywhere in the
// UI. No delete, no edit, no retry buttons that write." The UI is not where
// that can be enforced — a UI is a client, and a client is a suggestion. Two
// things enforce it here, and neither is the absence of a handler:
//
//   - the DATABASE ROLE (readonly.go), which is what actually stops a write;
//   - this guard, which refuses every method but GET, HEAD and OPTIONS on
//     EVERY path, including paths that do not exist.
//
// The second is the weaker of the two and it is still worth having: it makes
// "this API accepts no mutating request" a property of one function rather
// than a property of every handler anyone ever adds.
//
// Nothing served here is cacheable. FD anti-pattern 1 is "a verified state
// rendered from cache while the live check errored", and the cheapest way for
// that to happen to a well-written frontend is an intermediary that cached a
// proof response.

// ServerConfig is the query API's two halves: the read-only ledger index, and
// the live proof BFF.
type ServerConfig struct {
	Store  *Store
	Prover *Prover
	// LogDir is where the harness writes tool-call bodies, one directory per
	// run, each file named by its own digest. Empty disables the route: a
	// deployment that keeps no bodies answers "no log" rather than pretending
	// to have one.
	//
	// READ-ONLY here, and mounted that way. Retention belongs to the hook that
	// writes them; a read path able to delete would be one misconfiguration
	// away from pruning on somebody else's schedule.
	LogDir string
	// LogRetentionDays is reported so a reader can tell a body that aged out
	// from one that never existed.
	LogRetentionDays int
}

// Health is what an operator reads to see that "read-only" is a measured fact
// rather than a claim. It is the report Open gathered from the server itself.
type Health struct {
	Database ReadOnlyReport `json:"database"`
	Repos    []string       `json:"repos"`
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

// Error codes, spelled once.
const (
	codeBadRequest = "bad_request"
	codeNotFound   = "not_found"
	codeInternal   = "internal"
)

// Server is the read-only HTTP surface.
type Server struct {
	store     *Store
	prover    *Prover
	mux       *http.ServeMux
	logDir    string
	logRetain int
}

// NewServer wires the routes.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("%w: a query API with no store can answer nothing", ErrBadRequest)
	}
	if cfg.Prover == nil {
		return nil, fmt.Errorf("%w: a query API with no prover would have to answer "+
			"verification questions out of the database, which IP §6.11 forbids", ErrBadRequest)
	}
	retain := cfg.LogRetentionDays
	if retain <= 0 {
		retain = 90
	}
	s := &Server{
		store: cfg.Store, prover: cfg.Prover, mux: http.NewServeMux(),
		logDir: cfg.LogDir, logRetain: retain,
	}
	s.mux.HandleFunc("GET /api/v1/runs", s.handleRuns)
	s.mux.HandleFunc("GET /api/v1/runs/{run_id}", s.handleRun)
	s.mux.HandleFunc("GET /api/v1/runs/{run_id}/log", s.handleRunLog)
	s.mux.HandleFunc("GET /api/v1/overview", s.handleOverview)
	s.mux.HandleFunc("GET /api/v1/alerts", s.handleAlerts)
	s.mux.HandleFunc("GET /api/v1/proof/{commit_sha}", s.handleProof)
	s.mux.HandleFunc("GET /api/v1/attribution/{commit_sha}", s.handleAttribution)
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	return s, nil
}

// ServeHTTP refuses every mutating method before it looks at the path.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		writeError(w, http.StatusMethodNotAllowed, codeBadRequest,
			r.Method+" is not a method this API has. It is read-only: the credential "+
				"it holds cannot write to the ledger, and no path here accepts anything "+
				"but GET, HEAD and OPTIONS (FD P6).")
		return
	}
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request) {
	filter, err := runFilterFrom(r)
	if err != nil {
		writeProblem(w, err)
		return
	}
	page, err := s.store.ListRuns(r.Context(), filter)
	if err != nil {
		writeProblem(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	detail, err := s.store.Run(r.Context(), r.PathValue("run_id"))
	if err != nil {
		writeProblem(w, err)
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

// handleRunLog serves what the agent actually did, checked against the chain.
//
// The bodies are not in the ledger and never will be (doc 02 §3, IP E4), so
// this reads them from the operator's own disk and reports, per line, whether
// they still hash to the digest the chain recorded. That check is the reason
// the route exists — rendering the files without it would be a log; with it,
// it is a record.
func (s *Server) handleRunLog(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("run_id")
	if s.logDir == "" {
		// Not an error. A deployment may legitimately keep no bodies, and an
		// empty log says so rather than failing the page around it.
		writeJSON(w, http.StatusOK, RunLog{
			RunID: runID, RetentionDays: s.logRetain, Entries: []LogEntry{},
		})
		return
	}
	detail, err := s.store.Run(r.Context(), runID)
	if err != nil {
		writeProblem(w, err)
		return
	}
	log, err := BuildRunLog(runID, s.logDir, s.logRetain, detail.Timeline)
	if err != nil {
		writeProblem(w, fmt.Errorf("%w: %w", ErrBadRequest, err))
		return
	}
	writeJSON(w, http.StatusOK, log)
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	o, err := s.store.Overview(r.Context())
	if err != nil {
		writeProblem(w, err)
		return
	}
	writeJSON(w, http.StatusOK, o)
}

// handleAlerts serves #167's list endpoint: a paged, type-filterable read of
// the two alert event types. Read-only like every other route here — it never
// writes a resolution, see ADR-0044 for why that lives outside this server.
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	filter, err := alertFilterFrom(r)
	if err != nil {
		writeProblem(w, err)
		return
	}
	page, err := s.store.ListAlerts(r.Context(), filter)
	if err != nil {
		writeProblem(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

// handleProof is FD §3.6's public page, server side. The verdict is live and
// the material comes with it; an unreachable upstream is an "unavailable"
// verdict in a 200, not an HTTP error, because "we could not check" is an
// answer this API is obliged to give in full.
func (s *Server) handleProof(w http.ResponseWriter, r *http.Request) {
	proof, err := s.prover.Prove(r.Context(), r.URL.Query().Get("repo"), r.PathValue("commit_sha"))
	if err != nil {
		writeProblem(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proof)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, Health{
		Database: s.store.ReadOnly(),
		Repos:    s.prover.Repos(),
	})
}

// runFilterFrom reads the runs table's state out of the URL.
//
// FD §7: "every view's state (filters, selected run, verification input) lives
// in the URL", so the query string IS the filter and there is nothing else it
// could be read from.
func runFilterFrom(r *http.Request) (RunFilter, error) {
	q := r.URL.Query()
	// The direction is validated in the store, beside the two statements it
	// chooses between, so the check and the SQL cannot drift apart.
	f := RunFilter{
		Order:     q.Get("order"),
		Repo:      q.Get("repo"),
		AgentType: q.Get("agent_type"),
		Status:    q.Get("status"),
		Search:    q.Get("q"),
		Cursor:    q.Get("cursor"),
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return RunFilter{}, fmt.Errorf("%w: limit=%q is not a positive number", ErrBadRequest, v)
		}
		f.Limit = n
	}
	for _, bound := range []struct {
		name string
		into *time.Time
	}{{"from", &f.From}, {"to", &f.To}} {
		v := q.Get(bound.name)
		if v == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return RunFilter{}, fmt.Errorf("%w: %s=%q is not an RFC 3339 timestamp",
				ErrBadRequest, bound.name, v)
		}
		*bound.into = t
	}
	return f, nil
}

// alertFilterFrom reads the alerts feed's state out of the URL, matching
// runFilterFrom's shape and the query API's own parameter names.
func alertFilterFrom(r *http.Request) (AlertFilter, error) {
	q := r.URL.Query()
	f := AlertFilter{
		EventType: q.Get("event_type"),
		Cursor:    q.Get("cursor"),
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return AlertFilter{}, fmt.Errorf("%w: limit=%q is not a positive number", ErrBadRequest, v)
		}
		f.Limit = n
	}
	return f, nil
}

// writeProblem maps an error to a status. Only three kinds reach here: a
// request this API cannot make sense of, a thing it does not hold, and a
// failure of its own. A verification that could not run is none of them — it
// is a verdict, and it is served with a 200.
func writeProblem(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrBadRequest):
		writeError(w, http.StatusBadRequest, codeBadRequest, err.Error())
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, codeNotFound, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, codeInternal, err.Error())
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorEnvelope{Error: errorBody{Code: code, Message: message}})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	// A response that fails to encode has already had its status written;
	// there is nowhere left to report it but the connection, which closing
	// does. The bodies here are plain structs, so this cannot fire in practice.
	discardError(json.NewEncoder(w).Encode(body))
}
