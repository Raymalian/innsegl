// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
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

// ServerConfig is the query API's halves: the read-only ledger index, the
// live proof BFF, and — RM-260/RM-261, ADR-0062 — the sign-in surface that
// gates every one of them.
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

	// AuthStore holds RM-260/RM-261's users/passkeys/sessions — required,
	// the same way Store and Prover are: a server with no way to check a
	// session cannot be constructed at all, which is deny-by-default applied
	// one level up from the route table (ADR-0062).
	AuthStore *AuthStore
	// WebAuthn configures the relying party (RP ID, RP origin, display
	// name). Required.
	WebAuthn WebAuthnConfig
	// SessionLifetime bounds a session's server-side life. Zero applies
	// defaultSessionLifetime.
	SessionLifetime time.Duration

	// Resolver is RM-330's resolver credential (ADR-0044's 2026-10-03
	// amendment): the one credential this process holds that may write, and
	// only an alert resolution. Optional. Nil answers both resolution routes
	// 503 and leaves `innsegl resolve-alert` as the way to resolve.
	Resolver *Resolver

	// Organisations is the accounts spine (RM-333, #511): the user's
	// organisations, their machines and repositories, and the passkey-gated
	// mint and revoke. Optional. Nil answers the account page's organisation
	// routes 503 and lists no organisations.
	Organisations Organisations
	// CoreCACertFile is the gateway's CA certificate (PEM), whose
	// fingerprint the account page's connect command pins. Empty: the page
	// shows a placeholder instead.
	CoreCACertFile string
}

// Health is what an operator reads to see that "read-only" is a measured fact
// rather than a claim. It is the report Open gathered from the server itself.
//
// It names no repository. A health probe says whether the service is up; a
// list of the repositories it serves would tell anyone who can reach the probe
// which projects exist (#309).
type Health struct {
	Database ReadOnlyReport `json:"database"`
	// Auth is RM-260/RM-261's own measured fact, served the same way: the
	// auth-writer credential's own proof that it cannot write the ledger
	// (ADR-0062: "verified by a startup probe the same way AssertReadOnly
	// already is"), and whether any user has enrolled yet — a plain boolean
	// (AB-27's own "no oracle" discipline).
	Auth AuthHealth `json:"auth"`
	// Resolver is RM-330's own measured fact: what the resolver credential
	// was proved able to do at start-up. Absent when none is configured.
	Resolver *ResolverReport `json:"resolver,omitempty"`
}

// AuthHealth is the sign-in surface's own share of GET /api/v1/health, which
// is allow-listed and answers with no session.
type AuthHealth struct {
	CannotWriteLedger ReadOnlyReport `json:"cannot_write_ledger"`
	Enrolled          bool           `json:"enrolled"`
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

// Error codes, spelled once. codeForbidden and codeUnauthorized are in
// authhandlers.go, spelled once for the sign-in surface the same way.
const (
	codeBadRequest = "bad_request"
	codeNotFound   = "not_found"
	codeInternal   = "internal"
	// codeUnavailable is a write this server cannot make right now: no
	// resolver credential, or a ledger that did not take it (RM-330).
	codeUnavailable = "unavailable"
)

// authAllowedRoutes is ADR-0062's explicit, reviewed allow-list: the only
// read routes that answer with no session. Everything else registered on
// s.mux — today's runs/overview/alerts/proof-for-stored-content routes, and
// whatever registerRecordRoutes adds — is refused without one. A route is
// matched by the exact pattern Go's own http.ServeMux.Handler resolves it
// to, the same pattern the mux itself dispatches on, so this list cannot
// drift from what is actually registered the way a hand-parsed path prefix
// could.
//
//   - GET /api/v1/health — and a future readiness route, should one exist —
//     names no repository and no stored content (see Health's own doc
//     comment).
//   - GET /api/v1/proof/{commit_sha} — the public paste-a-SHA verification
//     page's live three-check path. proof.go's own package doc comment:
//     "IT NEVER CONSULTS THE LEDGER. A Prover holds no Store, no pool and no
//     DSN." This is the ADR's "no path to the body store... or any other
//     stored content", by construction rather than by review alone.
//
// TestAUTH001ADenyByDefaultRouteRegisteredWithNoDecisionIsRefused proves the
// inverse: a route added to s.mux and left OFF this list is refused, not
// silently admitted.
var authAllowedRoutes = map[string]bool{
	"GET /api/v1/health":             true,
	"GET /api/v1/proof/{commit_sha}": true,
}

// Server is the query API's HTTP surface: read-only over the ledger, and —
// ADR-0062 — refuses to answer any of it without a session.
type Server struct {
	store     *Store
	prover    *Prover
	mux       *http.ServeMux
	logDir    string
	logRetain int

	authStore       *AuthStore
	authMux         *http.ServeMux
	accountMux      *http.ServeMux
	resolutionMux   *http.ServeMux
	resolver        *Resolver
	orgs            Organisations
	coreCACertFile  string
	webAuthn        *webauthn.WebAuthn
	webAuthnConfig  WebAuthnConfig
	sessionLifetime time.Duration
}

// NewServer wires the routes. It refuses to construct at all without a way
// to check a session — deny-by-default applied one level above the route
// table: a *Server with no AuthStore could not gate anything it went on to
// register, so it is never allowed to exist.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("%w: a query API with no store can answer nothing", ErrBadRequest)
	}
	if cfg.Prover == nil {
		return nil, fmt.Errorf("%w: a query API with no prover would have to answer "+
			"verification questions out of the database, which IP §6.11 forbids", ErrBadRequest)
	}
	if cfg.AuthStore == nil {
		return nil, fmt.Errorf("%w: a query API with no AuthStore could not check a "+
			"session for a single route, so ADR-0062's deny-by-default gate could not "+
			"be enforced; this server refuses to exist rather than serve open", ErrBadRequest)
	}
	webAuthn, err := newWebAuthn(cfg.WebAuthn)
	if err != nil {
		return nil, err
	}
	retain := cfg.LogRetentionDays
	if retain <= 0 {
		retain = 90
	}
	sessionLifetime := cfg.SessionLifetime
	if sessionLifetime <= 0 {
		sessionLifetime = defaultSessionLifetime
	}

	s := &Server{
		store: cfg.Store, prover: cfg.Prover, mux: http.NewServeMux(),
		logDir: cfg.LogDir, logRetain: retain,
		authStore: cfg.AuthStore, webAuthn: webAuthn,
		webAuthnConfig:  cfg.WebAuthn,
		sessionLifetime: sessionLifetime,
		resolver:        cfg.Resolver,
		orgs:            cfg.Organisations,
		coreCACertFile:  cfg.CoreCACertFile,
	}
	s.authMux = s.newAuthMux()
	s.accountMux = s.newAccountMux()
	s.resolutionMux = s.newResolutionMux()

	s.mux.HandleFunc("GET /api/v1/runs", s.handleRuns)
	s.mux.HandleFunc("GET /api/v1/runs/{run_id}", s.handleRun)
	s.mux.HandleFunc("GET /api/v1/runs/{run_id}/log", s.handleRunLog)
	s.mux.HandleFunc("GET /api/v1/overview", s.handleOverview)
	s.mux.HandleFunc("GET /api/v1/repos", s.handleRepos)
	s.mux.HandleFunc("GET /api/v1/alerts", s.handleAlerts)
	s.mux.HandleFunc("GET /api/v1/proof/{commit_sha}", s.handleProof)
	s.mux.HandleFunc("GET /api/v1/attribution/{commit_sha}", s.handleAttribution)
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	// The run record and step diff routes (#395, #396; recordhandler.go).
	// Called here, before NewServer
	// returns, so anything it adds is on s.mux from the start and is
	// therefore gated by ServeHTTP exactly like every route above: nothing
	// about being added later, by a different change, exempts it.
	s.registerRecordRoutes()
	return s, nil
}

// ServeHTTP is ADR-0062's gate. Two surfaces, two different rules:
//
//   - authRoutePrefix (the sign-in surface itself) is the ONE place this
//     package answers a non-GET method — see serveAuth for its own origin
//     check, the thing that actually protects it.
//   - everything else is read-only (GET/HEAD/OPTIONS only, as before #409)
//     AND refuses to answer without a session UNLESS its exact matched
//     pattern is in authAllowedRoutes.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if strings.HasPrefix(r.URL.Path, authRoutePrefix) {
		s.serveAuth(w, r)
		return
	}
	// #445: the account surface, mounted the same way the sign-in surface
	// is — its own prefix, its own method set, served before the read-only
	// mux's GET-only switch below ever runs. Unlike authRoutePrefix, every
	// route here requires a session (serveAccount enforces it itself); there
	// is no public account route.
	if strings.HasPrefix(r.URL.Path, accountRoutePrefix) {
		s.serveAccount(w, r)
		return
	}
	// RM-330: resolving alerts, after a fresh passkey ceremony, through the
	// resolver credential. The read-only mux below never sees these paths and
	// stays GET-only.
	if strings.HasPrefix(r.URL.Path, resolutionRoutePrefix+"/") {
		s.serveResolutions(w, r)
		return
	}

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

	// Deny-by-default (ADR-0062, #410): a route answers only by matching
	// authAllowedRoutes' exact pattern, using the SAME pattern-matching
	// http.ServeMux itself will dispatch on (Handler, not ServeHTTP, so this
	// is a lookup and not a second dispatch) — a route registered on s.mux
	// and never added to the list is therefore refused, not silently
	// admitted, however it got onto the mux.
	if _, pattern := s.mux.Handler(r); !authAllowedRoutes[pattern] {
		if _, _, ok := s.sessionFromRequest(r); !ok {
			writeError(w, http.StatusUnauthorized, codeUnauthorized,
				"sign in required (ADR-0062): this dashboard and its read API answer "+
					"nothing without an operator session")
			return
		}
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
// the two alert event types. Read-only like every other route on this mux;
// resolutions are written by alertresolutions.go's own surface, through the
// resolver credential (ADR-0044's 2026-10-03 amendment).
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

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	enrolled, err := s.authStore.EnrolmentOpen(r.Context())
	// EnrolmentOpen reports the door being OPEN; health reports the
	// opposite sense ("has anyone enrolled") because that is the fact a
	// reader of this endpoint actually wants. A query failure here answers
	// "not enrolled" rather than failing the whole health response — this
	// endpoint is on ADR-0062's own allow-list and must keep answering.
	health := Health{
		Database: s.store.ReadOnly(),
		Auth: AuthHealth{
			CannotWriteLedger: s.authStore.CannotWriteLedger(),
			Enrolled:          err == nil && !enrolled,
		},
	}
	if s.resolver != nil {
		scope := s.resolver.Scope()
		health.Resolver = &scope
	}
	writeJSON(w, http.StatusOK, health)
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
		Activity:  q.Get("activity"),
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
