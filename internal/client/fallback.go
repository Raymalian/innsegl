// SPDX-License-Identifier: Apache-2.0

package client

// The availability layer (ADR-0068). A model request goes to the core. When
// the core does not answer -- connect, TLS, a timeout, or a 5xx of its own
// (one that does not carry clientjournal.RecordedHeader, which the core sets
// on every reply it relays from the provider) -- the request goes to the
// provider directly, unchanged, and the reply streams to the harness as it
// arrives. Inside a repository the exchange is journaled; outside one there
// is nothing to attribute, and the bypass is logged. When the core relays
// an exchange and says it did not record it ("false"), the reply already
// streaming to the harness is journaled as it passes.
//
// Nothing here buffers a reply before forwarding it: the capture is a copy
// taken while the bytes go by.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"innsegl.dev/innsegl/internal/clientjournal"
)

// DefaultProviderURL is where a model request goes when the core does not
// answer, unless core.json names another.
const DefaultProviderURL = "https://api.anthropic.com"

// statementWait bounds how long a session's first model request waits for
// the session's statement. The hook states it within milliseconds of the
// session starting; a session with no hook waits this once.
const statementWait = 2 * time.Second

// DefaultCoreDownFor is how long, after the core failed to answer, model
// requests go to the provider without trying the core first.
const DefaultCoreDownFor = 15 * time.Second

// maxReplayableBytes bounds the request body held to resend it to the
// provider and to journal it. A larger request goes to the core alone.
const maxReplayableBytes = 16 << 20

// maxCaptureBytes bounds the reply journaled; past it the entry says the
// reply is incomplete.
const maxCaptureBytes = 16 << 20

// isModelPath reports whether path is model traffic the provider answers.
func isModelPath(path string) bool {
	return path == "/v1/messages" || strings.HasPrefix(path, "/v1/messages/")
}

// exchange is one model request held for a possible resend and journal.
type exchange struct {
	body      []byte
	header    http.Header
	method    string
	path      string
	query     string
	session   string
	agent     string
	statement json.RawMessage
	hasRepo   bool
	started   time.Time
}

type exchangeKey struct{}

func exchangeFrom(ctx context.Context) *exchange {
	if ex, ok := ctx.Value(exchangeKey{}).(*exchange); ok {
		return ex
	}
	return nil
}

// journalRefusal is a request that had to be journaled and could not be.
type journalRefusal struct{ err error }

func (j journalRefusal) Error() string { return j.err.Error() }
func (j journalRefusal) Unwrap() error { return j.err }

// errCoreFailed is the core's own 5xx.
type errCoreFailed struct{ status int }

func (e errCoreFailed) Error() string {
	return fmt.Sprintf("the core answered %d without relaying the request", e.status)
}

// serveModel handles one model request: held for a resend, then to the core,
// or straight to the provider while the core is known to be down.
func (s *Server) serveModel(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxReplayableBytes+1))
	if err != nil {
		http.Error(w, "innsegl client: reading the request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(body) > maxReplayableBytes {
		// Too large to hold: it goes to the core as it streams, and only there.
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(body), r.Body), r.Body}
		s.proxy.ServeHTTP(w, r)
		return
	}
	session := r.Header.Get("X-Claude-Code-Session-Id")
	agent := r.Header.Get("X-Claude-Code-Agent-Id")
	ex := &exchange{
		body: body, header: r.Header.Clone(), method: r.Method, path: r.URL.Path, query: r.URL.RawQuery,
		session: session, agent: agent, started: s.Now().UTC(),
	}
	if session != "" {
		if _, known := s.statements.lookup(session, ""); !known && s.awaited.first(session) {
			// The session's SessionStart hook states it at the same moment
			// Claude Code sends its first request; wait for the statement
			// once, so that request is recorded too.
			s.statements.awaitSession(r.Context(), session, statementWait)
		}
		ex.statement, ex.hasRepo = s.statements.statement(session, agent)
	}
	s.serveHeld(w, r.WithContext(context.WithValue(r.Context(), exchangeKey{}, ex)), ex)
}

// serveHeld sends a held model request: to the core, or straight to the
// provider while the core is known to be down.
func (s *Server) serveHeld(w http.ResponseWriter, r *http.Request, ex *exchange) {
	r.Body = io.NopCloser(bytes.NewReader(ex.body))
	r.ContentLength = int64(len(ex.body))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(ex.body)), nil }

	if s.coreDown() {
		s.forwardDirect(w, r, ex)
		return
	}
	s.flushOutboxBeforeLive(r.Context())
	s.proxy.ServeHTTP(w, r)
}

func (s *Server) coreDown() bool { return s.Now().UnixNano() < s.downUntil.Load() }

func (s *Server) markCoreDown() { s.downUntil.Store(s.Now().Add(s.coreDownFor).UnixNano()) }

// modifyResponse sorts the core's answer to a model request: its own 5xx
// is an outage (the proxy's ErrorHandler then forwards to the provider), a
// relayed exchange it did not record is journaled as it streams.
func (s *Server) modifyResponse(resp *http.Response) error {
	ex := exchangeFrom(resp.Request.Context())
	if ex != nil {
		recorded := resp.Header.Get(clientjournal.RecordedHeader)
		if resp.StatusCode >= 500 && recorded == "" {
			head, rerr := io.ReadAll(io.LimitReader(resp.Body, maxRefusalLogBytes))
			if rerr != nil {
				head = []byte("(unreadable: " + rerr.Error() + ")")
			}
			s.log.Printf("the core answered %s %s for session %s with %d: %s",
				resp.Request.Method, resp.Request.URL.Path, orNone(ex.session), resp.StatusCode, strings.TrimSpace(string(head)))
			return errCoreFailed{status: resp.StatusCode}
		}
		if s.downUntil.Swap(0) != 0 {
			// The core is back: deliver what it did not take meanwhile.
			s.kickOutbox()
		}
		s.countRecorded(recorded)
		if recorded == clientjournal.RecordedNone && ex.session != "" && s.unrecorded.first(ex.session) {
			// Once per session: what the core did not record, and whether a
			// statement went with it, so a gap is visible on the machine.
			s.log.Printf("the core recorded nothing for %s %s in session %s (class %q, statement attached: %v)",
				ex.method, ex.path, ex.session, resp.Request.Header.Get("X-Claude-Code-Request-Class"), len(ex.statement) > 0)
		}
		if recorded == clientjournal.RecordedFalse && ex.hasRepo {
			if err := s.outbox.reserve(int64(len(ex.body))); err != nil {
				return journalRefusal{err}
			}
			resp.Body = s.capture(resp, ex, clientjournal.ReasonCoreNotRecorded)
		}
	}
	return s.explainRefusal(resp)
}

// proxyError is the reverse proxy's ErrorHandler: the core did not answer.
func (s *Server) proxyError(w http.ResponseWriter, r *http.Request, err error) {
	var refusal journalRefusal
	if errors.As(err, &refusal) {
		s.refuseUnjournaled(w, r, refusal.err)
		return
	}
	if r.URL.Path == SessionStatementPath {
		s.keepStatement(w, r, err)
		return
	}
	ex := exchangeFrom(r.Context())
	if ex != nil && r.Context().Err() == nil {
		s.markCoreDown()
		s.log.Printf("the core at %s did not answer %s for session %s (%v); forwarding to the provider directly "+
			"for the next %s", s.core.CoreURL, r.URL.Path, orNone(ex.session), err, s.coreDownFor)
		s.forwardDirect(w, r, ex)
		return
	}
	s.log.Printf("forwarding to %s: %v", s.core.CoreURL, err)
	http.Error(w, fmt.Sprintf("innsegl client: the core at %s did not answer: %v", s.core.CoreURL, err), http.StatusBadGateway)
}

// refuseUnjournaled is the one refusal: a request that must be journaled
// when the outbox cannot hold it.
func (s *Server) refuseUnjournaled(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Printf("refusing %s %s for session %s: the core cannot record it and the client outbox cannot "+
		"hold it: %v", r.Method, r.URL.Path, orNone(exchangeSession(r)), err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	msg, merr := json.Marshal(map[string]string{"error": "innsegl client: this request is in a recorded repository, " +
		"the core cannot record it now, and the client outbox cannot hold it (" + err.Error() + "). " +
		"Nothing was sent. Free space for the outbox or bring the core back; GET " + StatusPath + " shows the outbox."})
	if merr != nil {
		msg = []byte(`{"error":"innsegl client: the client outbox cannot hold this request; nothing was sent"}`)
	}
	if _, werr := w.Write(msg); werr != nil {
		s.log.Printf("writing the refusal: %v", werr)
	}
}

func exchangeSession(r *http.Request) string {
	if ex := exchangeFrom(r.Context()); ex != nil {
		return ex.session
	}
	return ""
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// hopByHop headers are the connection's own, never forwarded.
var hopByHop = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func stripHopByHop(h http.Header) {
	for _, f := range h.Values("Connection") {
		for _, name := range strings.Split(f, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range hopByHop {
		h.Del(name)
	}
}

// forwardDirect sends the held request to the provider, unchanged but for
// the statement (the core's, never the provider's) and the encoding (plain,
// so the reply can be journaled), and streams the reply back.
func (s *Server) forwardDirect(w http.ResponseWriter, r *http.Request, ex *exchange) {
	if ex.hasRepo {
		if err := s.outbox.reserve(int64(len(ex.body))); err != nil {
			s.refuseUnjournaled(w, r, err)
			return
		}
	} else {
		s.logBypass(ex)
	}
	target := *s.provider
	target.Path = strings.TrimSuffix(target.Path, "/") + ex.path
	target.RawQuery = ex.query
	out, err := http.NewRequestWithContext(r.Context(), ex.method, target.String(), bytes.NewReader(ex.body))
	if err != nil {
		http.Error(w, "innsegl client: building the provider request: "+err.Error(), http.StatusBadGateway)
		return
	}
	out.Header = ex.header.Clone()
	stripHopByHop(out.Header)
	out.Header.Del(StatementHeader)
	out.Header.Set("Accept-Encoding", "identity")
	out.ContentLength = int64(len(ex.body))
	resp, err := s.providerClient.Do(out)
	if err != nil {
		s.log.Printf("the provider at %s did not answer either: %v", s.provider.Host, err)
		http.Error(w, fmt.Sprintf("innsegl client: neither the core nor the provider at %s answered: %v", s.provider.Host, err),
			http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	body := resp.Body
	if ex.hasRepo {
		body = s.capture(resp, ex, clientjournal.ReasonCoreUnreachable)
		defer func() { _ = body.Close() }()
	}
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	stripHopByHop(w.Header())
	w.WriteHeader(resp.StatusCode)
	flusher, ok := w.(http.Flusher)
	if !ok {
		flusher = nil
	}
	buf := make([]byte, 32<<10)
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if rerr != nil {
			return
		}
	}
}

// logBypass notes, once per session, a model request forwarded to the
// provider with nothing to record it under.
func (s *Server) logBypass(ex *exchange) {
	if !s.bypassed.first(ex.session) {
		return
	}
	s.log.Printf("finding: session %s states no repository and the core did not answer; its model requests "+
		"go to the provider directly, unrecorded, until the core answers", orNone(ex.session))
}

// capture copies a reply as it streams and journals the exchange when the
// reply ends: at its end, completely; at a close before its end, as far as
// it went.
func (s *Server) capture(resp *http.Response, ex *exchange, reason string) io.ReadCloser {
	return &capturingBody{src: resp.Body, s: s, ex: ex, reason: reason, status: resp.StatusCode, header: resp.Header.Clone()}
}

type capturingBody struct {
	src       io.ReadCloser
	s         *Server
	ex        *exchange
	reason    string
	status    int
	header    http.Header
	buf       bytes.Buffer
	truncated bool
	once      sync.Once
}

func (c *capturingBody) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	if n > 0 {
		if room := maxCaptureBytes - c.buf.Len(); room > 0 {
			c.buf.Write(p[:min(n, room)])
			if n > room {
				c.truncated = true
			}
		} else {
			c.truncated = true
		}
	}
	if errors.Is(err, io.EOF) {
		c.finish(true)
	}
	return n, err
}

func (c *capturingBody) Close() error {
	c.finish(false)
	return c.src.Close()
}

func (c *capturingBody) finish(complete bool) {
	c.once.Do(func() {
		e := clientjournal.Entry{
			SessionID: c.ex.session, AgentID: c.ex.agent, Reason: c.reason, Statement: c.ex.statement,
			Method: c.ex.method, Path: c.ex.path, Query: c.ex.query,
			RequestHeaders: clientjournal.KeptHeaders(c.ex.header), RequestBody: c.ex.body,
			ResponseStatus: c.status, ResponseHeaders: clientjournal.KeptHeaders(c.header),
			ResponseBody: c.buf.Bytes(), ResponseComplete: complete && !c.truncated,
			StartedAt: c.ex.started, EndedAt: c.s.Now().UTC(),
		}
		sealed, err := c.s.outbox.appendExchange(e)
		if err != nil {
			c.s.log.Printf("LOST: the exchange of session %s could not be written to the client outbox: %v",
				orNone(c.ex.session), err)
			return
		}
		c.s.log.Printf("journaled %s %s for session %s (%s) as %s", c.ex.method, c.ex.path, orNone(c.ex.session), c.reason, sealed.Hash())
		c.s.kickOutbox()
	})
}

// seenSet remembers, bounded, which keys were seen.
type seenSet struct {
	mu    sync.Mutex
	max   int
	order []string
	seen  map[string]bool
}

func newSeenSet(capacity int) *seenSet { return &seenSet{max: capacity, seen: map[string]bool{}} }

func (s *seenSet) first(k string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen[k] {
		return false
	}
	if len(s.order) >= s.max {
		delete(s.seen, s.order[0])
		s.order = s.order[1:]
	}
	s.order = append(s.order, k)
	s.seen[k] = true
	return true
}

// statement answers the statement in force for (session, agent), decoded,
// and whether it states a repository.
func (c *statementCache) statement(sessionID, agentID string) (json.RawMessage, bool) {
	v, ok := c.lookup(sessionID, agentID)
	if !ok {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return nil, false
	}
	var in struct {
		Repo string `json:"repo"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, false
	}
	return raw, in.Repo != ""
}

// providerTransport is the direct route's transport: the system roots, and
// a bounded connect. It never reads the proxy environment: the client is
// the proxy (RM-329), and started from a shell that names it, it would
// send its own traffic to itself.
func providerTransport() *http.Transport {
	return &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
}

// parseProvider checks the provider URL: https only.
func parseProvider(raw string) (*url.URL, error) {
	if raw == "" {
		raw = DefaultProviderURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("provider URL %q is not an https URL", raw)
	}
	return u, nil
}
