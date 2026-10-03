// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/clientjournal"
)

// hopByHopHeaders are stripped before forwarding, per RFC 7230 §6.1 --
// these name the connection between one pair of endpoints and have no
// business surviving a hop. Every other header, Authorization and any
// provider API key included, passes through unchanged: a caller's
// credential is not this gateway's to touch, and this package never logs
// or persists a header, on either side of the relay.
var hopByHopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// Proxy is an HTTP reverse proxy. ServeHTTP forwards every request to
// Upstream unchanged -- method, path and query, headers including
// credentials, body -- and streams the reply back as it arrives, flushing
// after every chunk it forwards so a server-sent-events reply is never
// buffered.
type Proxy struct {
	Upstream *Upstream

	// ToolUse, set or nil. While an Anthropic Messages reply streams, each
	// tool_use content block is handed to it as soon as its
	// content_block_stop event arrives -- before the reply finishes -- so a
	// later consumer (identity and record work, #37x) can act on a tool
	// call without waiting for the whole response. See sse.go. Nil means
	// nobody is watching, and streaming is unaffected either way: the bytes
	// forwarded to the caller never depend on whether this is set.
	ToolUse ToolUseObserver

	// ReplyText, when set, is handed each streamed reply's own text once
	// the message ends (sse.go's ReplyTextObserver). Nil hands nothing.
	ReplyText ReplyTextObserver
	// SubagentEnds, when set, is told when a subagent's reply ends its work:
	// stop_reason end_turn, with no tool asked for. Nil tells nothing.
	SubagentEnds SubagentEndRecorder

	// Guards run in order, before anything else ServeHTTP does. The first
	// to refuse ends the request there -- see guard.go for the interface
	// and for what plugs into it (#375, E15). Nil uses defaultGuards, which
	// includes the harness-shape guard (GW-011): a Proxy refuses an
	// unrecognised harness shape by default, wherever one is constructed,
	// with no wiring needed at the call site. An explicit empty slice
	// (Guards: []Guard{}) opts out of every default guard.
	Guards []Guard

	// Frames, set or nil. When an incoming request upgrades to a WebSocket
	// connection (GW-009, #372, see ws.go), every frame relayed in either
	// direction is handed to it after that frame has already been
	// forwarded. Nil means nobody is watching, and relaying is unaffected
	// either way -- the same shape ToolUse already has for an Anthropic
	// Messages reply.
	Frames FrameObserver
}

// ServeHTTP builds the outbound request, sends it, and streams the reply
// back. An upstream that cannot be reached, or that refuses the connection
// outright, gets a JSON error body naming innsegl and a 5xx status -- never
// a dropped connection with nothing said about why. Once the reply's own
// status and headers have been written, this is no longer possible (HTTP
// itself has no way to change a status after the fact); what happens then
// is exactly what forwarding those bytes as they arrive requires -- the
// connection ends when the upstream's does.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Guards run first, before anything else this method does -- see
	// guard.go. Nil (the zero value) uses defaultGuards, so a Proxy refuses
	// an unrecognised harness shape (GW-011) wherever one is constructed,
	// with no wiring needed at the call site; an explicit empty slice opts
	// out of every default guard.
	guards := p.Guards
	if guards == nil {
		guards = defaultGuards
	}
	for _, g := range guards {
		next, refusal := g.Check(r)
		if refusal != nil {
			if refusal.RetryAfter > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(int((refusal.RetryAfter+time.Second-1)/time.Second)))
			}
			writeGatewayError(w, refusal.Status, refusal.Reason)
			return
		}
		if next != nil {
			r = next
		}
	}

	// A WebSocket upgrade is relayed by ws.go instead of the ordinary HTTP
	// path below (GW-009, #372) -- dispatched here, after every guard has
	// already run, so an unrecognised harness shape is refused (GW-011)
	// before any upgrade is attempted, exactly as it already is before an
	// ordinary request is forwarded.
	if isWebSocketUpgrade(r) {
		p.relayWebSocket(w, r)
		return
	}

	outReq, err := p.buildRequest(r)
	if err != nil {
		writeGatewayError(w, http.StatusBadGateway,
			"innsegl gateway: could not build the upstream request: "+err.Error())
		return
	}

	resp, err := p.Upstream.Client.Do(outReq)
	if err != nil {
		// classifyUpstreamError (upstream.go, #371/GW-008) turns a TLS,
		// connect or timeout failure into the status and failure-class
		// message the caller gets -- never the raw err.Error(), which can
		// carry transport-internal detail this response has no business
		// repeating.
		status, msg := classifyUpstreamError(err)
		writeGatewayError(w, status, msg)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	copyHeader(w.Header(), resp.Header)
	// ADR-0068: the core says whether it recorded this exchange, and only
	// the core says it -- an upstream's own value never reaches the client.
	w.Header().Set(clientjournal.RecordedHeader, recordedValue(r.Context()))
	w.WriteHeader(resp.StatusCode)

	p.stream(w, r, resp)
}

// buildRequest constructs the exact request to send upstream: same method,
// same path and query (against the upstream's own base), same headers
// (hop-by-hop ones stripped, per RFC 7230), same body, streamed rather than
// buffered so an arbitrarily large request is never held in memory here.
func (p *Proxy) buildRequest(r *http.Request) (*http.Request, error) {
	target := p.Upstream.resolve(r.URL.Path, r.URL.RawQuery)

	//nolint:gosec // G704: the target IS the configured upstream (Upstream.resolve),
	// only the path and query come from the request -- forwarding a caller's
	// request to a configured, operator-set upstream is this package's whole
	// job (ADR-0057). #371 adds the https-only and certificate-strictness
	// rule this construction does not yet enforce.
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), r.Body)
	if err != nil {
		return nil, err
	}
	outReq.Header = cloneHeader(r.Header)
	stripHopByHop(outReq.Header)
	// The client service's statement is for the core alone (RM-313): it
	// names a host path, which is not the provider's to see.
	outReq.Header.Del(StatementHeader)
	// The reply is read here as well as relayed (stream, below), and a
	// compressed one reads as nothing: Claude Code asks for gzip, br and
	// zstd. Identity is the one encoding every client accepts, so the
	// upstream is asked for that and the client gets plain bytes.
	outReq.Header.Set("Accept-Encoding", "identity")
	// ContentLength is not a header net/http reads back out of outReq.Header
	// -- it is this field, and copying it is what keeps a request with a
	// known length from being resent as chunked, which the byte-identical
	// contract (GW-001) depends on.
	outReq.ContentLength = r.ContentLength
	outReq.Host = target.Host
	return outReq, nil
}

// stream copies resp's body to w, flushing after every chunk arrives so a
// streamed reply -- server-sent events above all -- reaches the caller as
// it is received rather than once the whole body has arrived. When an
// Anthropic Messages tool_use observer is configured and the reply is
// text/event-stream, a second writer parses a COPY of the same bytes
// io.Copy already wrote to the client: see messagesInterpreter, whose Write
// never errors and so never slows or interrupts the forwarding it rides
// alongside.
//
// r is the ORIGINAL request this reply answers -- carried through only so
// that a ToolUse observer implementing ContextToolUseObserver (below) can
// read what an earlier Guard already attached to r's context (E15, #380:
// the identity guard's own run id, for the tool-use spawn recorder that
// feeds TreeLinker.RecordSpawn with the PARENT's run id). Nothing about the
// bytes forwarded to the caller depends on r; it is never read from again.
func (p *Proxy) stream(w http.ResponseWriter, r *http.Request, resp *http.Response) {
	var dst io.Writer
	if flusher, ok := w.(http.Flusher); ok {
		dst = flushWriter{w: w, flusher: flusher}
	} else {
		// Every production ResponseWriter this gateway is handed is a
		// Flusher (net/http's server implementation always is); this is a
		// defensive fallback for an unusual wrapper that is not, and it
		// still forwards every byte -- just without an explicit Flush call
		// after each one.
		dst = w
	}

	if obs := p.replyObserver(r, resp.Header.Get("Content-Type")); obs != nil {
		dst = io.MultiWriter(dst, obs)
	}

	// A failed copy is discarded deliberately, not silently: by the time
	// streaming begins the reply's status and headers are already on the
	// wire, so there is nothing left to change, and this package logs
	// nothing here either way (see the package doc comment on what never
	// reaches a log). See discardCopyError.
	discardCopyError(io.Copy(dst, resp.Body))
}

// ContextToolUseObserver is a ToolUseObserver that also wants the request's
// own context -- the seam #380's tool-use spawn recorder needs, without
// widening ToolUseObserver's own interface (sse.go) for every observer that
// does not. p.ToolUse stays typed as plain ToolUseObserver, so every
// existing caller that hands it a bare ToolUseObserverFunc is unaffected;
// only an observer that additionally implements this interface is handed
// the context boundToolUseObserver wraps it in.
type ContextToolUseObserver interface {
	ToolUseObserver
	// OnToolUseContext is called instead of OnToolUse when the observer
	// implements this interface. ctx is the request's own context, exactly
	// as HarnessGuard, the identity guard and any other Guard in the chain
	// left it after Proxy.ServeHTTP's guards ran.
	OnToolUseContext(ctx context.Context, t ToolUse)
}

// boundToolUseObserver adapts observer so a messagesInterpreter -- which
// only ever calls the plain ToolUseObserver.OnToolUse -- reaches
// OnToolUseContext instead, carrying ctx, whenever observer implements
// ContextToolUseObserver. An observer that does not is called exactly as
// before.
func boundToolUseObserver(ctx context.Context, observer ToolUseObserver) ToolUseObserver {
	if ctxObserver, ok := observer.(ContextToolUseObserver); ok {
		return ToolUseObserverFunc(func(t ToolUse) { ctxObserver.OnToolUseContext(ctx, t) })
	}
	return observer
}

// discardCopyError is the named discard stream's io.Copy result gets, so
// the discard is visible and explained rather than a bare `_, _ =`.
func discardCopyError(int64, error) {}

// flushWriter flushes the underlying http.ResponseWriter after every Write,
// which is what keeps a chunked or event-stream reply from sitting in a
// buffer waiting for more data that may not arrive for a while (GW-002).
type flushWriter struct {
	w       io.Writer
	flusher http.Flusher
}

func (fw flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if fw.flusher != nil {
		fw.flusher.Flush()
	}
	return n, err
}

// isEventStream reports whether contentType names text/event-stream,
// parameters (a charset, most often) and all.
func isEventStream(contentType string) bool {
	base, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return base == "text/event-stream"
}

// cloneHeader deep-copies h so mutating the result (stripHopByHop) never
// touches the original request's own headers.
func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vv := range h {
		out[k] = append([]string(nil), vv...)
	}
	return out
}

// stripHopByHop removes RFC 7230 §6.1's hop-by-hop headers from h, along
// with any header the Connection header itself names -- a header that is
// hop-by-hop by the sender's own declaration and not only by a fixed list.
func stripHopByHop(h http.Header) {
	for _, f := range h.Values("Connection") {
		for _, name := range strings.Split(f, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

// copyHeader adds every value of every header in src to dst, preserving
// repeated headers, then strips what stripHopByHop always strips: a
// gateway manages its OWN connection to the caller, not the upstream's, so
// the upstream's Connection header (and anything it names) is never this
// gateway's to forward.
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
	stripHopByHop(dst)
}

// gatewayErrorBody is the JSON body an upstream failure gets instead of a
// dropped connection (GW-008). The failure-class vocabulary itself --
// "upstream certificate rejected", "upstream connection refused", "upstream
// request timed out" -- is classifyUpstreamError's, in upstream.go; this is
// the minimal clean response IP §6.3's "no indefinite hang, no silent
// drop" reasoning already requires of every other component in this
// codebase, extended to the one new component that did not exist to need
// it before.
type gatewayErrorBody struct {
	Error string `json:"error"`
}

func writeGatewayError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body, err := json.Marshal(gatewayErrorBody{Error: msg})
	if err != nil {
		// json.Marshal on a struct holding one string field cannot fail;
		// this is defensive rather than reachable, and still writes
		// SOMETHING naming innsegl rather than leaving the body empty.
		body = []byte(`{"error":"innsegl gateway: the upstream failed and the error could not be encoded"}`)
	}
	// Discarded deliberately: a write failure here means the caller has
	// already gone, and there is nothing left to tell it. See
	// discardCopyError's own comment for the same reasoning.
	discardWriteError(w.Write(body))
}

// discardWriteError is writeGatewayError's named discard for the same
// reason discardCopyError exists: visible and explained, not a bare `_, _ =`.
func discardWriteError(int, error) {}
