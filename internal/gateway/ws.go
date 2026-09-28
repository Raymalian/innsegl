// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ws.go relays a WebSocket upgrade end to end (GW-009, #372): once
// Proxy.ServeHTTP's guard loop (guard.go) has let a request through, an
// Upgrade: websocket request is dispatched to relayWebSocket instead of the
// ordinary HTTP path -- see proxy.go's own dispatch, the only line that
// file gained for this. Guards running first, unconditionally, is what
// makes an unrecognised harness shape refused before any upgrade is even
// attempted, the same way it is already refused before an ordinary request
// is forwarded.
//
// relayWebSocket:
//
//   - dials the SAME upstream over TLS the ordinary HTTP path already
//     trusts -- reusing p.Upstream.Client's own *http.Transport's
//     TLSClientConfig (upstreamTLSConfig below) rather than building a
//     second TLS configuration, so the https-only, strict-verification
//     rules RM-226 (#371) already enforces apply to a WebSocket upgrade
//     too, with no InsecureSkipVerify anywhere in this file;
//   - relays the HTTP/1.1 upgrade handshake -- request line, every header
//     the caller sent (minus the small set of hop-by-hop headers that are
//     never Connection or Upgrade themselves -- see
//     stripHopByHopKeepingUpgrade), and the upstream's own status line and
//     headers back -- the same "nothing added, nothing dropped beyond
//     hop-by-hop" contract GW-001 already holds for ordinary requests;
//   - once both sides have switched protocols, copies WebSocket frames byte
//     for byte in both directions and hands each one (direction, opcode,
//     payload) to an optional FrameObserver before it is forwarded onward.
//     It parses only a frame's header -- opcode, length, mask -- never the
//     meaning of a payload; a harness's event format inside that payload is
//     E21's to parse, not this file's.
//
// No WebSocket library: go.mod carries none today, and doc 01 §7 prefers
// few dependencies. RFC 6455's frame format is a two-byte header plus an
// optional extended length and an optional mask, small enough that
// net/http.Hijacker plus a frame-boundary-aware byte copy -- the same
// witness-on-top-of-the-forwarded-bytes shape messagesInterpreter already
// uses in sse.go, applied to raw frames instead of SSE events -- covers
// this file's whole job: relay, never terminate or interpret.

// ---------------------------------------------------------------------------
// FrameObserver: what a caller sees.
// ---------------------------------------------------------------------------

// Direction names which way a relayed Frame travelled.
type Direction int

const (
	// ClientToUpstream: the harness sent this frame; it is on its way to
	// the model provider.
	ClientToUpstream Direction = iota
	// UpstreamToClient: the model provider sent this frame; it is on its
	// way back to the harness.
	UpstreamToClient
)

// Opcode is a WebSocket frame's own opcode (RFC 6455 §5.2), named rather
// than left as a bare integer so a FrameObserver never has to hardcode the
// RFC's numbering itself.
type Opcode uint8

// The RFC 6455 §5.2 opcodes this file relays. OpcodeContinuation appears on
// a fragment of a larger message; this file relays frames, not reassembled
// messages, so a fragmented message reaches a FrameObserver as the several
// frames it was sent as, exactly as the wire carried it.
const (
	OpcodeContinuation Opcode = 0x0
	OpcodeText         Opcode = 0x1
	OpcodeBinary       Opcode = 0x2
	OpcodeClose        Opcode = 0x8
	OpcodePing         Opcode = 0x9
	OpcodePong         Opcode = 0xA
)

// Frame is one WebSocket frame, as handed to a FrameObserver: which way it
// travelled, its opcode, and its payload exactly as decoded off the wire --
// unmasked, since a masked client frame and its content should read the
// same to an observer that has no reason to care about the wire-level
// masking RFC 6455 §5.3 requires only on the client-to-upstream leg. The
// bytes actually relayed are never altered by this decoding -- see this
// file's own doc comment.
type Frame struct {
	Direction Direction
	Opcode    Opcode
	Payload   []byte
}

// FrameObserver is notified of each Frame as it is relayed, in either
// direction. An implementation must return quickly -- the same reasoning
// ToolUseObserver's own doc comment gives in sse.go applies here unchanged:
// this runs on the path relaying the frame, after it has already been
// forwarded, so a slow observer is a slow relay. Unlike ToolUseObserver,
// OnFrame may be called concurrently from the two relay directions (one
// goroutine per direction, see relayFrames below); an observer that needs a
// single ordered view across both synchronizes itself.
type FrameObserver interface {
	OnFrame(Frame)
}

// FrameObserverFunc adapts an ordinary func to a FrameObserver.
type FrameObserverFunc func(Frame)

// OnFrame calls f.
func (f FrameObserverFunc) OnFrame(fr Frame) { f(fr) }

// ---------------------------------------------------------------------------
// Dispatch: what proxy.go calls.
// ---------------------------------------------------------------------------

// isWebSocketUpgrade reports whether r asks to switch to the WebSocket
// protocol (RFC 6455 §4.1): a GET request naming "websocket" in its Upgrade
// header and "Upgrade" among the tokens its Connection header lists -- both
// checked case-insensitively, since neither RFC 7230 §6.7 nor RFC 6455
// require a client to send an exact-case token.
func isWebSocketUpgrade(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, f := range r.Header.Values("Connection") {
		for _, tok := range strings.Split(f, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "Upgrade") {
				return true
			}
		}
	}
	return false
}

// relayWebSocket handles r after Proxy.ServeHTTP's guard loop has already
// let it through (see proxy.go's dispatch). w must be an http.Hijacker --
// every production ResponseWriter this gateway is handed is one, the same
// assumption Proxy.stream's flushWriter fallback already documents for
// http.Flusher in proxy.go; an unusual wrapper that is not one gets a clean
// JSON refusal instead of a panic.
func (p *Proxy) relayWebSocket(w http.ResponseWriter, r *http.Request) {
	tlsConfig, ok := upstreamTLSConfig(p.Upstream)
	if !ok {
		writeGatewayError(w, http.StatusBadGateway,
			"innsegl gateway: the upstream client has no TLS configuration to relay a WebSocket upgrade with")
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		writeGatewayError(w, http.StatusInternalServerError,
			"innsegl gateway: this server does not support hijacking a connection, so a WebSocket upgrade cannot be relayed")
		return
	}

	target := p.Upstream.resolve(r.URL.Path, r.URL.RawQuery)

	tlsDialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: upstreamDialTimeout}, Config: tlsConfig}
	upstreamNetConn, err := tlsDialer.DialContext(r.Context(), "tcp", hostWithDefaultPort(target))
	if err != nil {
		status, msg := classifyUpstreamError(err)
		writeGatewayError(w, status, msg)
		return
	}
	upstreamConn, ok := upstreamNetConn.(*tls.Conn)
	if !ok {
		// tls.Dialer.DialContext always returns a *tls.Conn on a nil error
		// -- this is defensive rather than reachable, and still refuses
		// cleanly rather than panicking on the type assertion below.
		writeGatewayError(w, http.StatusBadGateway,
			"innsegl gateway: the upstream dial did not return a TLS connection")
		return
	}
	defer func() { _ = upstreamConn.Close() }()

	if writeErr := writeUpgradeRequest(upstreamConn, r, target); writeErr != nil {
		status, msg := classifyUpstreamError(writeErr)
		writeGatewayError(w, status, msg)
		return
	}

	upstreamReader := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamReader, r)
	if err != nil {
		status, msg := classifyUpstreamError(err)
		writeGatewayError(w, status, msg)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		writeGatewayError(w, http.StatusBadGateway, fmt.Sprintf(
			"innsegl gateway: upstream declined the WebSocket upgrade (status %d)", resp.StatusCode))
		return
	}

	clientConn, clientRW, err := hj.Hijack()
	if err != nil {
		writeGatewayError(w, http.StatusInternalServerError,
			"innsegl gateway: could not hijack the client connection to relay a WebSocket upgrade: "+err.Error())
		return
	}
	defer func() { _ = clientConn.Close() }()

	if writeErr := writeSwitchingProtocolsResponse(clientRW.Writer, resp.Header); writeErr != nil {
		// The client is gone; nothing left to tell it -- the same reasoning
		// discardWriteError's own comment in proxy.go gives.
		return
	}

	relayFrames(clientRW.Reader, clientConn, upstreamReader, upstreamConn, p.Frames)
}

// upstreamTLSConfig extracts the *tls.Config the SAME Upstream.Client
// already uses for ordinary HTTP requests -- never a second one built here
// -- so a WebSocket upgrade is verified by the identical https-only,
// strict-certificate rules RM-226 (#371) already enforces. false means the
// given Upstream's Client carries no *http.Transport to extract one from (a
// caller-supplied http.RoundTripper of some other kind); relayWebSocket
// refuses cleanly rather than inventing a TLS configuration of its own.
func upstreamTLSConfig(up *Upstream) (*tls.Config, bool) {
	if up == nil || up.Client == nil {
		return nil, false
	}
	transport, ok := up.Client.Transport.(*http.Transport)
	if !ok || transport == nil {
		return nil, false
	}
	if transport.TLSClientConfig == nil {
		// http.Transport's own zero value dials with the same behaviour an
		// explicit empty tls.Config{} would: system roots, ordinary
		// verification. Handing back an explicit empty Config here reuses
		// that same behaviour rather than inventing a stricter or looser
		// one.
		return &tls.Config{}, true
	}
	return transport.TLSClientConfig, true
}

// hostWithDefaultPort returns target.Host with ":443" appended when target
// carries no explicit port. tls.DialWithDialer, unlike http.Client, needs a
// dial address rather than a URL, and an https upstream with no port in its
// base URL (the common case: https://api.anthropic.com) means 443, the same
// default net/http's own transport already assumes for an https request.
func hostWithDefaultPort(target *url.URL) string {
	if target.Port() != "" {
		return target.Host
	}
	return target.Host + ":443"
}

// wsHopByHopHeaders are stripped from a relayed WebSocket upgrade request,
// deliberately NOT including "Connection" or "Upgrade" -- unlike
// stripHopByHop (proxy.go), which strips both for ordinary HTTP because RFC
// 7230 §6.1 says a header a Connection header names is hop-by-hop by the
// sender's own declaration. Here, "Connection: Upgrade" and the Upgrade
// header itself are exactly what negotiates the switch to WebSocket with
// the upstream; dropping them would make an upgrade impossible to relay at
// all.
var wsHopByHopHeaders = []string{
	"Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding",
}

func stripHopByHopKeepingUpgrade(h http.Header) {
	for _, name := range wsHopByHopHeaders {
		h.Del(name)
	}
}

// writeUpgradeRequest sends r's upgrade handshake to conn, addressed at
// target: request line, then every header r carried (cloned first, so
// mutating it here never touches r's own headers -- the same reasoning
// buildRequest's own cloneHeader call already carries in proxy.go), minus
// wsHopByHopHeaders, with Host set to target's own host.
func writeUpgradeRequest(conn net.Conn, r *http.Request, target *url.URL) error {
	header := cloneHeader(r.Header)
	stripHopByHopKeepingUpgrade(header)
	header.Set("Host", target.Host)

	requestURI := target.EscapedPath()
	if requestURI == "" {
		requestURI = "/"
	}
	if target.RawQuery != "" {
		requestURI += "?" + target.RawQuery
	}

	bw := bufio.NewWriter(conn)
	if _, err := fmt.Fprintf(bw, "%s %s HTTP/1.1\r\n", r.Method, requestURI); err != nil {
		return err
	}
	if err := header.Write(bw); err != nil {
		return err
	}
	if _, err := bw.WriteString("\r\n"); err != nil {
		return err
	}
	return bw.Flush()
}

// writeSwitchingProtocolsResponse sends the upstream's own 101 response
// back to the client unchanged: same headers, in the same "every header
// forwarded" shape GW-001 already holds for an ordinary reply.
func writeSwitchingProtocolsResponse(w *bufio.Writer, header http.Header) error {
	if _, err := w.WriteString("HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
		return err
	}
	if err := header.Write(w); err != nil {
		return err
	}
	if _, err := w.WriteString("\r\n"); err != nil {
		return err
	}
	return w.Flush()
}

// ---------------------------------------------------------------------------
// Frame relay: the byte path, once both sides have switched protocols.
// ---------------------------------------------------------------------------

// relayFrames copies WebSocket frames in both directions until either side
// closes or errors, then closes both connections so the other direction's
// blocked read unblocks too -- the standard shape a bidirectional TCP relay
// uses to end cleanly on either side's disconnect.
func relayFrames(clientReader *bufio.Reader, clientConn net.Conn,
	upstreamReader *bufio.Reader, upstreamConn net.Conn, observer FrameObserver) {
	done := make(chan struct{}, 2)
	go func() {
		copyFrames(ClientToUpstream, clientReader, upstreamConn, observer)
		done <- struct{}{}
	}()
	go func() {
		copyFrames(UpstreamToClient, upstreamReader, clientConn, observer)
		done <- struct{}{}
	}()

	<-done
	_ = clientConn.Close()
	_ = upstreamConn.Close()
	<-done
}

// copyFrames reads frames from src and writes each one, unchanged, to dst,
// handing (direction, opcode, payload) to observer -- if one is set --
// after the frame has already been forwarded (the same "witness, not a
// gate" ordering messagesInterpreter already uses for SSE events). It
// returns on the first read or write error, including a clean EOF: the
// caller (relayFrames) treats that as this direction's own end.
func copyFrames(direction Direction, src *bufio.Reader, dst io.Writer, observer FrameObserver) {
	for {
		header, raw, err := readFrameHeader(src)
		if err != nil {
			return
		}
		if err := relayOneFrame(direction, header, raw, src, dst, observer); err != nil {
			return
		}
	}
}

// wsFrameHeader is a decoded RFC 6455 §5.2 frame header: enough to know the
// opcode, how many payload bytes follow, and whether they are masked --
// nothing about a frame's payload is ever interpreted beyond this. E21 is a
// harness's event format, and this file never parses one.
type wsFrameHeader struct {
	opcode  Opcode
	masked  bool
	maskKey [4]byte
	length  uint64
}

// readFrameHeader reads one frame's header from r, returning both the
// decoded fields and the exact bytes read -- raw is forwarded to the peer
// byte for byte by relayOneFrame, never re-encoded from the decoded fields,
// so a decoding bug here can never itself corrupt what is relayed.
func readFrameHeader(r *bufio.Reader) (wsFrameHeader, []byte, error) {
	var first [2]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return wsFrameHeader{}, nil, err
	}
	raw := append([]byte(nil), first[:]...)

	header := wsFrameHeader{
		opcode: Opcode(first[0] & 0x0f),
		masked: first[1]&0x80 != 0,
	}
	length := uint64(first[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return wsFrameHeader{}, nil, err
		}
		raw = append(raw, ext[:]...)
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return wsFrameHeader{}, nil, err
		}
		raw = append(raw, ext[:]...)
		length = binary.BigEndian.Uint64(ext[:])
	}
	header.length = length

	if header.masked {
		if _, err := io.ReadFull(r, header.maskKey[:]); err != nil {
			return wsFrameHeader{}, nil, err
		}
		raw = append(raw, header.maskKey[:]...)
	}
	return header, raw, nil
}

// wsFrameCopyChunk bounds how much of a frame's payload is read from the
// wire in one pass -- a streaming bound, not a size limit: a frame of any
// length is still relayed in full, in chunks this size, so this file never
// holds more of one frame in memory at once than this.
const wsFrameCopyChunk = 32 * 1024

// relayOneFrame forwards header's raw bytes and its declared payload from
// src to dst unchanged, then -- once the whole frame has already reached
// dst -- hands (direction, opcode, unmasked payload) to observer, if one is
// set. Nothing observer does can affect what was already written to dst;
// this is a witness on top of the forwarded bytes, never a gate in front of
// them, the same contract messagesInterpreter already holds for SSE events.
func relayOneFrame(direction Direction, header wsFrameHeader, raw []byte,
	src *bufio.Reader, dst io.Writer, observer FrameObserver) error {
	if _, err := dst.Write(raw); err != nil {
		return err
	}

	var observed []byte
	buf := make([]byte, wsFrameCopyChunk)
	remaining := header.length
	var maskPos int
	for remaining > 0 {
		n := uint64(len(buf))
		if remaining < n {
			n = remaining
		}
		if _, err := io.ReadFull(src, buf[:n]); err != nil {
			return err
		}
		chunk := buf[:n]
		if _, err := dst.Write(chunk); err != nil {
			return err
		}
		if observer != nil {
			unmasked := append([]byte(nil), chunk...)
			if header.masked {
				for i := range unmasked {
					unmasked[i] ^= header.maskKey[(maskPos+i)%4]
				}
			}
			observed = append(observed, unmasked...)
			maskPos += len(chunk)
		}
		remaining -= n
	}

	if observer != nil {
		if observed == nil {
			observed = []byte{}
		}
		observer.OnFrame(Frame{Direction: direction, Opcode: header.opcode, Payload: observed})
	}
	return nil
}
