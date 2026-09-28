// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1" // RFC 6455 §1.3's own handshake hash, not a security use of SHA-1; gosec is excluded from _test.go files (.golangci.yml).
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// GW-009: a WebSocket upgrade is relayed to the same upstream ordinary HTTP
// traffic goes to, over the same TLS trust; frames round-trip byte for byte
// in both directions; every frame reaches an optional FrameObserver; and an
// unrecognised harness shape is refused by the guards before any upgrade is
// attempted.
//
// These helpers are deliberately independent of ws.go's own frame codec --
// they encode and decode RFC 6455 frames from scratch -- so a bug shared
// between the production encoder and a test decoder built the same way
// could not hide a fidelity break from these tests.
// ---------------------------------------------------------------------------

const wsAcceptGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// wsAcceptKey computes RFC 6455 §1.3's Sec-WebSocket-Accept value for key.
func wsAcceptKey(key string) string {
	sum := sha1.Sum([]byte(key + wsAcceptGUID)) // same RFC 6455 handshake hash as above.
	return base64.StdEncoding.EncodeToString(sum[:])
}

// testWSFrame is one decoded frame, independent of ws.go's own Frame type,
// for a test to compare against what it sent or expects to receive.
type testWSFrame struct {
	opcode  byte
	payload []byte
}

// writeTestWSFrame encodes and writes a single, unfragmented RFC 6455 frame.
// masked is true for a client's own frames (RFC 6455 §5.1: a client MUST
// mask every frame it sends) and false for a server's.
func writeTestWSFrame(w io.Writer, opcode byte, payload []byte, masked bool) error {
	var buf bytes.Buffer
	buf.WriteByte(0x80 | opcode) // FIN=1, no fragmentation in these tests

	maskBit := byte(0)
	if masked {
		maskBit = 0x80
	}
	switch {
	case len(payload) < 126:
		buf.WriteByte(maskBit | byte(len(payload)))
	case len(payload) <= 0xFFFF:
		buf.WriteByte(maskBit | 126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(len(payload))) // bounded by the case above (<= 0xFFFF).
		buf.Write(ext[:])
	default:
		buf.WriteByte(maskBit | 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(len(payload)))
		buf.Write(ext[:])
	}

	out := payload
	if masked {
		var key [4]byte
		if _, err := rand.Read(key[:]); err != nil {
			return err
		}
		buf.Write(key[:])
		out = make([]byte, len(payload))
		for i, b := range payload {
			out[i] = b ^ key[i%4]
		}
	}
	buf.Write(out)

	_, err := w.Write(buf.Bytes())
	return err
}

// readTestWSFrame decodes a single, unfragmented RFC 6455 frame.
func readTestWSFrame(r *bufio.Reader) (testWSFrame, error) {
	var first [2]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return testWSFrame{}, err
	}
	opcode := first[0] & 0x0f
	masked := first[1]&0x80 != 0
	length := uint64(first[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return testWSFrame{}, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return testWSFrame{}, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	var key [4]byte
	if masked {
		if _, err := io.ReadFull(r, key[:]); err != nil {
			return testWSFrame{}, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return testWSFrame{}, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= key[i%4]
		}
	}
	return testWSFrame{opcode: opcode, payload: payload}, nil
}

// wsOpcode* mirror RFC 6455 §5.2 -- kept local to the test file so it does
// not depend on ws.go's own Opcode constants (see this file's own doc
// comment on independence).
const (
	wsOpcodeText   = 0x1
	wsOpcodeBinary = 0x2
	wsOpcodeClose  = 0x8
	wsOpcodePing   = 0x9
	wsOpcodePong   = 0xA
)

// recordedFrame is what echoWSUpstream saw, tagged with which connection
// (by remote address) it arrived on, so a test with more than one client in
// flight can tell them apart if it ever needs to.
type recordedFrame struct {
	opcode  byte
	payload []byte
}

// echoWSUpstream is a TLS test server that performs the RFC 6455 handshake
// by hand (this package's own dispatch is what is under test, not a second
// copy of it standing in for "the upstream"), then, for every frame it
// receives, records it and immediately echoes an unmasked frame carrying the
// same opcode and payload straight back. A close frame ends that
// connection's loop after the echo.
type echoWSUpstream struct {
	mu       sync.Mutex
	received []recordedFrame
}

func (u *echoWSUpstream) recorded() []recordedFrame {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]recordedFrame(nil), u.received...)
}

func (u *echoWSUpstream) handle(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	accept := wsAcceptKey(r.Header.Get("Sec-WebSocket-Key"))
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := rw.WriteString(resp); err != nil {
		return
	}
	if err := rw.Flush(); err != nil {
		return
	}

	for {
		fr, err := readTestWSFrame(rw.Reader)
		if err != nil {
			return
		}
		u.mu.Lock()
		u.received = append(u.received, recordedFrame(fr))
		u.mu.Unlock()

		if writeErr := writeTestWSFrame(conn, fr.opcode, fr.payload, false); writeErr != nil {
			return
		}
		if fr.opcode == wsOpcodeClose {
			return
		}
	}
}

// startEchoWSUpstream starts a TLS-served echoWSUpstream, reusing this
// package's own upstream_test.go certificate helpers (newTestCA, leafOpts)
// -- same package, same test binary, nothing there is edited to get them.
func startEchoWSUpstream(t *testing.T) (*httptest.Server, *echoWSUpstream, *tls.Config) {
	t.Helper()
	u := &echoWSUpstream{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(u.handle))
	ca := newTestCA(t)
	leaf := ca.leaf(t, leafOpts{ipAddresses: []net.IP{net.ParseIP("127.0.0.1")}})
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, u, &tls.Config{RootCAs: ca.pool, MinVersion: tls.VersionTLS12}
}

// wsHarnessClient is a minimal WebSocket client speaking directly to a
// gateway address (never to the upstream) -- standing in for the harness
// GW-009 relays traffic for, built without any WebSocket library, matching
// ws.go's own stdlib-only approach.
type wsHarnessClient struct {
	conn net.Conn
	r    *bufio.Reader
}

// dialWSHarnessClient performs the client side of the RFC 6455 handshake
// against a plain (non-TLS) gateway listener -- the gateway's own listener
// is the one this package's tests always reach over plain HTTP; TLS lives
// only between the gateway and the upstream (see ws.go's own doc comment).
func dialWSHarnessClient(t *testing.T, gatewayURL string, headers map[string]string) (*wsHarnessClient, *http.Response) {
	t.Helper()
	u := strings.TrimPrefix(gatewayURL, "http://")
	host, path, _ := strings.Cut(u, "/")
	path = "/" + path

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(t.Context(), "tcp", host)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var keyRaw [16]byte
	if _, keyErr := rand.Read(keyRaw[:]); keyErr != nil {
		t.Fatalf("generate Sec-WebSocket-Key: %v", keyErr)
	}
	key := base64.StdEncoding.EncodeToString(keyRaw[:])

	var req bytes.Buffer
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&req, "Host: %s\r\n", host)
	req.WriteString("Upgrade: websocket\r\n")
	req.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&req, "Sec-WebSocket-Key: %s\r\n", key)
	req.WriteString("Sec-WebSocket-Version: 13\r\n")
	for k, v := range headers {
		fmt.Fprintf(&req, "%s: %s\r\n", k, v)
	}
	req.WriteString("\r\n")
	if _, writeErr := conn.Write(req.Bytes()); writeErr != nil {
		t.Fatalf("write handshake request: %v", writeErr)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read handshake response: %v", err)
	}
	// The caller closes resp.Body (bodyclose, and matching proxy_test.go's
	// own convention) -- a 101's body is empty (see ws.go's own doc
	// comment on bodyAllowedForStatus), so this is never more than a
	// formality, but it keeps one place owning the close rather than two.

	if resp.StatusCode == http.StatusSwitchingProtocols {
		wantAccept := wsAcceptKey(key)
		if got := resp.Header.Get("Sec-WebSocket-Accept"); got != wantAccept {
			t.Errorf("Sec-WebSocket-Accept = %q, want %q (the client's own key round-tripped through the relay)", got, wantAccept)
		}
	}

	return &wsHarnessClient{conn: conn, r: br}, resp
}

func (c *wsHarnessClient) send(t *testing.T, opcode byte, payload []byte) {
	t.Helper()
	if err := writeTestWSFrame(c.conn, opcode, payload, true); err != nil {
		t.Fatalf("send frame: %v", err)
	}
}

func (c *wsHarnessClient) recv(t *testing.T) testWSFrame {
	t.Helper()
	fr, err := readTestWSFrame(c.r)
	if err != nil {
		t.Fatalf("receive frame: %v", err)
	}
	return fr
}

// recvWithTimeout guards a read against a relay that silently drops a
// frame instead of forwarding it -- without this, that failure mode hangs
// the test until go test's own -timeout instead of failing with a readable
// assertion.
func (c *wsHarnessClient) recvWithTimeout(t *testing.T, d time.Duration) (testWSFrame, error) {
	t.Helper()
	type result struct {
		fr  testWSFrame
		err error
	}
	ch := make(chan result, 1)
	go func() {
		fr, err := readTestWSFrame(c.r)
		ch <- result{fr, err}
	}()
	select {
	case r := <-ch:
		return r.fr, r.err
	case <-time.After(d):
		return testWSFrame{}, errors.New("timed out waiting for a frame")
	}
}

// newWSGateway wires a Proxy (guards as given, nil for the default) in
// front of an echoWSUpstream, the WebSocket-relay analogue of
// guard_test.go's newCountingProxy.
func newWSGateway(t *testing.T, guards []Guard, observer FrameObserver) (string, *echoWSUpstream) {
	t.Helper()
	srv, upstream, tlsConfig := startEchoWSUpstream(t)
	up, err := NewUpstream(srv.URL, &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}})
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	gw := httptest.NewServer(&Proxy{Upstream: up, Guards: guards, Frames: observer})
	t.Cleanup(gw.Close)
	return gw.URL, upstream
}

// --- GW-009: the upgrade and frames round-trip unchanged in both
// directions, with Guards explicitly emptied to isolate the relay's own
// mechanics from the harness-shape guard (covered separately below). ---

func TestGW009UpgradeSwitchesProtocolsAndFramesRoundTripUnchanged(t *testing.T) {
	gwURL, upstream := newWSGateway(t, []Guard{}, nil)

	client, resp := dialWSHarnessClient(t, gwURL, map[string]string{"X-Test": "ws"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101 (Switching Protocols)", resp.StatusCode)
	}
	if got := resp.Header.Get("Upgrade"); !strings.EqualFold(got, "websocket") {
		t.Errorf("Upgrade header = %q, want websocket", got)
	}

	// mediumPayload and hugePayload exercise RFC 6455 §5.2's two extended
	// length encodings (16-bit and 64-bit) end to end -- readFrameHeader's
	// own 126 and 127 branches, on both the client->upstream (masked) and
	// upstream->client (unmasked) legs, and relayOneFrame's multi-chunk
	// copy loop for hugePayload, which is several times wsFrameCopyChunk.
	mediumPayload := bytes.Repeat([]byte("m"), 200)
	hugePayload := bytes.Repeat([]byte("h"), 3*wsFrameCopyChunk+17)

	cases := []struct {
		name    string
		opcode  byte
		payload []byte
	}{
		{"text", wsOpcodeText, []byte("hello upstream, café ☃")},
		{"binary", wsOpcodeBinary, []byte{0x00, 0x01, 0xFF, 0xFE, 0x10}},
		{"ping", wsOpcodePing, []byte("ping-payload")},
		{"pong", wsOpcodePong, []byte("pong-payload")},
		{"16-bit extended length", wsOpcodeBinary, mediumPayload},
		{"64-bit extended length, multiple chunks", wsOpcodeBinary, hugePayload},
	}
	for _, tc := range cases {
		client.send(t, tc.opcode, tc.payload)
		got, err := client.recvWithTimeout(t, 5*time.Second)
		if err != nil {
			t.Fatalf("%s: %v (want the echoed frame, not a relay that silently dropped it)", tc.name, err)
		}
		if got.opcode != tc.opcode {
			t.Errorf("%s: echoed opcode = %#x, want %#x", tc.name, got.opcode, tc.opcode)
		}
		if !bytes.Equal(got.payload, tc.payload) {
			t.Errorf("%s: echoed payload = %q, want %q", tc.name, got.payload, tc.payload)
		}
	}

	// Close ends the exchange cleanly and is itself a frame the relay must
	// carry, not special-cased away.
	client.send(t, wsOpcodeClose, []byte{})
	got, err := client.recvWithTimeout(t, 5*time.Second)
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	if got.opcode != wsOpcodeClose {
		t.Errorf("close: echoed opcode = %#x, want %#x", got.opcode, wsOpcodeClose)
	}

	recorded := upstream.recorded()
	if len(recorded) != len(cases)+1 {
		t.Fatalf("upstream recorded %d frames, want %d", len(recorded), len(cases)+1)
	}
	for i, tc := range cases {
		if recorded[i].opcode != tc.opcode || !bytes.Equal(recorded[i].payload, tc.payload) {
			t.Errorf("upstream frame %d = (opcode %#x, %q), want (opcode %#x, %q)",
				i, recorded[i].opcode, recorded[i].payload, tc.opcode, tc.payload)
		}
	}
}

// --- Every frame in both directions reaches an optional FrameObserver. ---

type recordingFrameObserver struct {
	mu     sync.Mutex
	frames []Frame
}

func (o *recordingFrameObserver) OnFrame(f Frame) {
	// Payload is copied by the relay before this is called (see ws.go); a
	// defensive copy here as well would only hide a shared-backing-array
	// bug instead of catching it, so none is made.
	o.mu.Lock()
	defer o.mu.Unlock()
	o.frames = append(o.frames, f)
}

func (o *recordingFrameObserver) snapshot() []Frame {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]Frame(nil), o.frames...)
}

func TestGW009EveryFrameReachesTheObserver(t *testing.T) {
	observer := &recordingFrameObserver{}
	gwURL, _ := newWSGateway(t, []Guard{}, observer)

	client, resp := dialWSHarnessClient(t, gwURL, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}

	client.send(t, wsOpcodeText, []byte("observed message"))
	if got := client.recv(t); got.opcode != wsOpcodeText {
		t.Fatalf("echoed opcode = %#x, want text", got.opcode)
	}
	client.send(t, wsOpcodeClose, []byte{})
	_ = client.recv(t)

	// The observer runs on a separate goroutine from the assertion below;
	// give the last (close) frame a moment to be recorded rather than
	// racing the relay's own goroutines.
	var frames []Frame
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		frames = observer.snapshot()
		if len(frames) >= 4 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if len(frames) != 4 {
		t.Fatalf("observer saw %d frames, want 4 (text+close each way): %+v", len(frames), frames)
	}
	var sawClientText, sawUpstreamText bool
	for _, f := range frames {
		if f.Opcode == OpcodeText && f.Direction == ClientToUpstream && string(f.Payload) == "observed message" {
			sawClientText = true
		}
		if f.Opcode == OpcodeText && f.Direction == UpstreamToClient && string(f.Payload) == "observed message" {
			sawUpstreamText = true
		}
	}
	if !sawClientText {
		t.Error("observer never saw the client's own text frame (ClientToUpstream)")
	}
	if !sawUpstreamText {
		t.Error("observer never saw the echoed text frame (UpstreamToClient)")
	}
}

// --- An unrecognised harness shape is refused by the guards before any
// upgrade is attempted -- default guards, upstream address unreachable so
// a 502 (a dial that should never have happened) is distinguishable from
// the guard's own 400. ---

func TestGW009UnrecognisedHarnessShapeRefusedBeforeUpgrade(t *testing.T) {
	// Nothing listens here; if the guard were bypassed, the relay would try
	// to dial this and the caller would see a gateway (502/504) failure,
	// not the guard's own 400.
	up, err := NewUpstream("https://127.0.0.1:1", nil)
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	gw := httptest.NewServer(&Proxy{Upstream: up}) // nil Guards -> defaultGuards
	defer gw.Close()

	// A recognised path, but deliberately no X-Claude-Code-Session-Id
	// header: isolating the missing session id as the one thing this
	// request gets wrong, the same way guard_test.go's own
	// TestGW011MissingSessionHeaderIsRefused does for an ordinary request.
	client, resp := dialWSHarnessClient(t, gw.URL+"/v1/messages", nil)
	defer func() { _ = client.conn.Close() }()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (the guard's own refusal, not a dial attempt)", resp.StatusCode, http.StatusBadRequest)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read refusal body: %v", err)
	}
	if !strings.Contains(string(body), "innsegl") {
		t.Errorf("refusal body %q does not name innsegl", body)
	}
	if !strings.Contains(string(body), reasonMissingSessionID) {
		t.Errorf("refusal body %q does not carry the guard's own reason %q", body, reasonMissingSessionID)
	}
}

// --- The opt-out: an explicit empty Guards slice lets an unrecognised
// shape upgrade -- the control proving the refusal above comes from the
// guard, exactly as guard_test.go's own opt-out case does for ordinary
// HTTP requests. ---

func TestGW009UpgradeSucceedsWhenGuardsAreExplicitlyEmptied(t *testing.T) {
	gwURL, _ := newWSGateway(t, []Guard{}, nil)

	// No session header at all: with Guards emptied, nothing refuses it.
	_, resp := dialWSHarnessClient(t, gwURL, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101 (Guards was explicitly emptied)", resp.StatusCode)
	}
}

// --- isWebSocketUpgrade's own unit coverage: what makes the dispatch fire
// at all. ---

func TestIsWebSocketUpgrade(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		upgrade    string
		connection string
		want       bool
	}{
		{"ordinary GET", http.MethodGet, "", "", false},
		{"upgrade header wrong value", http.MethodGet, "h2c", "Upgrade", false},
		{"connection header missing Upgrade token", http.MethodGet, "websocket", "keep-alive", false},
		{"case-insensitive match", http.MethodGet, "WebSocket", "keep-alive, Upgrade", true},
		{"exact match", http.MethodGet, "websocket", "Upgrade", true},
		{"POST is not a valid upgrade method", http.MethodPost, "websocket", "Upgrade", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), tc.method, "/v1/messages", nil)
			if tc.upgrade != "" {
				req.Header.Set("Upgrade", tc.upgrade)
			}
			if tc.connection != "" {
				req.Header.Set("Connection", tc.connection)
			}
			if got := isWebSocketUpgrade(req); got != tc.want {
				t.Errorf("isWebSocketUpgrade() = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- A failed upstream upgrade (nothing listening) returns the same JSON
// error style as an ordinary HTTP upstream failure -- reusing
// writeGatewayError and classifyUpstreamError, not a second error shape. ---

func TestGW009UnreachableUpstreamReturnsTheSameJSONErrorShapeAsHTTP(t *testing.T) {
	up, err := NewUpstream("https://127.0.0.1:1", nil)
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	gw := httptest.NewServer(&Proxy{Upstream: up, Guards: []Guard{}})
	defer gw.Close()

	_, resp := dialWSHarnessClient(t, gw.URL, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 500 || resp.StatusCode >= 600 {
		t.Fatalf("status = %d, want a 5xx", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "innsegl") {
		t.Errorf("error body %q does not name innsegl", body)
	}
}

// --- Unit coverage of ws.go's own building blocks, below the level of a
// full network round trip. ---

func TestFrameObserverFuncCallsTheUnderlyingFunc(t *testing.T) {
	var got Frame
	f := FrameObserverFunc(func(fr Frame) { got = fr })
	want := Frame{Direction: UpstreamToClient, Opcode: OpcodePing, Payload: []byte("x")}
	f.OnFrame(want)
	if got.Direction != want.Direction || got.Opcode != want.Opcode || !bytes.Equal(got.Payload, want.Payload) {
		t.Errorf("OnFrame did not call the underlying func: got %+v, want %+v", got, want)
	}
}

// stubRoundTripperForTLSConfig is a http.RoundTripper that is not
// *http.Transport, standing in for a caller-supplied one -- the branch
// upstreamTLSConfig refuses rather than inventing a TLS configuration for.
type stubRoundTripperForTLSConfig struct{}

func (stubRoundTripperForTLSConfig) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("not implemented")
}

func TestUpstreamTLSConfig(t *testing.T) {
	t.Run("nil Upstream", func(t *testing.T) {
		if _, ok := upstreamTLSConfig(nil); ok {
			t.Error("want ok=false for a nil Upstream")
		}
	})
	t.Run("nil Client", func(t *testing.T) {
		if _, ok := upstreamTLSConfig(&Upstream{}); ok {
			t.Error("want ok=false for an Upstream with a nil Client")
		}
	})
	t.Run("Transport is not *http.Transport", func(t *testing.T) {
		up := &Upstream{Client: &http.Client{Transport: stubRoundTripperForTLSConfig{}}}
		if _, ok := upstreamTLSConfig(up); ok {
			t.Error("want ok=false when Client.Transport is not *http.Transport")
		}
	})
	t.Run("Transport with no TLSClientConfig gets an explicit empty one", func(t *testing.T) {
		up := &Upstream{Client: &http.Client{Transport: &http.Transport{}}}
		cfg, ok := upstreamTLSConfig(up)
		if !ok {
			t.Fatal("want ok=true")
		}
		if cfg == nil {
			t.Error("want a non-nil *tls.Config")
		}
	})
	t.Run("Transport's own TLSClientConfig is reused, not copied", func(t *testing.T) {
		want := &tls.Config{MinVersion: tls.VersionTLS12}
		up := &Upstream{Client: &http.Client{Transport: &http.Transport{TLSClientConfig: want}}}
		got, ok := upstreamTLSConfig(up)
		if !ok {
			t.Fatal("want ok=true")
		}
		if got != want {
			t.Error("upstreamTLSConfig built a new *tls.Config instead of reusing Transport's own -- exactly the second TLS configuration GW-009 must never build")
		}
	})
}

func TestHostWithDefaultPort(t *testing.T) {
	cases := []struct {
		raw, want string
	}{
		{"https://api.anthropic.com/v1/messages", "api.anthropic.com:443"},
		{"https://example.com:8443/v1/messages", "example.com:8443"},
		{"https://127.0.0.1:9999/v1/messages", "127.0.0.1:9999"},
	}
	for _, tc := range cases {
		u, err := url.Parse(tc.raw)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", tc.raw, err)
		}
		if got := hostWithDefaultPort(u); got != tc.want {
			t.Errorf("hostWithDefaultPort(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestRelayWebSocketRefusesWhenUpstreamHasNoTLSTransport(t *testing.T) {
	up := &Upstream{Client: &http.Client{Transport: stubRoundTripperForTLSConfig{}}}
	p := &Proxy{Upstream: up}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/messages", nil)
	rec := httptest.NewRecorder() // not an http.Hijacker either, but the TLS-config check runs first

	p.relayWebSocket(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	if !strings.Contains(rec.Body.String(), "TLS configuration") {
		t.Errorf("body = %q, want it to name the missing TLS configuration", rec.Body.String())
	}
}

func TestRelayWebSocketRefusesWhenResponseWriterIsNotAHijacker(t *testing.T) {
	up, err := NewUpstream("https://example.invalid", nil) // defaultUpstreamClient: a real *http.Transport
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	p := &Proxy{Upstream: up}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/messages", nil)
	rec := httptest.NewRecorder() // an http.ResponseWriter, deliberately not an http.Hijacker

	p.relayWebSocket(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if !strings.Contains(rec.Body.String(), "hijacking") {
		t.Errorf("body = %q, want it to name the missing hijacking support", rec.Body.String())
	}
}

// declineWSUpstream is a TLS test server that answers every request with an
// ordinary (non-101) status -- an upstream that declines the upgrade
// outright, rather than one that is unreachable.
func declineWSUpstream(t *testing.T) (*httptest.Server, *tls.Config) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	ca := newTestCA(t)
	leaf := ca.leaf(t, leafOpts{ipAddresses: []net.IP{net.ParseIP("127.0.0.1")}})
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &tls.Config{RootCAs: ca.pool, MinVersion: tls.VersionTLS12}
}

func TestRelayWebSocketReportsAnUpstreamThatDeclinesTheUpgrade(t *testing.T) {
	srv, tlsConfig := declineWSUpstream(t)
	up, err := NewUpstream(srv.URL, &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}})
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}
	gw := httptest.NewServer(&Proxy{Upstream: up, Guards: []Guard{}})
	defer gw.Close()

	_, resp := dialWSHarnessClient(t, gw.URL, nil)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "declined the WebSocket upgrade") {
		t.Errorf("error body %q does not name the declined upgrade", body)
	}
	if !strings.Contains(string(body), "400") {
		t.Errorf("error body %q does not name the upstream's own status", body)
	}
}

// closedPipeConn is one end of a net.Pipe whose peer has already been
// closed, so a Write on it fails deterministically -- a real error path
// (a client or upstream connection that dies mid-write), not a fake one.
func newClosedPipeConn(t *testing.T) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	if err := server.Close(); err != nil {
		t.Fatalf("close pipe peer: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestWriteUpgradeRequestFailsWhenTheConnectionIsGone(t *testing.T) {
	conn := newClosedPipeConn(t)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/messages", nil)
	target, err := url.Parse("https://example.invalid/v1/messages")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	if err := writeUpgradeRequest(conn, req, target); err == nil {
		t.Error("writeUpgradeRequest succeeded writing to a closed connection, want an error")
	}
}

func TestWriteSwitchingProtocolsResponseFailsWhenTheConnectionIsGone(t *testing.T) {
	conn := newClosedPipeConn(t)
	bw := bufio.NewWriter(conn)

	if err := writeSwitchingProtocolsResponse(bw, http.Header{"Upgrade": {"websocket"}}); err == nil {
		t.Error("writeSwitchingProtocolsResponse succeeded writing to a closed connection, want an error")
	}
}
