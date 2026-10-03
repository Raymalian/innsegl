// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

// connectproxy.go is the client service as Claude Code's HTTPS proxy
// (RM-329, #500). Claude Code keeps its own base URL, so it turns off none
// of the features it reserves for a direct connection; it reaches the
// provider through HTTPS_PROXY, which is this service, and trusts the
// client's proxy CA through NODE_EXTRA_CA_CERTS.
//
// Only ProviderAPIHost is opened. A model request on it goes into the
// recorded path to the core (serveModel), exactly as one sent to the base
// URL did. Any other request on it (Remote Control, sign-in, settings,
// telemetry) passes straight to the provider and is never logged or
// journaled: those carry the person's own credentials. Every other host is
// a blind tunnel.

// proxyDialTimeout bounds opening a tunnel.
const proxyDialTimeout = 10 * time.Second

func (s *Server) initProxy() {
	transport := http.DefaultTransport
	if s.providerClient != nil && s.providerClient.Transport != nil {
		transport = s.providerClient.Transport
	}
	provider := s.provider
	s.passThrough = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(provider)
			pr.Out.Host = provider.Host
		},
		Transport:     transport,
		FlushInterval: -1,
		ErrorLog:      s.log,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// The path only: a query or a body may carry a credential.
			s.log.Printf("passing %s %s to the provider: %v", r.Method, r.URL.Path, err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	s.plain = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			base := (&urlOnly{pr.In}).base()
			pr.SetURL(&base)
			pr.Out.Host = pr.In.Host
		},
		Transport:     &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: proxyDialTimeout}).DialContext},
		FlushInterval: -1,
		ErrorLog:      s.log,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.log.Printf("forwarding %s to %s: %v", r.Method, r.URL.Host, err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
}

// serveConnect answers a CONNECT: the provider's API is opened, any other
// host is tunnelled.
func (s *Server) serveConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "innsegl client: CONNECT needs host:port", http.StatusBadRequest)
		return
	}
	if strings.EqualFold(host, ProviderAPIHost) && port == "443" {
		s.openProvider(w)
		return
	}
	s.tunnel(w, r)
}

// tunnel joins the caller to r.Host unopened. A host that cannot be reached
// is a 502, never a 403: Remote Control gives up on a session its proxy
// refuses.
func (s *Server) tunnel(w http.ResponseWriter, r *http.Request) {
	up, err := (&net.Dialer{Timeout: proxyDialTimeout}).DialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		s.log.Printf("tunnel to %s: %v", r.Host, err)
		http.Error(w, "innsegl client: cannot reach "+r.Host, http.StatusBadGateway)
		return
	}
	conn, ok := hijackConnected(w, s)
	if !ok {
		up.Close()
		return
	}
	go s.pipe(up, conn, r.Host)
	go s.pipe(conn, up, r.Host)
}

// pipe copies one direction of a tunnel, then closes the far end so the
// other direction ends too. A connection closed by either side is the
// normal end, not an error.
func (s *Server) pipe(dst, src net.Conn, host string) {
	if _, err := io.Copy(dst, src); err != nil && !errors.Is(err, net.ErrClosed) {
		s.log.Printf("tunnel to %s: %v", host, err)
	}
	if err := dst.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		s.log.Printf("closing the tunnel to %s: %v", host, err)
	}
}

// openProvider answers the CONNECT, then serves HTTP over TLS on the
// connection with a leaf from the proxy CA.
func (s *Server) openProvider(w http.ResponseWriter) {
	conn, ok := hijackConnected(w, s)
	if !ok {
		return
	}
	tlsConn := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.proxyCA.leaf(s.Now())
		},
	})
	ln := newOneConnListener(tlsConn)
	srv := &http.Server{
		Handler:           http.HandlerFunc(s.serveProvider),
		ReadHeaderTimeout: 60 * time.Second,
		ErrorLog:          s.log,
		ConnState: func(_ net.Conn, st http.ConnState) {
			if st == http.StateClosed || st == http.StateHijacked {
				ln.done()
			}
		},
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
			s.log.Printf("serving an opened provider connection: %v", err)
		}
	}()
}

// serveProvider routes one request on an opened provider connection.
func (s *Server) serveProvider(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && isModelPath(r.URL.Path) {
		if s.revoked.Load() {
			http.Error(w, "innsegl client: this installation was revoked; the core refused its renewal. "+
				"Run `innsegl connect --disconnect`, then enrol again with a new token.", http.StatusForbidden)
			return
		}
		s.serveModel(w, r)
		return
	}
	if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/") && !strings.HasPrefix(r.URL.Path, "/v1/code/") {
		// A POST under the API that is neither a model request nor Remote
		// Control: a new kind of request the recorder does not know. Said,
		// so the list grows; passed on, so nothing breaks.
		s.log.Printf("finding: an unclassified provider request POST %s was passed through unrecorded", r.URL.Path)
	}
	s.passThrough.ServeHTTP(w, r)
}

// hijackConnected takes the connection and answers the CONNECT.
func hijackConnected(w http.ResponseWriter, s *Server) (net.Conn, bool) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "innsegl client: this connection cannot be taken over", http.StatusInternalServerError)
		return nil, false
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		s.log.Printf("taking over a CONNECT: %v", err)
		return nil, false
	}
	if _, err = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		_ = conn.Close()
		return nil, false
	}
	if buf != nil && buf.Reader.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: buf.Reader}, true
	}
	return conn, true
}

// bufferedConn reads first what the server had already buffered.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// oneConnListener hands out one connection, then blocks until it is done.
type oneConnListener struct {
	conn     net.Conn
	once     sync.Once
	doneOnce sync.Once
	closed   chan struct{}
}

func newOneConnListener(c net.Conn) *oneConnListener {
	return &oneConnListener{conn: c, closed: make(chan struct{})}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *oneConnListener) done()          { l.doneOnce.Do(func() { close(l.closed) }) }
func (l *oneConnListener) Close() error   { l.done(); return nil }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// urlOnly gives a proxy-form request's scheme and host as a base URL.
type urlOnly struct{ r *http.Request }

func (u *urlOnly) base() url.URL {
	return url.URL{Scheme: u.r.URL.Scheme, Host: u.r.URL.Host}
}
