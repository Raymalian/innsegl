// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// The CLI's own calls to the core (status, CA custody, the trust backup, the
// operator author, disconnect) reach the client service on a unix socket in
// the client folder, not on its loopback TCP address (#600). The folder is
// 0700 and the socket 0600, and the service also asks the kernel who the
// caller is (LOCAL_PEERCRED on macOS, SO_PEERCRED on Linux): a connection
// from any uid but the service's own is closed before a byte is read. The
// loopback TCP address stays for the harness: its model traffic, the hooks
// and git.

// SocketName is the CLI socket's name in the client folder.
const SocketName = "client.sock"

// SocketBase is the URL a request on the socket carries. The host is a
// name only; the socket is what is dialled.
const SocketBase = "http://innsegl-client"

// maxSocketPath is the longest socket path both macOS (104 bytes with the
// terminating zero) and Linux (108) can bind.
const maxSocketPath = 103

// SocketPath is the CLI socket of the enrolment at paths.
func SocketPath(paths Paths) string { return filepath.Join(paths.Dir, SocketName) }

// SocketTransport sends every request to the socket at path, never through
// a proxy: a shell inside a harness carries HTTPS_PROXY pointing at the
// same service.
func SocketTransport(path string) *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}
}

// ListenSocket listens on the CLI socket at path for this process's own
// user only. logf says each connection it refuses; nil says nothing.
func ListenSocket(ctx context.Context, path string, logf func(string, ...any)) (net.Listener, error) {
	return listenSocket(ctx, path, os.Getuid(), logf)
}

func listenSocket(ctx context.Context, path string, uid int, logf func(string, ...any)) (net.Listener, error) {
	if len(path) > maxSocketPath {
		return nil, fmt.Errorf("the CLI socket path %s is too long (%d bytes; a socket takes at most %d)",
			path, len(path), maxSocketPath)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	// A socket a stopped service left behind is replaced; any other file
	// there is not this service's to remove.
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s is not a socket; move it away so the client service can listen there", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &peerListener{Listener: ln, uid: uid, logf: logf}, nil
}

// peerListener hands on only the connections whose peer is uid.
type peerListener struct {
	net.Listener
	uid  int
	logf func(string, ...any)
}

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		got, err := peerUID(c)
		if err == nil && got == l.uid {
			return c, nil
		}
		if err != nil {
			l.logf("refused a connection on the CLI socket: the kernel did not name its user (%v)", err)
		} else {
			l.logf("refused a connection on the CLI socket from uid %d; only uid %d may use it", got, l.uid)
		}
		_ = c.Close()
	}
}

// errPeerUnknown is a connection whose peer's user cannot be read.
var errPeerUnknown = errors.New("not a unix socket connection")

// rawConn is the file descriptor under a socket connection.
func rawConn(c net.Conn) (interface {
	Control(func(fd uintptr)) error
}, error,
) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil, errPeerUnknown
	}
	return uc.SyscallConn()
}

// SocketHandler serves the CLI on its socket: the service's status and the
// pass-through to the core. Nothing of the harness's is served here.
func (s *Server) SocketHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == StatusPath:
			s.serveStatus(w, r)
		case r.URL.Path == CorePassPrefix || strings.HasPrefix(r.URL.Path, CorePassPrefix+"/"):
			s.serveCorePass(w, r)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			if err := json.NewEncoder(w).Encode(map[string]string{
				"error": "innsegl client: " + r.URL.Path + " is not served on the CLI socket",
			}); err != nil {
				s.log.Printf("answering the CLI: %v", err)
			}
		}
	})
}

// serveCorePassGone answers a CLI call sent to the loopback TCP address: it
// moved to the socket (#600), and the core is not asked.
func (s *Server) serveCorePassGone(w http.ResponseWriter) {
	w.Header().Set(CorePassHeader, "1")
	s.corePassError(w, http.StatusGone, "innsegl client: the CLI's calls to the core go over the socket "+
		SocketPath(s.paths)+", not this address; run the innsegl binary this service runs")
}
