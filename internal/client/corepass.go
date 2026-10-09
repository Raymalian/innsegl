// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"

	"innsegl.dev/innsegl/internal/cacustody"
	"innsegl.dev/innsegl/internal/trustbackup"
)

// The CLI reaches the core through the client service, never by dialling it.
//
// On macOS, a binary started from a terminal that lacks the Local Network
// permission cannot open a connection to a core on the LAN ("no route to
// host"), while the launchd service is not affected. Loopback is never
// "local network". So `innsegl status`, `ca-custody`, `trust-backup fetch`,
// `author` and `connect --disconnect` send their calls to the service on its
// loopback address, under CorePassPrefix, and the service sends them on over
// its own certificate. Only the routes in CorePassRoutes pass, only with
// their own method, and only for the installation the service serves.

// CorePassPrefix is the client service's route for the CLI's own calls to
// the core: <prefix><core path>.
const CorePassPrefix = "/_client/core"

// CorePassHeader marks every answer the pass-through gives, its refusals
// included. An answer without it came from a service older than this route.
const CorePassHeader = "X-Innsegl-Client-Pass" //nolint:gosec // G101: a header's name, not a credential

// CorePassInstallationHeader names the installation the CLI is calling for,
// from its own core.json. The service refuses a call for another one.
const CorePassInstallationHeader = "X-Innsegl-Installation" //nolint:gosec // G101: a header's name, not a credential

// corePassUnreachableHeader marks the service's own answer that the core did
// not answer it, so the CLI can tell that apart from the core's own 502.
const corePassUnreachableHeader = "X-Innsegl-Core-Unreachable" //nolint:gosec // G101: a header's name, not a credential

// corePassMaxBody bounds what the CLI may send: a pin report or the CA's
// unlock material, each well under a kilobyte.
const corePassMaxBody = 64 << 10

// CoreRoute is one method and core path the pass-through admits.
type CoreRoute struct{ Method, Path string }

// CorePassRoutes is everything the CLI asks the core for. It is matched
// exactly: no prefix, no query, no other method.
var CorePassRoutes = []CoreRoute{
	{http.MethodGet, CoreStatusPath},
	{http.MethodGet, cacustody.CorePath},
	{http.MethodGet, cacustody.CoreMaterialPath},
	{http.MethodPost, cacustody.CoreUnlockPath},
	{http.MethodGet, trustbackup.CorePath},
	{http.MethodGet, trustbackup.CoreLatestPath},
	{http.MethodGet, OperatorAuthorPath},
	{http.MethodPost, OperatorAuthorPath},
	{http.MethodPost, DisconnectPath},
}

func corePassAllowed(method, path string) bool {
	for _, r := range CorePassRoutes {
		if r.Method == method && r.Path == path {
			return true
		}
	}
	return false
}

// ErrClientServiceDown is the client service not answering on loopback.
var ErrClientServiceDown = errors.New("the client service is not answering")

// ErrClientServiceOld is a client service that predates the pass-through:
// the binary was rebuilt and the service still runs the old one.
var ErrClientServiceOld = errors.New("the client service is older than this command")

// ErrCoreUnreachable is the client service saying the core did not answer it.
var ErrCoreUnreachable = errors.New("the core did not answer the client service")

// RestartCommand is how a person restarts the client service on goos.
func RestartCommand(goos string) string {
	if goos == "darwin" {
		return "launchctl kickstart -k gui/$(id -u)/" + LaunchdLabel
	}
	return "systemctl --user restart " + SystemdUnit
}

// serveCorePass is the service's side: an allowlisted call goes on to the
// core over this service's certificate; anything else is refused here.
func (s *Server) serveCorePass(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(CorePassHeader, "1")
	path := strings.TrimPrefix(r.URL.Path, CorePassPrefix)
	if r.URL.RawQuery != "" || !corePassAllowed(r.Method, path) {
		s.corePassError(w, http.StatusForbidden, fmt.Sprintf("innsegl client: %s %s is not a core route the CLI "+
			"may use through this service", r.Method, path))
		return
	}
	if got := r.Header.Get(CorePassInstallationHeader); got != s.core.InstallationID {
		s.corePassError(w, http.StatusConflict, fmt.Sprintf("innsegl client: this service serves installation %s, "+
			"and the call is for %q", s.core.InstallationID, got))
		return
	}
	if s.revoked.Load() {
		s.corePassError(w, http.StatusForbidden, "innsegl client: this installation was revoked; the core refused "+
			"its renewal. Run `innsegl connect --disconnect`, then enrol again with a new token.")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, corePassMaxBody+1))
	if err != nil {
		s.corePassError(w, http.StatusBadRequest, "innsegl client: reading the request: "+err.Error())
		return
	}
	if len(body) > corePassMaxBody {
		s.corePassError(w, http.StatusRequestEntityTooLarge, "innsegl client: the request is larger than any the CLI sends")
		return
	}
	var reader io.Reader = http.NoBody
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	// The path sent on is the allowlisted one, never the caller's bytes.
	//nolint:gosec // G704: core.json's own https core URL and an allowlisted path; the caller chooses neither
	out, err := http.NewRequestWithContext(r.Context(), r.Method, strings.TrimSuffix(s.core.CoreURL, "/")+path, reader)
	if err != nil {
		s.corePassError(w, http.StatusInternalServerError, "innsegl client: "+err.Error())
		return
	}
	if len(body) > 0 {
		out.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	}
	resp, err := s.transport.RoundTrip(out)
	if err != nil {
		w.Header().Set(corePassUnreachableHeader, "1")
		s.corePassError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer func() { _ = resp.Body.Close() }()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		s.log.Printf("passing the core's answer to %s %s to the CLI: %v", r.Method, path, err)
	}
}

func (s *Server) corePassError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": msg}); err != nil {
		s.log.Printf("answering the CLI: %v", err)
	}
}

// serviceCaller is the CLI's side: a RoundTripper that sends to the client
// service and turns its own answers about itself into errors that say which
// part is not answering.
type serviceCaller struct {
	rt           http.RoundTripper
	base         string
	installation string
}

func (c serviceCaller) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.Header.Set(CorePassInstallationHeader, c.installation)
	resp, err := c.rt.RoundTrip(out)
	if err != nil {
		return nil, fmt.Errorf("%w at %s (%w); start it: %s", ErrClientServiceDown, c.base, err, RestartCommand(runtime.GOOS))
	}
	if resp.Header.Get(CorePassHeader) == "" {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: the service at %s does not pass the CLI's calls to the core. Restart it so it "+
			"runs this build: %s", ErrClientServiceOld, c.base, RestartCommand(runtime.GOOS))
	}
	if resp.Header.Get(corePassUnreachableHeader) != "" {
		defer func() { _ = resp.Body.Close() }()
		var e struct {
			Error string `json:"error"`
		}
		if derr := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&e); derr != nil {
			e.Error = "its answer could not be read: " + derr.Error()
		}
		return nil, fmt.Errorf("%w: %s", ErrCoreUnreachable, e.Error)
	}
	return resp, nil
}

// coreViaService answers the transport and base URL a CLI call to the core
// uses: the client service at local ("http://host:port"), or, when local is
// empty, at the loopback address the enrolment names. A path is appended to
// the base as it would be to the core's URL.
func coreViaService(paths Paths, local string) (http.RoundTripper, string, error) {
	cfg, err := ReadCoreConfig(paths)
	if err != nil {
		return nil, "", err
	}
	if local == "" {
		listen := cfg.Listen
		if listen == "" {
			listen = DefaultListen
		}
		local = "http://" + listen
	}
	u, err := url.Parse(local)
	if err != nil || u.Scheme != "http" || u.Host == "" {
		return nil, "", fmt.Errorf("the client service address %q is not http://<loopback>:<port>", local)
	}
	if err := CheckLoopback(u.Host); err != nil {
		return nil, "", err
	}
	base := strings.TrimSuffix(local, "/")
	rt := serviceCaller{
		// Never through a proxy: a shell inside a harness carries
		// HTTPS_PROXY pointing at this same service.
		rt:           &http.Transport{Proxy: nil, DialContext: (&net.Dialer{}).DialContext},
		base:         base,
		installation: cfg.InstallationID,
	}
	return rt, base + CorePassPrefix, nil
}
