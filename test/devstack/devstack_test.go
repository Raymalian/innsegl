// SPDX-License-Identifier: Apache-2.0

package devstack

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/go-webauthn/webauthn/protocol"

	"innsegl.dev/innsegl/internal/unlockkey"
	"innsegl.dev/innsegl/internal/webauthntest"
)

// devPrefix is the name every container of a dev stack carries (ADR-0072).
// A container without it is a live core's, and these cases never touch one.
const devPrefix = "innsegl-dev-"

// stack is the running dev stack, as these cases reach it.
type stack struct {
	dashboard string // the dashboard's origin, which is also its WebAuthn origin
	core      string // the core's client endpoint
	caPath    string // the core's own CA, which a workstation trusts for it
	state     string // where the dev owner's passkey is kept between phases
}

// requireStack is the stack these cases run against, or a skip that says how
// to give them one. It fails, never skips, once asked to run: a requested
// run against a missing or live stack is an error, not an absence.
func requireStack(t *testing.T) stack {
	t.Helper()
	if os.Getenv("INNSEGL_DEVSTACK_E2E") != "1" {
		t.Skip("skipping: this case runs against a running dev stack (make dev-stack, custody on); " +
			"set INNSEGL_DEVSTACK_E2E=1 with one up, as reference/ca-custody.md says")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	s := stack{
		dashboard: envOr("INNSEGL_DEVSTACK_DASHBOARD", "http://localhost:8082"),
		core:      envOr("INNSEGL_DEVSTACK_CORE", "https://localhost:28095"),
		caPath:    envOr("INNSEGL_DEVSTACK_CA", filepath.Join(home, ".innsegl", "dev", "ca", "gateway-ca.pem")),
		state:     os.Getenv("INNSEGL_DEVSTACK_STATE"),
	}
	if s.state == "" {
		t.Fatal("INNSEGL_DEVSTACK_STATE is unset: name a directory for the dev owner's passkey")
	}
	for _, raw := range []string{s.dashboard, s.core} {
		u, perr := url.Parse(raw)
		if perr != nil || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1") {
			t.Fatalf("%q is not a loopback address; a dev stack is published on loopback only (ADR-0072)", raw)
		}
	}
	names := docker(t, "ps", "--format", "{{.Names}}")
	for _, n := range strings.Fields(names) {
		if strings.HasPrefix(n, "innsegl-") && !strings.HasPrefix(n, devPrefix) &&
			(strings.HasSuffix(n, "-core") || strings.HasSuffix(n, "-api") || strings.Contains(n, "-ca-")) {
			t.Fatalf("%s runs here: a live-named stack is up, and these cases never run beside one", n)
		}
	}
	for _, c := range []string{devPrefix + "api", devPrefix + "core", devPrefix + "ca-custodian", devPrefix + "ca-store"} {
		if !strings.Contains(" "+strings.Join(strings.Fields(names), " ")+" ", " "+c+" ") {
			t.Fatalf("%s is not running: bring the dev stack up with custody on (INNSEGL_CA_CUSTODY=on) first", c)
		}
	}
	if err := os.MkdirAll(s.state, 0o700); err != nil {
		t.Fatal(err)
	}
	return s
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return string(out)
}

// ---------------------------------------------------------------------------
// HTTP, as the dashboard's own browser sends it
// ---------------------------------------------------------------------------

type answer struct {
	status int
	header http.Header
	body   []byte
}

// call sends one request with the dashboard's Origin, as a browser does on
// every POST, and the session cookie when there is one.
func (s stack) call(t *testing.T, method, path string, body any, cookie *http.Cookie) answer {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.dashboard+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", s.dashboard)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return answer{status: resp.StatusCode, header: resp.Header, body: raw}
}

func (s stack) must(t *testing.T, method, path string, body any, cookie *http.Cookie, into any) answer {
	t.Helper()
	a := s.call(t, method, path, body, cookie)
	if a.status != http.StatusOK {
		t.Fatalf("%s %s: %d %s", method, path, a.status, a.body)
	}
	if into != nil {
		if err := json.Unmarshal(a.body, into); err != nil {
			t.Fatalf("%s %s: decoding %s: %v", method, path, a.body, err)
		}
	}
	return a
}

func sessionCookie(t *testing.T, h http.Header) *http.Cookie {
	t.Helper()
	for _, c := range (&http.Response{Header: h}).Cookies() {
		if c.Name == "innsegl_session" {
			return c
		}
	}
	t.Fatal("no session cookie was set")
	return nil
}

// ceremony is a begin answer: its id beside the WebAuthn options.
type ceremony struct {
	CeremonyID string `json:"ceremony_id"`
	protocol.CredentialAssertion
}

type finish struct {
	CeremonyID string          `json:"ceremony_id"`
	Credential json.RawMessage `json:"credential"`
}

// ---------------------------------------------------------------------------
// The dev owner: the stack's first account, a soft passkey kept on disk
// ---------------------------------------------------------------------------

type owner struct {
	auth   *webauthntest.Authenticator
	userID string
	cookie *http.Cookie
}

type ownerFile struct {
	Passkey json.RawMessage `json:"passkey"`
	UserID  string          `json:"user_id"`
	Session string          `json:"session,omitempty"`
}

func (s stack) ownerPath() string { return filepath.Join(s.state, "owner.json") }

// save writes the owner back, with the passkey's sign counter as it is now:
// the server refuses a counter that goes backwards.
func (s stack) save(t *testing.T, o *owner) {
	t.Helper()
	raw, err := o.auth.Export()
	if err != nil {
		t.Fatal(err)
	}
	f := ownerFile{Passkey: raw, UserID: o.userID}
	if o.cookie != nil {
		f.Session = o.cookie.Value
	}
	out, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.ownerPath(), out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (s stack) load(t *testing.T) (*owner, bool) {
	t.Helper()
	raw, err := os.ReadFile(s.ownerPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, false
	}
	if err != nil {
		t.Fatal(err)
	}
	var f ownerFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("%s: %v", s.ownerPath(), err)
	}
	a, err := webauthntest.Import(f.Passkey)
	if err != nil {
		t.Fatal(err)
	}
	o := &owner{auth: a, userID: f.UserID}
	if f.Session != "" {
		o.cookie = &http.Cookie{Name: "innsegl_session", Value: f.Session}
	}
	return o, true
}

func (s stack) setupNeeded(t *testing.T) bool {
	t.Helper()
	var st struct {
		Needed bool `json:"needed"`
	}
	s.must(t, http.MethodGet, "/api/v1/auth/setup", nil, nil, &st)
	return st.Needed
}

// createOwner is the setup link's path: a one-time code from the API
// container, then first-user enrolment, which founds the operator
// organisation with this user as its owner.
func (s stack) createOwner(t *testing.T) *owner {
	t.Helper()
	code := strings.TrimSpace(docker(t, "exec", devPrefix+"api", "sh", "-c",
		`innsegl admin-credential enrol-code -dsn "$INNSEGL_API_AUTH_DSN"`))
	if code == "" {
		t.Fatal("the API container minted no enrolment code")
	}
	a := s.must(t, http.MethodPost, "/api/v1/auth/enrol/begin",
		map[string]string{"display_name": "Dev Owner", "code": code}, nil, nil)
	var id struct {
		CeremonyID string `json:"ceremony_id"`
	}
	var creation protocol.CredentialCreation
	if err := json.Unmarshal(a.body, &id); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(a.body, &creation); err != nil {
		t.Fatal(err)
	}
	handle, ok := creation.Response.User.ID.(string)
	if !ok {
		t.Fatalf("the creation options' user id is a %T", creation.Response.User.ID)
	}
	userID, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(handle, "="))
	if err != nil {
		t.Fatalf("the creation options' user id %q: %v", handle, err)
	}
	auth, err := webauthntest.New()
	if err != nil {
		t.Fatal(err)
	}
	cred, err := auth.Register(&creation, s.dashboard)
	if err != nil {
		t.Fatal(err)
	}
	done := s.must(t, http.MethodPost, "/api/v1/auth/enrol/finish", finish{CeremonyID: id.CeremonyID, Credential: cred}, nil, nil)
	o := &owner{auth: auth, userID: string(userID), cookie: sessionCookie(t, done.header)}
	s.save(t, o)
	return o
}

// signIn is a passkey sign-in with the owner's passkey.
func (s stack) signIn(t *testing.T, o *owner) {
	t.Helper()
	var c ceremony
	s.must(t, http.MethodPost, "/api/v1/auth/login/begin", struct{}{}, nil, &c)
	cred, err := o.auth.Assert(&c.CredentialAssertion, s.dashboard, o.userID)
	if err != nil {
		t.Fatal(err)
	}
	done := s.must(t, http.MethodPost, "/api/v1/auth/login/finish", finish{CeremonyID: c.CeremonyID, Credential: cred}, nil, nil)
	o.cookie = sessionCookie(t, done.header)
	s.save(t, o)
}

// theOwner is the stack's owner, signed in: the one a rehearsal's first
// phase enrolled, or a new one on a stack that has no account yet.
func (s stack) theOwner(t *testing.T) *owner {
	t.Helper()
	if o, ok := s.load(t); ok {
		s.signIn(t, o)
		return o
	}
	if !s.setupNeeded(t) {
		t.Fatalf("this dev stack has an account, and %s holds no passkey for it; "+
			"point INNSEGL_DEVSTACK_STATE at the directory its first phase used, or use a dev stack with no account yet",
			s.ownerPath())
	}
	return s.createOwner(t)
}

// confirm is a step-up: begin, the owner's passkey, finish.
func (s stack) confirm(t *testing.T, o *owner, begin, end string, req, into any) {
	t.Helper()
	var c ceremony
	s.must(t, http.MethodPost, begin, req, o.cookie, &c)
	cred, err := o.auth.Assert(&c.CredentialAssertion, s.dashboard, o.userID)
	if err != nil {
		t.Fatal(err)
	}
	s.save(t, o)
	s.must(t, http.MethodPost, end, finish{CeremonyID: c.CeremonyID, Credential: cred}, o.cookie, into)
}

// operatorOrg is the id of the organisation the owner owns as the
// deployment's operator.
func (s stack) operatorOrg(t *testing.T, o *owner) string {
	t.Helper()
	var st struct {
		Authenticated bool `json:"authenticated"`
		Organisations []struct {
			ID       string `json:"id"`
			Role     string `json:"role"`
			Operator bool   `json:"operator"`
		} `json:"organisations"`
	}
	s.must(t, http.MethodGet, "/api/v1/auth/session", nil, o.cookie, &st)
	for _, org := range st.Organisations {
		if org.Operator && org.Role == "owner" {
			return org.ID
		}
	}
	t.Fatalf("the dev owner owns no operator organisation: %+v", st)
	return ""
}

// ---------------------------------------------------------------------------
// A soft security key with PRF, and the browser's derivation
// ---------------------------------------------------------------------------

type prfKey struct {
	*webauthntest.Authenticator
	secret []byte
}

func newPRFKey(t *testing.T) *prfKey {
	t.Helper()
	a, err := webauthntest.New()
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	return &prfKey{Authenticator: a, secret: secret}
}

// output is the PRF extension's answer for salt: the authenticator's
// hmac-secret over WebAuthn's own hash of it.
func (k *prfKey) output(salt []byte) []byte {
	h := sha256.Sum256(append([]byte("WebAuthn PRF\x00"), salt...))
	mac := hmac.New(sha256.New, k.secret)
	mac.Write(h[:])
	return mac.Sum(nil)
}

func (k *prfKey) identity(t *testing.T, salt []byte, p unlockkey.Purpose) *age.X25519Identity {
	t.Helper()
	id, err := unlockkey.Derive(k.output(salt), p)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// ---------------------------------------------------------------------------
// The operator's machine: a workstation's client folder, its client
// service, and the innsegl CLI, all under a home of their own
// ---------------------------------------------------------------------------

// buildInnsegl builds this checkout's CLI, the one the operator runs.
func buildInnsegl(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "innsegl")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/innsegl")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the CLI: %v\n%s", err, out)
	}
	return bin
}

func readCA(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the core's CA: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("%s holds no PEM block", path)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// freeLoopback is a loopback address nothing listens on: never the
// operator's own client service (127.0.0.1:28195).
func freeLoopback(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// clientService is `innsegl client serve` for the test's own home.
type clientService struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
	log    *bytes.Buffer
	done   chan struct{}
}

func startClientService(t *testing.T, bin, home, listen string) *clientService {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var log bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "client", "serve", "--listen", listen)
	cmd.Env = append(os.Environ(), "HOME="+home)
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	svc := &clientService{cmd: cmd, cancel: cancel, log: &log, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(svc.done) }()
	t.Cleanup(svc.stop)
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		resp, err := http.Get("http://" + listen + "/_client/status") //nolint:noctx // a probe loop
		if err == nil {
			_ = resp.Body.Close()
			return svc
		}
	}
	svc.stop()
	t.Fatalf("the client service never answered on %s:\n%s", listen, log.String())
	return nil
}

func (c *clientService) stop() {
	c.cancel()
	<-c.done
}

// cli runs the CLI as the operator's machine, with stdin as its terminal.
func cli(t *testing.T, bin, home, stdin string, args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "HOME="+home)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, string(out)
	case errors.As(err, &exit):
		return exit.ExitCode(), string(out)
	}
	t.Fatalf("innsegl %s: %v\n%s", strings.Join(args, " "), err, out)
	return -1, ""
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	raw, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func shortJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(raw)
}
