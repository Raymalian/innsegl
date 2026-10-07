// SPDX-License-Identifier: Apache-2.0

// Package commitpath is the contract of ADR-0059's commit path, shared by the
// host commands git runs (prepare-commit-msg, gpg.x509.program) and the core
// that answers them.
package commitpath

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/workspace"
)

// Where the core answers, and how a host command finds it.
const (
	TrailersPath = "/_gateway/commit-trailers"
	SignPath     = "/_gateway/commit-sign"

	// EnvToolUseID carries the harness's tool call id into git's own
	// children (ADR-0059 decision 1).
	EnvToolUseID = "INNSEGL_TOOL_USE_ID"
	// EnvCoreURL overrides DefaultCoreURL.
	EnvCoreURL = "INNSEGL_CORE_URL"
	// DefaultCoreURL is https, not http (RM-246, #391): the gateway's
	// listener serves TLS from the core's own CA, and this Client trusts
	// ONLY that CA (TrustedHTTPClient) -- never the system roots, never
	// InsecureSkipVerify.
	DefaultCoreURL = "https://127.0.0.1:28095"
)

// TrailersRequest asks for the run's trailers (ADR-0059 decision 2).
type TrailersRequest struct {
	ToolUseID string `json:"tool_use_id"`
	Message   string `json:"message"`
}

// TrailersResponse is the message with the run's trailers placed by
// ADR-0028's render.
type TrailersResponse struct {
	Message string `json:"message"`
}

// SignRequest is what git handed its signing program: its arguments and the
// unsigned commit object (ADR-0059 decisions 3 and 4).
type SignRequest struct {
	ToolUseID string   `json:"tool_use_id"`
	Args      []string `json:"args"`
	Payload   []byte   `json:"payload"`
}

// SignResponse is what the signing program hands back to git: the signature
// for stdout and the status lines for the status fd.
type SignResponse struct {
	Signature []byte `json:"signature"`
	Status    []byte `json:"status"`
}

// IsGitCommitCommand reports whether a shell command runs a git subcommand
// that writes a commit object: in any of its simple commands, a `git` word
// whose subcommand, after git's own options, is one of commitCreatingGit
// (`commit`, and since #536 also `merge`, `pull`, `revert`, `cherry-pick` and
// `rebase`, each of which authors a commit as whoever git is configured as).
// It is a reading of the command, not a shell parser:
// the harness hook uses it to decide where the tool call id goes, and the core
// uses it to require that the tool call it resolves asked for a commit. Both
// read it the same way because both call this.
func IsGitCommitCommand(cmd string) bool {
	for _, simple := range splitSimpleCommands(cmd) {
		if commitCreatingGit[gitSubcommand(strings.Fields(simple))] {
			return true
		}
	}
	return false
}

// commitCreatingGit is every git subcommand that can create a commit object.
// `pull` may merge, and `rebase` replays commits as new ones.
var commitCreatingGit = map[string]bool{
	"commit":      true,
	"merge":       true,
	"pull":        true,
	"revert":      true,
	"cherry-pick": true,
	"rebase":      true,
}

// splitSimpleCommands splits on the shell's command separators.
func splitSimpleCommands(cmd string) []string {
	return strings.FieldsFunc(cmd, func(r rune) bool {
		return r == ';' || r == '&' || r == '|' || r == '\n'
	})
}

// gitSubcommand returns the subcommand of the first command word that is
// git, skipping leading VAR=value assignments and git's own options. Only the
// command word counts: `echo git commit` is echo's.
func gitSubcommand(words []string) string {
	i := 0
	for i < len(words) && strings.Contains(words[i], "=") && !strings.HasPrefix(words[i], "-") {
		i++
	}
	if i >= len(words) || path.Base(words[i]) != "git" {
		return ""
	}
	for i++; i < len(words); i++ {
		w := words[i]
		switch {
		case w == "-C" || w == "-c":
			i++ // the option's own argument
		case strings.HasPrefix(w, "-"):
		default:
			return w
		}
	}
	return ""
}

// maxToolUseIDBytes bounds a tool call id; the harness's are far shorter.
const maxToolUseIDBytes = 128

// IsToolUseID reports whether s has the shape of a harness tool call id:
// "toolu_" and then letters, digits and underscores. The id travels through
// a shell and into a log line, so nothing else is allowed through.
func IsToolUseID(s string) bool {
	const prefix = "toolu_"
	if len(s) <= len(prefix) || len(s) > maxToolUseIDBytes || !strings.HasPrefix(s, prefix) {
		return false
	}
	for _, c := range s[len(prefix):] {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// Client calls the core.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// defaultTimeout bounds one call. Signing reaches Fulcio and Rekor from the
// core, so it is generous; git waits on it either way.
const defaultTimeout = 2 * time.Minute

// maxResponseBytes bounds what the client reads back.
const maxResponseBytes = 4 << 20

// ClientFromEnv builds a Client from EnvCoreURL, or DefaultCoreURL. Its HTTP
// field trusts ONLY the core's own gateway CA (TrustedHTTPClient) -- never
// the system roots, never InsecureSkipVerify.
func ClientFromEnv(getenv func(string) string) Client {
	base := getenv(EnvCoreURL)
	if base == "" {
		base = DefaultCoreURL
	}
	return Client{BaseURL: base, HTTP: TrustedHTTPClient(getenv)}
}

// EnvExtraCACerts is $NODE_EXTRA_CA_CERTS -- read first, so an installer
// that already arranges for a Node-style client to add one extra trusted
// root (RM-246's own harness-trust story) points this package at the SAME
// file, rather than the deployment having to teach two different
// mechanisms about one certificate.
const EnvExtraCACerts = "NODE_EXTRA_CA_CERTS"

// gatewayCACertFileName is gateway.CACertFileName's value, repeated rather
// than imported: internal/gateway's own production code imports this
// package (record.go, for commitpath.Resolver), so this package cannot
// import internal/gateway back without a cycle. The two packages agree on
// this file name by convention; internal/gateway/tls_test.go and this
// package's own tls_test.go (an external test, which has no such cycle)
// both assert against gateway.CACertFileName directly, so a change to one
// without the other fails a test rather than silently drifting.
const gatewayCACertFileName = "gateway-ca.pem"

// CAFile resolves which file names the core's own gateway CA certificate:
// $NODE_EXTRA_CA_CERTS if set, else $HOME/.innsegl/ca/gateway-ca.pem -- the
// host half of RM-246's contract. deploy/compose/innsegl.yml bind-mounts
// that path's parent directory into the core, which writes its CA
// certificate there on every start (gateway.LoadOrCreateCA's own
// PublicDir).
func CAFile(getenv func(string) string) string {
	if f := getenv(EnvExtraCACerts); f != "" {
		return f
	}
	home := getenv("HOME")
	if home == "" {
		home = "."
	}
	return filepath.Join(home, ".innsegl", "ca", gatewayCACertFileName)
}

// TrustedHTTPClient builds an *http.Client that trusts ONLY the core's own
// gateway CA (CAFile) -- never the system roots, never
// InsecureSkipVerify, ever. If the CA file cannot be read or is not a
// valid PEM certificate, the client's trust pool is simply left empty:
// every TLS handshake then fails the same way a wrong or a stale CA already
// would (TLS-002), rather than silently widening trust to make the client
// "work".
func TrustedHTTPClient(getenv func(string) string) *http.Client {
	pool := x509.NewCertPool()
	// #nosec G703 -- CAFile resolves to $NODE_EXTRA_CA_CERTS or
	// $HOME/.innsegl/ca/gateway-ca.pem, both operator/deployment
	// configuration, never attacker-controlled input; a read failure here
	// is handled by leaving the pool empty (see this function's own doc
	// comment), not propagated as an error.
	if pemBytes, err := os.ReadFile(CAFile(getenv)); err == nil {
		pool.AppendCertsFromPEM(pemBytes)
	}
	return &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}

// Trailers asks the core for the run's trailers.
func (c Client) Trailers(ctx context.Context, req TrailersRequest) (TrailersResponse, error) {
	var resp TrailersResponse
	return resp, c.call(ctx, TrailersPath, req, &resp)
}

// Sign asks the core to sign a payload.
func (c Client) Sign(ctx context.Context, req SignRequest) (SignResponse, error) {
	var resp SignResponse
	return resp, c.call(ctx, SignPath, req, &resp)
}

// call posts req as JSON and decodes a 200 answer into out. Any other status
// is an error carrying the core's own reason when it gave one.
func (c Client) call(ctx context.Context, endpoint string, req, out any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("innsegl: encode the request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.BaseURL, "/")+endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("innsegl: build the request to the core: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("innsegl: the core at %s could not be reached: %w", c.BaseURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("innsegl: read the core's answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var refusal struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &refusal) == nil && refusal.Error != "" {
			return fmt.Errorf("innsegl: the core refused (%d): %s", resp.StatusCode, refusal.Error)
		}
		return fmt.Errorf("innsegl: the core answered %d", resp.StatusCode)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("innsegl: the core's answer is not the expected shape: %w", err)
	}
	return nil
}

// GitPathPrefix is where a hosted core receives a repository's objects
// (ADR-0065): <GitPathPrefix><host>/<org>/<name>.git, git's smart HTTP.
const GitPathPrefix = "/_core/git/"

// StagingRefPrefix names the refs a client pushes the objects of a commit
// about to be signed to.
const StagingRefPrefix = "refs/innsegl/staging/"

// StagingRef is the one ref an installation pushes a tool call's objects to.
func StagingRef(installation, toolUseID string) string {
	return StagingRefPrefix + installation + "/" + toolUseID
}

// clientStatusPath is the client service's own status route
// (internal/client.StatusPath, repeated: that package's tests import this
// one's, and the value is pinned by a test that imports both).
const clientStatusPath = "/_client/status"

// Stage pushes the objects a commit payload names -- its tree and parents --
// to the hosted core's mirror of dir's repository, on this installation's
// staging ref for toolUseID (#465, ADR-0065). The core computes the change's
// identity from them, and on a hosted core they exist only here.
//
// Only a client service is pushed to: it alone is plain http on loopback
// and answers its status route with an installation. Against the
// single-host core (https, the agent's checkout on the same disk) Stage does
// nothing.
//
// git cannot push a bare tree, so the push carries a throwaway commit of the
// tree and parents. It is written to a temporary object directory, never to
// the repository's own: a refused commit leaves no commit object behind
// (CMT-014).
func (c Client) Stage(ctx context.Context, dir, toolUseID string, payload []byte) error {
	if !strings.HasPrefix(c.BaseURL, "http://") {
		return nil
	}
	installation, ok := c.installation(ctx)
	if !ok {
		return nil
	}
	if !IsToolUseID(toolUseID) {
		return fmt.Errorf("%q is not a tool call id", toolUseID)
	}
	tree, parents, err := payloadObjects(payload)
	if err != nil {
		return err
	}
	repo, err := workspace.RepoID(ctx, dir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	objects, err := stageGit(ctx, dir, nil, "rev-parse", "--path-format=absolute", "--git-path", "objects")
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "innsegl-stage-")
	if err != nil {
		return fmt.Errorf("a temporary object directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	env := []string{
		"GIT_OBJECT_DIRECTORY=" + tmp,
		"GIT_ALTERNATE_OBJECT_DIRECTORIES=" + objects,
		// A fixed identity and date: the staging commit is the same object
		// for the same tree and parents, whoever runs it.
		"GIT_AUTHOR_NAME=innsegl", "GIT_AUTHOR_EMAIL=staging@innsegl.invalid", "GIT_AUTHOR_DATE=@0 +0000",
		"GIT_COMMITTER_NAME=innsegl", "GIT_COMMITTER_EMAIL=staging@innsegl.invalid", "GIT_COMMITTER_DATE=@0 +0000",
	}
	args := []string{"commit-tree", "--no-gpg-sign", "-m", "innsegl staging"}
	for _, p := range parents {
		args = append(args, "-p", p)
	}
	commit, err := stageGit(ctx, dir, env, append(args, tree)...)
	if err != nil {
		return err
	}
	remote := strings.TrimSuffix(c.BaseURL, "/") + GitPathPrefix + repo + ".git"
	_, err = stageGit(ctx, dir, env, "-c", "push.gpgSign=false", "-c", "http.followRedirects=false",
		"push", "--no-verify", "--quiet", remote, "+"+commit+":"+StagingRef(installation, toolUseID))
	return err
}

// installation asks the client service which installation it is. Any
// answer but a 200 naming one means this is not a client service.
func (c Client) installation(ctx context.Context) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(c.BaseURL, "/")+clientStatusPath, nil)
	if err != nil {
		return "", false
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()
	var st struct {
		InstallationID string `json:"installation_id"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&st) != nil {
		return "", false
	}
	return st.InstallationID, st.InstallationID != ""
}

// payloadObjects reads the tree and parent lines of an unsigned commit
// object's header.
func payloadObjects(payload []byte) (tree string, parents []string, err error) {
	header, _, _ := strings.Cut(string(payload), "\n\n")
	for _, line := range strings.Split(header, "\n") {
		key, val, _ := strings.Cut(line, " ")
		switch key {
		case "tree":
			tree = val
		case "parent":
			parents = append(parents, val)
		}
	}
	for _, oid := range append([]string{tree}, parents...) {
		if !isObjectID(oid) {
			return "", nil, fmt.Errorf("the commit object names %q, which is not an object id", oid)
		}
	}
	return tree, parents, nil
}

func isObjectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// stageGit runs git in dir with the process's environment plus extra, never
// prompting, and never through a proxy to the loopback client service.
func stageGit(ctx context.Context, dir string, extra []string, args ...string) (string, error) {
	// G204: an argument list, never shell text; args are this package's own
	// and validated object ids.
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...) //nolint:gosec // see above
	cmd.Env = append(append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"NO_PROXY="+noProxy(os.Getenv("NO_PROXY")), "no_proxy="+noProxy(os.Getenv("no_proxy")),
	), extra...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

func noProxy(existing string) string {
	const loopback = "127.0.0.1,localhost,::1"
	if existing == "" {
		return loopback
	}
	return existing + "," + loopback
}

// Window is how long after the core relayed a `git commit` tool call that
// call may still authorise a commit. The entry also ends when the call's
// result arrives, so in practice the bound is the command's own run.
const Window = 30 * time.Minute

// RelayedCall is a tool call the core relayed whose result has not arrived.
type RelayedCall struct {
	RunID string
	// WorkingDirectory is where the harness said the agent works, on the
	// request whose reply carried this tool call. The core checks it is the
	// run's own repository before reading anything from it.
	WorkingDirectory string
	Tool             string
	Input            json.RawMessage
	Truncated        bool
	ObservedAt       time.Time
	// Installation is the client installation whose request carried the
	// call (ADR-0063); empty in the single-host shape.
	Installation string
}

// Resolver finds a relayed, still-running tool call by its id.
type Resolver interface {
	LookupPending(toolUseID string) (RelayedCall, bool)
}

// ScopedResolver answers only the calls the given installation relayed. On
// a hosted core every commit-path request carries its caller's verified
// installation, and a call relayed for another installation (or for none) is
// not found: both routes then refuse it exactly as they refuse an id that was
// never relayed, so the refusal says nothing about whose call it was.
func ScopedResolver(base Resolver, installation string) Resolver {
	return scopedResolver{base: base, installation: installation}
}

type scopedResolver struct {
	base         Resolver
	installation string
}

func (s scopedResolver) LookupPending(toolUseID string) (RelayedCall, bool) {
	call, ok := s.base.LookupPending(toolUseID)
	if !ok || call.Installation == "" || call.Installation != s.installation {
		return RelayedCall{}, false
	}
	return call, true
}

type resolverContextKey struct{}

// WithResolver attaches the resolver a request's commit-path calls use.
func WithResolver(ctx context.Context, r Resolver) context.Context {
	return context.WithValue(ctx, resolverContextKey{}, r)
}

// ResolverFrom answers the request's resolver, or fallback when it carries
// none (the single-host shape).
func ResolverFrom(ctx context.Context, fallback Resolver) Resolver {
	if r, ok := ctx.Value(resolverContextKey{}).(Resolver); ok && r != nil {
		return r
	}
	return fallback
}

// Resolve is ADR-0059 decision 4's first gate: the id names a Bash tool call
// the core relayed, whose command runs `git commit`, whose input arrived
// whole, whose result has not arrived yet, and which is inside Window. Both
// the trailer endpoint and the signing endpoint call it, so a commit is
// authorised the same way at both steps. Every refusal names its reason.
func Resolve(r Resolver, toolUseID string, now time.Time) (RelayedCall, error) {
	if toolUseID == "" {
		return RelayedCall{}, fmt.Errorf("no tool call id: this git commit was not run by an agent through the gateway (%s is unset)", EnvToolUseID)
	}
	if !IsToolUseID(toolUseID) {
		return RelayedCall{}, fmt.Errorf("%q is not a tool call id", toolUseID)
	}
	call, ok := r.LookupPending(toolUseID)
	if !ok {
		return RelayedCall{}, fmt.Errorf("no relayed tool call %s is running", toolUseID)
	}
	if call.Truncated {
		return RelayedCall{}, fmt.Errorf("tool call %s was truncated, so its command cannot be read", toolUseID)
	}
	var input struct {
		Command string `json:"command"`
	}
	if call.Tool != "Bash" || json.Unmarshal(call.Input, &input) != nil || !IsGitCommitCommand(input.Command) {
		return RelayedCall{}, fmt.Errorf("tool call %s is not a git commit", toolUseID)
	}
	if now.Sub(call.ObservedAt) > Window {
		return RelayedCall{}, fmt.Errorf("tool call %s is older than %s", toolUseID, Window)
	}
	return call, nil
}
