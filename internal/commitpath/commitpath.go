// SPDX-License-Identifier: Apache-2.0

// Package commitpath is the contract of ADR-0059's commit path, shared by the
// host commands git runs (prepare-commit-msg, gpg.x509.program) and the core
// that answers them.
package commitpath

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
)

// Where the core answers, and how a host command finds it.
const (
	TrailersPath = "/_gateway/commit-trailers"
	SignPath     = "/_gateway/commit-sign"

	// EnvToolUseID carries the harness's tool call id into git's own
	// children (ADR-0059 decision 1).
	EnvToolUseID = "INNSEGL_TOOL_USE_ID"
	// EnvCoreURL overrides DefaultCoreURL.
	EnvCoreURL     = "INNSEGL_CORE_URL"
	DefaultCoreURL = "http://127.0.0.1:28095"
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

// IsGitCommitCommand reports whether a shell command runs `git commit`: in
// any of its simple commands, a `git` word whose subcommand, after git's own
// options, is `commit`. It is a reading of the command, not a shell parser:
// the harness hook uses it to decide where the tool call id goes, and the core
// uses it to require that the tool call it resolves asked for a commit. Both
// read it the same way because both call this.
func IsGitCommitCommand(cmd string) bool {
	for _, simple := range splitSimpleCommands(cmd) {
		if gitSubcommand(strings.Fields(simple)) == "commit" {
			return true
		}
	}
	return false
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

// ClientFromEnv builds a Client from EnvCoreURL, or DefaultCoreURL.
func ClientFromEnv(getenv func(string) string) Client {
	base := getenv(EnvCoreURL)
	if base == "" {
		base = DefaultCoreURL
	}
	return Client{BaseURL: base}
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

// Window is how long after the core relayed a `git commit` tool call that
// call may still authorise a commit. The entry also ends when the call's
// result arrives, so in practice the bound is the command's own run.
const Window = 30 * time.Minute

// RelayedCall is a tool call the core relayed whose result has not arrived.
type RelayedCall struct {
	RunID      string
	Tool       string
	Input      json.RawMessage
	Truncated  bool
	ObservedAt time.Time
}

// Resolver finds a relayed, still-running tool call by its id.
type Resolver interface {
	LookupPending(toolUseID string) (RelayedCall, bool)
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
