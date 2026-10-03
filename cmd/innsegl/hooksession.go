// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/workspace"
)

// sessionHookTimeout bounds one statement. The hook runs before every user
// turn, so it must never be what makes the harness slow: a stack that is up
// answers in milliseconds, and one that is down refuses the connection at
// once.
const sessionHookTimeout = 3 * time.Second

// exitBlock is a harness hook's "stop": on UserPromptSubmit, exit 2 stops
// the prompt and shows stderr to the person.
const exitBlock = 2

// gatewayUnreachableError is a statement that never reached the gateway: no
// connection, no TLS handshake, no answer in time. Distinct from the gateway
// answering with an error, which means it is up and has said why.
type gatewayUnreachableError struct{ err error }

func (e *gatewayUnreachableError) Error() string { return e.err.Error() }
func (e *gatewayUnreachableError) Unwrap() error { return e.err }

// gatewayRefusedError is a statement the gateway answered with an error
// status: it is up, and said no.
type gatewayRefusedError struct {
	status int
	msg    string
}

func (e *gatewayRefusedError) Error() string {
	if e.msg == "" {
		return fmt.Sprintf("the gateway answered %d", e.status)
	}
	return fmt.Sprintf("the gateway answered %d: %s", e.status, e.msg)
}

// unreachableMessage is what a person sees when their prompt is stopped
// because the gateway is down. It names the cause and both ways out.
func unreachableMessage(base string, err error) string {
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return fmt.Sprintf(`innsegl: the gateway at %s answered with a certificate this machine
does not trust (%v). The gateway's CA has changed since install.sh copied
it, so this prompt would fail.

  Fix it:  re-run install.sh from the innsegl checkout, then restart Claude Code
`, base, err)
	}
	// The hook runs as the checkout's own binary (install.sh), so its
	// directory is where make start and install.sh are.
	checkout := "<innsegl checkout>"
	if exe, exeErr := innseglBinaryPath(); exeErr == nil {
		checkout = filepath.Dir(exe)
	}
	return fmt.Sprintf(`innsegl: the gateway at %s is not answering (%v).
Every model request goes through it, so this prompt would fail.
The usual cause is Docker, or the innsegl stack, not running.

  Start it:              cd %s && make start
  Work without innsegl:  cd %s && ./install.sh --pause
                         then restart Claude Code; --resume puts it back
`, base, err, checkout, checkout)
}

// runHookSession is `innsegl hook session`: the harness's SessionStart,
// UserPromptSubmit, SubagentStart and CwdChanged hook. It reads the hook's
// own input -- session_id, cwd and, for a subagent, agent_id and agent_type,
// structured fields on every event (captured from Claude Code 2.1.287,
// 2026-10-01) --
// and states them to the gateway's local session-workspace endpoint, which
// is where the gateway learns each session's working directory
// (internal/gateway/workspaceregistry.go).
//
// It prints nothing to stdout and exits 0, like `hook pre-tool-use`: the
// gateway is the gate, not this hook. One exception: before a user turn,
// when the gateway cannot be reached at all, it stops the prompt (exit 2)
// with a message saying what is down and how to get out -- the request would
// fail anyway, with nothing but "connection refused". A gateway that took the
// connection but did not answer in time is never a stop: it is up, and the
// model request may still go through. A statement that does
// not arrive, or that the core refuses, never stops a session: the core
// forwards its requests unrecorded (RM-313), and the next hook event states
// it again. Failures go to stderr, which the harness shows only in its debug
// output; a refusal before a user turn is said on one line of its own.
func runHookSession(stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string,
	post func(url string, body []byte) error,
) int {
	_ = stdout // never written: a hook's stdout can be read as instructions
	ctx, cancel := context.WithTimeout(context.Background(), sessionHookTimeout)
	defer cancel()
	var in struct {
		SessionID     string `json:"session_id"`
		AgentID       string `json:"agent_id"`
		AgentType     string `json:"agent_type"`
		Cwd           string `json:"cwd"`
		HookEventName string `json:"hook_event_name"`
	}
	if err := json.NewDecoder(io.LimitReader(stdin, 1<<20)).Decode(&in); err != nil {
		fmt.Fprintf(stderr, "innsegl hook session: the hook input is not JSON: %v\n", err)
		return exitOK
	}
	scrubProxyFromShell(getenv, stderr)
	if in.SessionID == "" || in.Cwd == "" {
		fmt.Fprintln(stderr, "innsegl hook session: the hook input names no session_id or cwd")
		return exitOK
	}
	base := getenv(commitpath.EnvCoreURL)
	if base == "" {
		base = commitpath.DefaultCoreURL
	}
	if in.HookEventName == "SessionEnd" || (in.HookEventName == "SubagentStop" && in.AgentID != "") {
		// The session, or one subagent, is over: say so, so its run is
		// retired now rather than by the silence backstop days later. Never
		// a stop.
		end := map[string]string{"session_id": in.SessionID}
		if in.HookEventName == "SubagentStop" {
			end["agent_id"] = in.AgentID
		}
		body, err := json.Marshal(end)
		if err == nil {
			err = post(strings.TrimSuffix(base, "/")+gatewaySessionEndPath, body)
		}
		if err != nil {
			fmt.Fprintf(stderr, "innsegl hook session: signalling the end of the session: %v\n", err)
		}
		return exitOK
	}
	statement := map[string]string{"session_id": in.SessionID, "agent_id": in.AgentID, "cwd": in.Cwd}
	// RM-314: the harness's own name for the subagent's type, as it sent it.
	// The gateway folds it; the model's subagent_type is only a witness.
	if in.AgentType != "" {
		statement["agent_type"] = in.AgentType
	}
	// The client derives the workspace itself (internal/workspace) and states
	// it; the core binds it to the caller's scope. A directory that is not a
	// working tree with a usable origin states the directory alone: the hook
	// never fails on one, and the gateway resolves a bare directory the
	// single-host way.
	if derived, derr := workspace.Derive(ctx, in.Cwd); derr == nil {
		// A repository is signable from its first use: link it when
		// innsegl's prepare-commit-msg hook is not there yet, so its agent
		// commits carry the run's trailers the core signs against.
		if _, lerr := linkEnsure(ctx, derived.Main); lerr != nil {
			fmt.Fprintf(stderr, "innsegl hook session: linking %s for signing: %v\n", derived.Main, lerr)
		}
		statement["repo"] = derived.Repo
		statement["worktree"] = derived.Worktree
		statement["branch"] = derived.Branch
		statement["task"] = derived.Task
		statement["head"] = derived.Head
	}
	body, err := json.Marshal(statement)
	if err != nil {
		return exitOK
	}
	err = post(strings.TrimSuffix(base, "/")+gatewaySessionWorkspacePath, body)
	var unreachable *gatewayUnreachableError
	var refused *gatewayRefusedError
	switch {
	case err == nil:
	case errors.As(err, &unreachable) && in.HookEventName == "UserPromptSubmit" && !isTimeout(err):
		fmt.Fprint(stderr, unreachableMessage(base, unreachable.err))
		return exitBlock
	case errors.As(err, &refused) && in.HookEventName == "UserPromptSubmit" &&
		(refused.status == http.StatusUnauthorized || refused.status == http.StatusForbidden):
		// RM-313: said, never hidden, and never a stop. The core forwards
		// this session's requests unrecorded.
		fmt.Fprintf(stderr, "innsegl: the core refused this session's statement (%d): the repository is outside "+
			"this installation's scope, or the session belongs to another installation; this session runs unrecorded\n",
			refused.status)
	default:
		fmt.Fprintf(stderr, "innsegl hook session: stating the working directory: %v\n", err)
	}
	return exitOK
}

// isTimeout reports whether err is the gateway taking too long rather than
// not being there: a context deadline or any network timeout.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

// clientProxyVars are the proxy variables managed settings point at the
// client (RM-329), in the order the unset line names them.
var clientProxyVars = []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"}

// proxyCASuffix ends the path NODE_EXTRA_CA_CERTS names when it is the
// client's proxy CA.
var proxyCASuffix = string(filepath.Separator) + filepath.Join(".innsegl", "client", "proxy-ca.pem")

// scrubProxyFromShell keeps the client's proxy out of the agent's shell
// (RM-329, #500). The proxy is for Claude Code's own requests; the harness
// gives every Bash command its environment, so without this git, npm, go
// and gh would depend on the client being up and would trust its CA. The
// harness runs what a hook appends to CLAUDE_ENV_FILE before each Bash
// command. Only variables that point at the client are removed: another
// proxy is the person's own.
func scrubProxyFromShell(getenv func(string) string, stderr io.Writer) {
	path := getenv("CLAUDE_ENV_FILE")
	if path == "" {
		return
	}
	base := strings.TrimSuffix(getenv(commitpath.EnvCoreURL), "/")
	if base == "" {
		base = commitpath.DefaultCoreURL
	}
	var names []string
	for _, k := range clientProxyVars {
		if v := strings.TrimSuffix(getenv(k), "/"); v != "" && v == base {
			names = append(names, k)
		}
	}
	if strings.HasSuffix(getenv("NODE_EXTRA_CA_CERTS"), proxyCASuffix) {
		names = append(names, "NODE_EXTRA_CA_CERTS")
	}
	if len(names) == 0 {
		return
	}
	line := "unset " + strings.Join(names, " ") + "\n"
	// #nosec G304 -- the harness names this file for this hook.
	if have, err := os.ReadFile(path); err == nil && strings.Contains(string(have), line) {
		return
	}
	// #nosec G302 G304 -- the harness's own per-session file, read by its shell.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(stderr, "innsegl hook session: keeping the proxy out of the agent's shell: %v\n", err)
		return
	}
	if _, err = f.WriteString(line); err != nil {
		fmt.Fprintf(stderr, "innsegl hook session: keeping the proxy out of the agent's shell: %v\n", err)
	}
	if err = f.Close(); err != nil {
		fmt.Fprintf(stderr, "innsegl hook session: keeping the proxy out of the agent's shell: %v\n", err)
	}
}

// postToGateway sends body with the client that trusts only the gateway's
// own CA (commitpath.TrustedHTTPClient), never the system roots.
func postToGateway(getenv func(string) string) func(string, []byte) error {
	client := commitpath.TrustedHTTPClient(getenv)
	client.Timeout = sessionHookTimeout
	return func(url string, body []byte) error {
		ctx, cancel := context.WithTimeout(context.Background(), sessionHookTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return &gatewayUnreachableError{err: err}
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			msg, readErr := io.ReadAll(io.LimitReader(resp.Body, 512))
			if readErr != nil {
				return &gatewayRefusedError{status: resp.StatusCode}
			}
			return &gatewayRefusedError{status: resp.StatusCode, msg: strings.TrimSpace(string(msg))}
		}
		return nil
	}
}
