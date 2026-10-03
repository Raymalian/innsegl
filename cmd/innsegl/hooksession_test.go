// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type capturedPost struct {
	url  string
	body map[string]string
}

func capturePosts(err error) (*[]capturedPost, func(string, []byte) error) {
	var posts []capturedPost
	return &posts, func(url string, body []byte) error {
		var m map[string]string
		if jerr := json.Unmarshal(body, &m); jerr != nil {
			return jerr
		}
		posts = append(posts, capturedPost{url: url, body: m})
		return err
	}
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// The hook input Claude Code 2.1.287 sends, captured 2026-10-01 (ids
// synthetic): every event carries session_id and cwd, subagent events also
// agent_id.
func TestHookSessionStatesTheSessionsDirectory(t *testing.T) {
	posts, post := capturePosts(nil)
	in := `{"session_id":"7dc5d783-9896-4aef-84d9-a82114505fff","cwd":"/workspace/repo","hook_event_name":"UserPromptSubmit","prompt":"hi"}`
	var out, errOut bytes.Buffer

	code := runHookSession(strings.NewReader(in), &out, &errOut, env(map[string]string{"INNSEGL_CORE_URL": "https://127.0.0.1:28095"}), post)

	if code != exitOK || out.Len() != 0 {
		t.Fatalf("exit = %d, stdout = %q; want 0 and nothing printed", code, out.String())
	}
	if len(*posts) != 1 {
		t.Fatalf("posts = %d, want 1", len(*posts))
	}
	p := (*posts)[0]
	if p.url != "https://127.0.0.1:28095/_gateway/session-workspace" {
		t.Errorf("url = %q", p.url)
	}
	if p.body["session_id"] != "7dc5d783-9896-4aef-84d9-a82114505fff" || p.body["cwd"] != "/workspace/repo" || p.body["agent_id"] != "" {
		t.Errorf("body = %v", p.body)
	}
}

func TestHookSessionStatesASubagentsDirectory(t *testing.T) {
	posts, post := capturePosts(nil)
	in := `{"session_id":"7dc5d783-9896-4aef-84d9-a82114505fff","cwd":"/workspace/repo/web","hook_event_name":"SubagentStart","agent_id":"aa328d4891c7406b1","agent_type":"general-purpose"}`

	runHookSession(strings.NewReader(in), &bytes.Buffer{}, &bytes.Buffer{}, env(nil), post)

	if len(*posts) != 1 || (*posts)[0].body["agent_id"] != "aa328d4891c7406b1" {
		t.Fatalf("posts = %+v, want one naming the subagent", *posts)
	}
}

// The hook never blocks the harness: a stack that is down, or input it
// cannot read, still exits 0 and prints nothing to stdout. A session with no
// statement is forwarded unrecorded by the core (RM-313).
func TestHookSessionNeverBlocksTheHarness(t *testing.T) {
	for name, tc := range map[string]struct {
		in      string
		postErr error
		posts   int
	}{
		"stack down":    {`{"session_id":"7dc5d783-9896-4aef-84d9-a82114505fff","cwd":"/w"}`, errors.New("connection refused"), 1},
		"not JSON":      {`nope`, nil, 0},
		"no session id": {`{"cwd":"/w"}`, nil, 0},
		"no cwd":        {`{"session_id":"7dc5d783-9896-4aef-84d9-a82114505fff"}`, nil, 0},
	} {
		t.Run(name, func(t *testing.T) {
			posts, post := capturePosts(tc.postErr)
			var out bytes.Buffer
			if code := runHookSession(strings.NewReader(tc.in), &out, &bytes.Buffer{}, env(nil), post); code != exitOK {
				t.Errorf("exit = %d, want 0", code)
			}
			if out.Len() != 0 {
				t.Errorf("stdout = %q, want nothing", out.String())
			}
			if len(*posts) != tc.posts {
				t.Errorf("posts = %d, want %d", len(*posts), tc.posts)
			}
		})
	}
}

// When the gateway cannot be reached at all -- Docker or the stack is down --
// every model request would fail with a bare "connection refused". Before a
// user turn, the hook stops the prompt instead (exit 2, which the harness
// shows the person) and says what is down and the two ways out. The prompt
// would have failed anyway; this only makes the failure readable.
func TestHookSessionStopsAPromptWhenTheGatewayIsUnreachable(t *testing.T) {
	_, post := capturePosts(&gatewayUnreachableError{err: errors.New("dial tcp 127.0.0.1:28095: connect: connection refused")})
	in := `{"session_id":"7dc5d783-9896-4aef-84d9-a82114505fff","cwd":"/w","hook_event_name":"UserPromptSubmit"}`
	var out, errOut bytes.Buffer

	code := runHookSession(strings.NewReader(in), &out, &errOut, env(nil), post)

	if code != exitBlock {
		t.Fatalf("exit = %d, want %d", code, exitBlock)
	}
	msg := errOut.String()
	for _, want := range []string{"not answering", "connection refused", "make start", "install.sh --pause"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q does not say %q", msg, want)
		}
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want nothing", out.String())
	}
}

// Only a user turn is stopped: the other events cannot be blocked usefully,
// and a gateway that answered with an error is up -- it explains itself.
func TestHookSessionStopsOnlyAUserTurnAndOnlyWhenUnreachable(t *testing.T) {
	unreachable := &gatewayUnreachableError{err: errors.New("connection refused")}
	for name, tc := range map[string]struct {
		event string
		err   error
	}{
		"session start, unreachable":  {"SessionStart", unreachable},
		"subagent start, unreachable": {"SubagentStart", unreachable},
		"user turn, gateway answered": {"UserPromptSubmit", errors.New("the gateway answered 429")},
	} {
		t.Run(name, func(t *testing.T) {
			_, post := capturePosts(tc.err)
			in := `{"session_id":"7dc5d783-9896-4aef-84d9-a82114505fff","cwd":"/w","hook_event_name":"` + tc.event + `"}`
			if code := runHookSession(strings.NewReader(in), &bytes.Buffer{}, &bytes.Buffer{}, env(nil), post); code != exitOK {
				t.Errorf("exit = %d, want 0", code)
			}
		})
	}
}

// A gateway that answers with a certificate this machine does not trust is
// up; what is wrong is the trust root. The message says so and names the fix.
func TestHookSessionNamesAnUntrustedGatewayCertificate(t *testing.T) {
	_, post := capturePosts(&gatewayUnreachableError{err: &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}})
	in := `{"session_id":"7dc5d783-9896-4aef-84d9-a82114505fff","cwd":"/w","hook_event_name":"UserPromptSubmit"}`
	var errOut bytes.Buffer

	if code := runHookSession(strings.NewReader(in), &bytes.Buffer{}, &errOut, env(nil), post); code != exitBlock {
		t.Fatalf("exit = %d, want %d", code, exitBlock)
	}
	for _, want := range []string{"certificate", "install.sh"} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("message %q does not say %q", errOut.String(), want)
		}
	}
	if strings.Contains(errOut.String(), "make start") {
		t.Errorf("message %q tells the person to start a stack that is already up", errOut.String())
	}
}

// RM-313: a statement the core refuses (an installation whose scope leaves
// the repository out) no longer disappears. Before a user turn the hook says
// so on one stderr line, which the harness shows in its debug output, and
// still exits 0: the session goes on, unrecorded.
func TestRM313HookSurfacesARefusedStatementOnOneLine(t *testing.T) {
	refused := &gatewayRefusedError{status: 401, msg: `{"error":"innsegl core: request refused"}`}
	_, post := capturePosts(refused)
	in := `{"session_id":"7dc5d783-9896-4aef-84d9-a82114505fff","cwd":"/w","hook_event_name":"UserPromptSubmit"}`
	var out, errOut bytes.Buffer
	if code := runHookSession(strings.NewReader(in), &out, &errOut, env(nil), post); code != exitOK {
		t.Fatalf("exit = %d, want 0: a refusal never stops the prompt", code)
	}
	msg := errOut.String()
	if strings.Count(msg, "\n") != 1 {
		t.Fatalf("stderr %q, want exactly one line", msg)
	}
	for _, want := range []string{"refused", "401", "scope", "unrecorded"} {
		if !strings.Contains(msg, want) {
			t.Errorf("stderr %q does not say %q", msg, want)
		}
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want nothing", out.String())
	}
}

// RM-313 never-block: a gateway that accepted the connection but did not
// answer in time is up and slow, or waiting on a core that is down. The
// model request may well go through (the client falls back to the
// provider), so the prompt is never stopped for it -- measured 2026-10-02,
// a core that did not answer stopped every prompt on the machine.
func TestHookSessionNeverStopsAPromptForASlowGateway(t *testing.T) {
	_, post := capturePosts(&gatewayUnreachableError{err: context.DeadlineExceeded})
	in := `{"session_id":"7dc5d783-9896-4aef-84d9-a82114505fff","cwd":"/w","hook_event_name":"UserPromptSubmit"}`
	var errOut bytes.Buffer
	if code := runHookSession(strings.NewReader(in), &bytes.Buffer{}, &errOut, env(nil), post); code != exitOK {
		t.Fatalf("exit = %d, want 0: a slow gateway stopped the prompt (%s)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "deadline") {
		t.Errorf("stderr %q does not say what happened", errOut.String())
	}
}

// RM-329 (#500): the proxy is for Claude Code's own requests. The hook
// removes the proxy variables that point at the client from the agent's
// shell (CLAUDE_ENV_FILE), so git, npm, go and gh never depend on the client
// being up, and never trust its CA. Variables that name another proxy are
// the person's own and stay.
func TestRM329TheHookTakesTheClientProxyOutOfTheAgentsShell(t *testing.T) {
	_, post := capturePosts(nil)
	envFile := filepath.Join(t.TempDir(), "sessionstart-hook-0.sh")
	vars := map[string]string{
		"INNSEGL_CORE_URL":    "http://127.0.0.1:28195",
		"HTTPS_PROXY":         "http://127.0.0.1:28195",
		"https_proxy":         "http://127.0.0.1:28195",
		"HTTP_PROXY":          "http://proxy.corp.example:3128",
		"NODE_EXTRA_CA_CERTS": filepath.Join(t.TempDir(), ".innsegl", "client", "proxy-ca.pem"),
		"CLAUDE_ENV_FILE":     envFile,
	}
	in := `{"session_id":"7dc5d783-9896-4aef-84d9-a82114505fff","cwd":"/w","hook_event_name":"SessionStart"}`
	for range 2 {
		if code := runHookSession(strings.NewReader(in), &bytes.Buffer{}, &bytes.Buffer{}, env(vars), post); code != exitOK {
			t.Fatalf("exit %d", code)
		}
	}
	got, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("no env file written: %v", err)
	}
	want := "unset HTTPS_PROXY https_proxy NODE_EXTRA_CA_CERTS\n"
	if string(got) != want {
		t.Fatalf("env file %q, want %q once", got, want)
	}
}

// Without the client as proxy there is nothing to remove, and nothing is
// written.
func TestRM329TheHookWritesNothingWhenTheClientIsNotTheProxy(t *testing.T) {
	_, post := capturePosts(nil)
	envFile := filepath.Join(t.TempDir(), "env.sh")
	vars := map[string]string{"INNSEGL_CORE_URL": "http://127.0.0.1:28195", "CLAUDE_ENV_FILE": envFile,
		"HTTPS_PROXY": "http://proxy.corp.example:3128"}
	in := `{"session_id":"7dc5d783-9896-4aef-84d9-a82114505fff","cwd":"/w","hook_event_name":"SessionStart"}`
	runHookSession(strings.NewReader(in), &bytes.Buffer{}, &bytes.Buffer{}, env(vars), post)
	if _, err := os.Stat(envFile); err == nil {
		t.Fatal("an env file was written with nothing to remove")
	}
}

// When a session ends, the hook tells the gateway, so the session's run is
// retired instead of standing active until the silence backstop (seven days
// by default). Measured 2026-10-03: with no SessionEnd hook installed, thirty
// finished sessions on one branch all stayed active. The signal names the
// session only, states no workspace, and never stops anything.
func TestHookSessionSignalsTheEndOfASession(t *testing.T) {
	posts, post := capturePosts(nil)
	in := `{"session_id":"7dc5d783-9896-4aef-84d9-a82114505fff","cwd":"/w","hook_event_name":"SessionEnd","reason":"prompt_input_exit"}`
	code := runHookSession(strings.NewReader(in), &bytes.Buffer{}, &bytes.Buffer{},
		env(map[string]string{"INNSEGL_CORE_URL": "http://127.0.0.1:28195"}), post)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if len(*posts) != 1 {
		t.Fatalf("posted %d times, want once", len(*posts))
	}
	p := (*posts)[0]
	if p.url != "http://127.0.0.1:28195"+gatewaySessionEndPath {
		t.Errorf("posted to %q", p.url)
	}
	if len(p.body) != 1 || p.body["session_id"] != "7dc5d783-9896-4aef-84d9-a82114505fff" {
		t.Errorf("body %v, want the session id alone", p.body)
	}
}

// An unreachable gateway at session end is said and never blocks: the
// session is over either way, and the silence backstop still retires it.
func TestHookSessionEndNeverBlocks(t *testing.T) {
	_, post := capturePosts(&gatewayUnreachableError{err: errors.New("connection refused")})
	in := `{"session_id":"7dc5d783-9896-4aef-84d9-a82114505fff","cwd":"/w","hook_event_name":"SessionEnd"}`
	if code := runHookSession(strings.NewReader(in), &bytes.Buffer{}, &bytes.Buffer{}, env(nil), post); code != exitOK {
		t.Fatalf("exit %d, want 0", code)
	}
}
