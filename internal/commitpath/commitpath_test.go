// SPDX-License-Identifier: Apache-2.0

package commitpath

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIsGitCommitCommandFindsCommitAsGitsOwnSubcommand(t *testing.T) {
	for _, cmd := range []string{
		"git commit -m 'x'",
		"git add notes.txt && git commit -m \"add notes\"",
		"cd sub; git -C ../repo commit --amend --no-edit",
		"git -c user.name=a commit -F msg.txt",
		"GIT_EDITOR=true git commit",
		"/usr/bin/git commit -m x",
		"false || git --no-pager commit -m x",
		"git status\ngit commit -m two-lines",
	} {
		if !IsGitCommitCommand(cmd) {
			t.Errorf("IsGitCommitCommand(%q) = false, want true", cmd)
		}
	}
}

func TestIsGitCommitCommandIgnoresEverythingElse(t *testing.T) {
	for _, cmd := range []string{
		"",
		"git log --grep commit",
		"echo git commit",
		"git status",
		"gitk commit",
		"git -C commit status",
		"git show HEAD:commit.txt",
		"ls commit",
		"FOO=bar",
	} {
		if IsGitCommitCommand(cmd) {
			t.Errorf("IsGitCommitCommand(%q) = true, want false", cmd)
		}
	}
}

func TestIsToolUseIDAcceptsTheHarnessShapeOnly(t *testing.T) {
	for _, id := range []string{"toolu_01ABCdef234", "toolu_vrtx_01XyZ"} {
		if !IsToolUseID(id) {
			t.Errorf("IsToolUseID(%q) = false", id)
		}
	}
	for _, id := range []string{"", "toolu_", "tool_01", "toolu_01 x", "toolu_01;rm", strings.Repeat("a", 200)} {
		if IsToolUseID(id) {
			t.Errorf("IsToolUseID(%q) = true", id)
		}
	}
}

// TestDefaultCoreURLIsHTTPS pins RM-246's contract literally: the gateway
// listener is https, on the same loopback address and port as before.
func TestDefaultCoreURLIsHTTPS(t *testing.T) {
	if DefaultCoreURL != "https://127.0.0.1:28095" {
		t.Errorf("DefaultCoreURL = %q, want %q", DefaultCoreURL, "https://127.0.0.1:28095")
	}
}

// TestCAFilePrefersNodeExtraCACerts is CAFile's own contract: read
// $NODE_EXTRA_CA_CERTS first (the SAME variable an installer points a
// Node-style client at, RM-246), falling back to
// $HOME/.innsegl/ca/gateway-ca.pem.
func TestCAFilePrefersNodeExtraCACerts(t *testing.T) {
	got := CAFile(func(k string) string {
		if k == EnvExtraCACerts {
			return "/custom/ca.pem"
		}
		return ""
	})
	if got != "/custom/ca.pem" {
		t.Errorf("CAFile with NODE_EXTRA_CA_CERTS set = %q, want %q", got, "/custom/ca.pem")
	}

	got = CAFile(func(k string) string {
		if k == "HOME" {
			return "/home/op"
		}
		return ""
	})
	want := filepath.Join("/home/op", ".innsegl", "ca", "gateway-ca.pem")
	if got != want {
		t.Errorf("CAFile with no NODE_EXTRA_CA_CERTS = %q, want %q", got, want)
	}
}

func TestClientFromEnvDefaultsToTheLoopbackGateway(t *testing.T) {
	c := ClientFromEnv(func(string) string { return "" })
	if c.BaseURL != DefaultCoreURL {
		t.Errorf("BaseURL = %q, want %q", c.BaseURL, DefaultCoreURL)
	}
	c = ClientFromEnv(func(k string) string {
		if k == EnvCoreURL {
			return "http://127.0.0.1:1"
		}
		return ""
	})
	if c.BaseURL != "http://127.0.0.1:1" {
		t.Errorf("BaseURL = %q, want the environment's", c.BaseURL)
	}
}

func TestClientTrailersRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != TrailersPath || r.Method != http.MethodPost {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}
		var req TrailersRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode: %v", err)
		}
		if err := json.NewEncoder(w).Encode(TrailersResponse{Message: req.Message + "\n\nAgent-Run: run-x\n"}); err != nil {
			t.Errorf("encode: %v", err)
		}
	}))
	defer srv.Close()

	got, err := Client{BaseURL: srv.URL}.Trailers(t.Context(), TrailersRequest{ToolUseID: "toolu_01A", Message: "subject"})
	if err != nil {
		t.Fatalf("Trailers: %v", err)
	}
	if got.Message != "subject\n\nAgent-Run: run-x\n" {
		t.Errorf("Message = %q", got.Message)
	}
}

func TestClientSignRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != SignPath {
			t.Errorf("path %s", r.URL.Path)
		}
		var req SignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode: %v", err)
		}
		if string(req.Payload) != "tree abc\n" || strings.Join(req.Args, " ") != "--status-fd=2 -bsau key" {
			t.Errorf("request %+v", req)
		}
		if err := json.NewEncoder(w).Encode(SignResponse{Signature: []byte("SIG"), Status: []byte("[GNUPG:] SIG_CREATED \n")}); err != nil {
			t.Errorf("encode: %v", err)
		}
	}))
	defer srv.Close()

	got, err := Client{BaseURL: srv.URL}.Sign(t.Context(), SignRequest{
		ToolUseID: "toolu_01A", Args: []string{"--status-fd=2", "-bsau", "key"}, Payload: []byte("tree abc\n"),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if string(got.Signature) != "SIG" || !strings.Contains(string(got.Status), "SIG_CREATED") {
		t.Errorf("response %+v", got)
	}
}

// A refusal carries the core's own reason, so the host command can print
// why git made no commit.
func TestClientReportsTheCoresRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte(`{"error":"innsegl: no relayed git commit has tool call id toolu_01Z"}`)); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	defer srv.Close()

	_, err := Client{BaseURL: srv.URL}.Sign(t.Context(), SignRequest{ToolUseID: "toolu_01Z"})
	if err == nil || !strings.Contains(err.Error(), "no relayed git commit has tool call id toolu_01Z") {
		t.Fatalf("err = %v, want the core's own reason", err)
	}
	_, err = Client{BaseURL: srv.URL}.Trailers(t.Context(), TrailersRequest{ToolUseID: "toolu_01Z"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v, want the status named", err)
	}
}

func TestClientFailsWhenTheCoreIsUnreachableOrAnswersNonsense(t *testing.T) {
	if _, err := (Client{BaseURL: "http://127.0.0.1:1"}).Sign(t.Context(), SignRequest{}); err == nil {
		t.Error("an unreachable core gave no error")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte("not json")); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	defer srv.Close()
	if _, err := (Client{BaseURL: srv.URL}).Sign(t.Context(), SignRequest{}); err == nil {
		t.Error("a malformed answer gave no error")
	}
	if _, err := (Client{BaseURL: "::bad"}).Trailers(t.Context(), TrailersRequest{}); err == nil {
		t.Error("an unusable base URL gave no error")
	}
}

type fakeResolver map[string]RelayedCall

func (f fakeResolver) LookupPending(id string) (RelayedCall, bool) {
	c, ok := f[id]
	return c, ok
}

// CMT-006: only a relayed, still-running Bash `git commit` inside the window
// authorises a commit; every other id is refused by name.
func TestCMT006ResolveAuthorisesOnlyARelayedRunningGitCommit(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	call := func(tool, command string, age time.Duration, truncated bool) RelayedCall {
		input, err := json.Marshal(map[string]string{"command": command})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return RelayedCall{RunID: "run-a", Tool: tool, Input: input, Truncated: truncated, ObservedAt: now.Add(-age)}
	}
	res := fakeResolver{
		"toolu_ok":        call("Bash", "git add . && git commit -m x", time.Minute, false),
		"toolu_status":    call("Bash", "git status", time.Minute, false),
		"toolu_write":     call("Write", "git commit", time.Minute, false),
		"toolu_old":       call("Bash", "git commit -m x", Window+time.Second, false),
		"toolu_truncated": call("Bash", "git commit -m x", time.Minute, true),
		"toolu_badinput":  {RunID: "run-a", Tool: "Bash", Input: json.RawMessage(`"not an object"`), ObservedAt: now},
	}

	got, err := Resolve(res, "toolu_ok", now)
	if err != nil || got.RunID != "run-a" {
		t.Fatalf("Resolve(toolu_ok) = %+v, %v; want run-a", got, err)
	}
	for id, want := range map[string]string{
		"":                "no tool call id",
		"not-an-id":       "not a tool call id",
		"toolu_unknown":   "no relayed tool call",
		"toolu_status":    "not a git commit",
		"toolu_write":     "not a git commit",
		"toolu_old":       "older than",
		"toolu_truncated": "truncated",
		"toolu_badinput":  "not a git commit",
	} {
		if _, err := Resolve(res, id, now); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Resolve(%q) err = %v, want it to say %q", id, err, want)
		}
	}
}

// RM-309 (#489): scoped to an installation, the resolver does not see a tool
// call another installation relayed, so both commit-path routes refuse it
// exactly as they refuse a call that was never relayed.
func TestScopedResolverHidesAnotherInstallationsCall(t *testing.T) {
	base := fakeResolver{
		"toolu_a": {RunID: "run-a", Installation: "aaaa", Tool: "Bash"},
		"toolu_s": {RunID: "run-s", Tool: "Bash"}, // single-host: no installation
	}
	if _, ok := ScopedResolver(base, "aaaa").LookupPending("toolu_a"); !ok {
		t.Error("the relaying installation cannot see its own call")
	}
	if _, ok := ScopedResolver(base, "bbbb").LookupPending("toolu_a"); ok {
		t.Error("another installation sees the call")
	}
	if _, ok := ScopedResolver(base, "bbbb").LookupPending("toolu_s"); ok {
		t.Error("an installation sees a call no installation relayed")
	}

	_, unknown := Resolve(ScopedResolver(base, "bbbb"), "toolu_nope", time.Now())
	_, foreign := Resolve(ScopedResolver(base, "bbbb"), "toolu_a", time.Now())
	if unknown == nil || foreign == nil {
		t.Fatal("want both refused")
	}
	if strings.Replace(foreign.Error(), "toolu_a", "X", 1) != strings.Replace(unknown.Error(), "toolu_nope", "X", 1) {
		t.Errorf("refusals differ: %q vs %q", foreign, unknown)
	}
}

// The resolver a request carries overrides the configured one.
func TestResolverFromContext(t *testing.T) {
	base, scoped := fakeResolver{}, fakeResolver{"toolu_x": {RunID: "r"}}
	if ResolverFrom(context.Background(), base) == nil {
		t.Fatal("no fallback")
	}
	if _, ok := ResolverFrom(WithResolver(context.Background(), scoped), base).LookupPending("toolu_x"); !ok {
		t.Error("the request's resolver was not used")
	}
}
