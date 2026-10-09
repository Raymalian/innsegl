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
		// Every subcommand that writes a commit object (#536).
		"git merge feature",
		"git -C ../repo merge --no-ff -m x feature",
		"git pull origin main",
		"git -c pull.rebase=false pull",
		"git revert HEAD",
		"git -C sub revert --no-edit abc123",
		"git cherry-pick abc123",
		"git cherry-pick -x abc123 def456",
		"git rebase main",
		"git -C ../repo rebase --onto main a b",
		"GIT_EDITOR=true git merge --no-edit feature",
		"git fetch && git merge origin/main",
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
		"echo git merge",
		"git log --merges",
		"git -C merge status",
		"git branch --merged",
		"git mergetool",
		"git fetch",
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

// TestInsertGitOptionsPutsThemBeforeTheCommitSubcommand (ENF-012, PROPOSED):
// the options land inside every commit-creating git invocation, immediately
// before its subcommand word — after git's own options, so an option the
// command itself passes comes first and the inserted one, which git reads
// last, wins. Nothing else moves.
func TestInsertGitOptionsPutsThemBeforeTheCommitSubcommand(t *testing.T) {
	opts := []string{"-c", "a.b=1", "-c", "c.d=2"}
	const ins = "-c a.b=1 -c c.d=2 "
	for _, c := range []struct{ in, want string }{
		{"git commit -m x", "git " + ins + "commit -m x"},
		{"git -C d commit -m x", "git -C d " + ins + "commit -m x"},
		{"a && git commit -m x", "a && git " + ins + "commit -m x"},
		{"GIT_X=1 git commit", "GIT_X=1 git " + ins + "commit"},
		{"git pull origin main", "git " + ins + "pull origin main"},
		{"git merge --no-ff feature", "git " + ins + "merge --no-ff feature"},
		{"git revert HEAD", "git " + ins + "revert HEAD"},
		{"git cherry-pick abc123", "git " + ins + "cherry-pick abc123"},
		{"git rebase main", "git " + ins + "rebase main"},
		// The command's own -c stays first; the inserted one is read last.
		{"git -c a.b=0 commit", "git -c a.b=0 " + ins + "commit"},
		{"git -c user.name=a --no-pager commit -F msg.txt", "git -c user.name=a --no-pager " + ins + "commit -F msg.txt"},
		{"/usr/bin/git commit -m x", "/usr/bin/git " + ins + "commit -m x"},
		{"git add . && git commit -m a; git commit -m b", "git add . && git " + ins + "commit -m a; git " + ins + "commit -m b"},
		{"git status\ngit commit -m two-lines", "git status\ngit " + ins + "commit -m two-lines"},
		{"false || git --no-pager commit -m x", "false || git --no-pager " + ins + "commit -m x"},
		{"git commit -m x 2>&1", "git " + ins + "commit -m x 2>&1"},
	} {
		if got := InsertGitOptions(c.in, opts); got != c.want {
			t.Errorf("InsertGitOptions(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestInsertGitOptionsLeavesQuotedTextAndOtherCommandsAlone (ENF-012,
// PROPOSED): a separator or a `git commit` inside a quoted argument is prose,
// not a command, so it is left byte for byte; a command with no
// commit-creating git invocation comes back unchanged.
func TestInsertGitOptionsLeavesQuotedTextAndOtherCommandsAlone(t *testing.T) {
	opts := []string{"-c", "a.b=1"}
	const ins = "-c a.b=1 "
	for _, c := range []struct{ in, want string }{
		{`git commit -m "fix; git commit later"`, `git ` + ins + `commit -m "fix; git commit later"`},
		{`git commit -m 'a && git commit -m b'`, `git ` + ins + `commit -m 'a && git commit -m b'`},
		{`git commit -m "one | git commit" && echo done`, `git ` + ins + `commit -m "one | git commit" && echo done`},
		{`git -C "my dir" commit -m x`, `git -C "my dir" ` + ins + `commit -m x`},
		{`git commit -m a\;b`, `git ` + ins + `commit -m a\;b`},
		{"git commit -m \"multi\nline\"", "git " + ins + "commit -m \"multi\nline\""},
		{`echo "x; git commit"`, `echo "x; git commit"`},
		{`echo 'git commit'`, `echo 'git commit'`},
		{"echo git commit", "echo git commit"},
		{"git status", "git status"},
		{"git -C commit status", "git -C commit status"},
		{"git log --grep commit", "git log --grep commit"},
		{"", ""},
	} {
		if got := InsertGitOptions(c.in, opts); got != c.want {
			t.Errorf("InsertGitOptions(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := InsertGitOptions("git commit -m x", nil); got != "git commit -m x" {
		t.Errorf("InsertGitOptions with no options = %q, want the command unchanged", got)
	}
}

// ADR-0079 decision 2: adoption is looked for only when every commit the
// command makes is a plain `git commit`, whose parent is HEAD.
func TestIsAdoptableCommitIsAPlainCommitOnly(t *testing.T) {
	for cmd, want := range map[string]bool{
		"git commit -m x":                       true,
		"git add -A && git commit -m 'feat: x'": true,
		"git -C ../repo commit -F msg.txt":      true,
		`git commit -m "do not --amend this"`:   true,
		"git commit --amend --no-edit":          false,
		"git commit -m x --amend":               false,
		"git merge dev":                         false,
		"git commit -m x && git rebase main":    false,
		"git cherry-pick abc123":                false,
		"git status":                            false,
		"":                                      false,
	} {
		if got := IsAdoptableCommit(cmd); got != want {
			t.Errorf("IsAdoptableCommit(%q) = %v, want %v", cmd, got, want)
		}
	}
}
