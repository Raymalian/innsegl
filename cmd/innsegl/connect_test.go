// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/client/clienttest"
)

const connectTestBin = "/opt/innsegl/bin/innsegl"

// connectGolden is the whole managed settings file connect writes into an
// empty target: the route and the hooks, nothing that locks the machine
// down (RM-312).
const connectGolden = `{
  "env": {
    "INNSEGL_CORE_URL": "http://127.0.0.1:28195",
    "HTTPS_PROXY": "http://127.0.0.1:28195",
    "https_proxy": "http://127.0.0.1:28195",
    "HTTP_PROXY": "http://127.0.0.1:28195",
    "http_proxy": "http://127.0.0.1:28195",
    "NO_PROXY": "127.0.0.1,localhost,::1",
    "no_proxy": "127.0.0.1,localhost,::1",
    "NODE_EXTRA_CA_CERTS": "<home>/.innsegl/client/proxy-ca.pem",
    "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
    "OTEL_LOGS_EXPORTER": "otlp",
    "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:28195"
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/opt/innsegl/bin/innsegl hook pre-tool-use"
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/opt/innsegl/bin/innsegl hook session"
          }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/opt/innsegl/bin/innsegl hook session"
          }
        ]
      }
    ],
    "SubagentStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/opt/innsegl/bin/innsegl hook session"
          }
        ]
      }
    ],
    "CwdChanged": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/opt/innsegl/bin/innsegl hook session"
          }
        ]
      }
    ],
    "SessionEnd": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/opt/innsegl/bin/innsegl hook session"
          }
        ]
      }
    ],
    "SubagentStop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/opt/innsegl/bin/innsegl hook session"
          }
        ]
      }
    ]
  },
  "attribution": {
    "commit": ""
  }
}
`

type connectFixture struct {
	core     *clienttest.Core
	home     string
	settings string
	caFile   string
	calls    [][]string
	deps     connectDeps
}

func newConnectFixture(t *testing.T) *connectFixture {
	t.Helper()
	core, err := clienttest.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(core.Close)
	f := &connectFixture{core: core, home: t.TempDir()}
	f.settings = filepath.Join(t.TempDir(), "managed-settings.json")
	f.caFile = filepath.Join(t.TempDir(), "core-ca.pem")
	if err := os.WriteFile(f.caFile, core.CAPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	f.deps = connectDeps{
		home:    f.home,
		binPath: func() (string, error) { return connectTestBin, nil },
		goos:    "darwin",
		uid:     501,
		run: func(name string, args ...string) error {
			f.calls = append(f.calls, append([]string{name}, args...))
			return nil
		},
		now:      func() time.Time { return time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC) },
		hostname: func() (string, error) { return "dev-laptop", nil },
	}
	return f
}

func (f *connectFixture) connect(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := runConnect(context.Background(), args, &stdout, &stderr, f.deps)
	return code, stdout.String(), stderr.String()
}

// assertNothingWritten checks that a refused connect left no client state,
// no managed settings and no service behind.
func (f *connectFixture) assertNothingWritten(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(f.home, ".innsegl", "client")); !os.IsNotExist(err) {
		t.Error("~/.innsegl/client was created")
	}
	if _, err := os.Stat(f.settings); !os.IsNotExist(err) {
		t.Error("managed settings were written")
	}
	if len(f.calls) != 0 {
		t.Errorf("service commands ran: %v", f.calls)
	}
	if _, err := os.Stat(filepath.Join(f.home, "Library")); !os.IsNotExist(err) {
		t.Error("a LaunchAgent was written")
	}
}

func TestCLI015ConnectEnrolsWritesFilesSettingsAndService(t *testing.T) {
	f := newConnectFixture(t)
	repo := t.TempDir()
	if out, err := exec.CommandContext(context.Background(), "git", "init", "-q", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	code, stdout, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile,
		"--managed-settings", f.settings, repo)
	if code != exitOK {
		t.Fatalf("connect = %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	dir := filepath.Join(f.home, ".innsegl", "client")
	for name, mode := range map[string]os.FileMode{
		"key.pem": 0o600, "cert.pem": 0o644, "bundle.pem": 0o644, "gateway-ca.pem": 0o644, "core.json": 0o644,
	} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if st.Mode().Perm() != mode {
			t.Errorf("%s mode %o, want %o", name, st.Mode().Perm(), mode)
		}
	}
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("client dir mode: %v %v", st, err)
	}
	ca := readFile(t, filepath.Join(dir, "gateway-ca.pem"))
	if !bytes.Equal(ca, f.core.CAPEM) {
		t.Error("gateway-ca.pem is not the core's CA")
	}
	cfg, err := client.ReadCoreConfig(client.ClientPaths(f.home))
	if err != nil || cfg.CoreURL != f.core.URL() || cfg.InstallationID != f.core.EnrolledID() {
		t.Errorf("core.json = %+v, %v", cfg, err)
	}
	if !reflect.DeepEqual(f.core.Names(), []string{"dev-laptop"}) {
		t.Errorf("enrolled names = %v, want the hostname", f.core.Names())
	}

	got := readFile(t, f.settings)
	want := strings.ReplaceAll(connectGolden, "<home>", f.home)
	if string(got) != want {
		t.Fatalf("managed settings differ\n--- got\n%s\n--- want\n%s", got, want)
	}

	plist := filepath.Join(f.home, "Library", "LaunchAgents", "dev.innsegl.client.plist")
	text, err := os.ReadFile(plist)
	if err != nil || !strings.Contains(string(text), "<string>"+connectTestBin+"</string>") {
		t.Fatalf("plist: %v\n%s", err, text)
	}
	wantCalls := [][]string{
		{"launchctl", "bootout", "gui/501/dev.innsegl.client"},
		{"launchctl", "bootstrap", "gui/501", plist},
	}
	if !reflect.DeepEqual(f.calls, wantCalls) {
		t.Errorf("service calls = %v, want %v", f.calls, wantCalls)
	}

	hook := filepath.Join(repo, ".git", "hooks", "prepare-commit-msg")
	if text, err := os.ReadFile(hook); err != nil || !strings.Contains(string(text), linkHookMarker) {
		t.Errorf("the repository was not linked: %v", err)
	}

	// A second connect refuses rather than enrol over the first.
	code, _, stderr = f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile, "--managed-settings", f.settings)
	if code == exitOK || !strings.Contains(stderr, "already connected") {
		t.Fatalf("second connect = %d: %s", code, stderr)
	}
}

func TestCLI015ConnectByFingerprint(t *testing.T) {
	f := newConnectFixture(t)
	code, stdout, stderr := f.connect(f.core.URL(), "--token", clienttest.Token,
		"--ca-fingerprint", f.core.Fingerprint(), "--name", "ci-runner", "--managed-settings", f.settings, "--no-service")
	if code != exitOK {
		t.Fatalf("connect = %d\n%s\n%s", code, stdout, stderr)
	}
	ca := readFile(t, filepath.Join(f.home, ".innsegl", "client", "gateway-ca.pem"))
	if !bytes.Equal(ca, f.core.CAPEM) {
		t.Error("the fetched CA is not the core's")
	}
	if !reflect.DeepEqual(f.core.Names(), []string{"ci-runner"}) {
		t.Errorf("names = %v", f.core.Names())
	}
	if len(f.calls) != 0 {
		t.Errorf("--no-service ran service commands: %v", f.calls)
	}
}

func TestCLI015ConnectRefusesWithoutATrustAnchor(t *testing.T) {
	f := newConnectFixture(t)
	code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--managed-settings", f.settings)
	if code != exitUsage || !strings.Contains(stderr, "--ca") || !strings.Contains(stderr, "--ca-fingerprint") {
		t.Fatalf("connect = %d: %s", code, stderr)
	}
	if n, _ := f.core.Counts(); n != 0 {
		t.Fatal("the token was sent without a trust anchor")
	}
	f.assertNothingWritten(t)
}

func TestCLI015ConnectRefusesAFingerprintMismatch(t *testing.T) {
	f := newConnectFixture(t)
	code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token,
		"--ca-fingerprint", "sha256:"+strings.Repeat("00", 32), "--managed-settings", f.settings)
	if code == exitOK || !strings.Contains(stderr, "fingerprint") {
		t.Fatalf("connect = %d: %s", code, stderr)
	}
	if n, _ := f.core.Counts(); n != 0 {
		t.Fatal("the token was sent to a core whose CA did not match")
	}
	f.assertNothingWritten(t)
}

func TestCLI015ConnectEnrol401WritesNothing(t *testing.T) {
	f := newConnectFixture(t)
	bad := "ie_ffffffffffffffff_" + strings.Repeat("f", 64)
	code, _, stderr := f.connect(f.core.URL(), "--token", bad, "--ca", f.caFile, "--managed-settings", f.settings)
	if code == exitOK || !strings.Contains(stderr, "refused the enrolment token") {
		t.Fatalf("connect = %d: %s", code, stderr)
	}
	f.assertNothingWritten(t)
}

func TestCLI015ConnectReportsAnOutageAsRetryableAndWritesNothing(t *testing.T) {
	f := newConnectFixture(t)
	f.core.SetUnavailable(true)
	code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile, "--managed-settings", f.settings)
	if code == exitOK || !strings.Contains(stderr, "tried again") || !strings.Contains(stderr, "Nothing was written") {
		t.Fatalf("connect = %d: %s", code, stderr)
	}
	f.assertNothingWritten(t)
}

func TestCLI015ConnectRefusesAMalformedToken(t *testing.T) {
	f := newConnectFixture(t)
	code, _, stderr := f.connect(f.core.URL(), "--token", "not-a-token", "--ca", f.caFile, "--managed-settings", f.settings)
	if code != exitUsage || !strings.Contains(stderr, "token") {
		t.Fatalf("connect = %d: %s", code, stderr)
	}
	f.assertNothingWritten(t)
}

func TestCLI015ConnectRefusesANonLoopbackListen(t *testing.T) {
	f := newConnectFixture(t)
	code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile,
		"--managed-settings", f.settings, "--listen", "0.0.0.0:28195")
	if code != exitUsage || !strings.Contains(stderr, "loopback") {
		t.Fatalf("connect = %d: %s", code, stderr)
	}
	f.assertNothingWritten(t)
}

func TestCLI015ConnectStopsBeforeEnrolmentWhenSettingsAreNotWritable(t *testing.T) {
	f := newConnectFixture(t)
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	f.settings = filepath.Join(blocker, "managed-settings.json")
	code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile, "--managed-settings", f.settings)
	if code == exitOK || !strings.Contains(stderr, "sudo install -m 0644") {
		t.Fatalf("connect = %d: %s", code, stderr)
	}
	if n, _ := f.core.Counts(); n != 0 {
		t.Fatal("the token was spent although the settings could not be written")
	}
	if _, err := os.Stat(filepath.Join(f.home, ".innsegl", "client")); !os.IsNotExist(err) {
		t.Error("client state was written")
	}
}

func TestENF009ConnectPauseResumeDisconnect(t *testing.T) {
	f := newConnectFixture(t)
	operator := "{\n  \"model\": \"opus\",\n  \"env\": {\n    \"MY_VAR\": \"kept\"\n  }\n}\n"
	if err := os.WriteFile(f.settings, []byte(operator), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile, "--managed-settings", f.settings); code != exitOK {
		t.Fatalf("connect: %s", stderr)
	}
	installed := readFile(t, f.settings)

	if code, _, stderr := f.connect("--pause", "--managed-settings", f.settings); code != exitOK {
		t.Fatalf("pause: %s", stderr)
	}
	if paused := readFile(t, f.settings+".paused"); !bytes.Equal(paused, installed) {
		t.Fatal("pause changed the bytes")
	}
	if code, _, stderr := f.connect("--resume", "--managed-settings", f.settings); code != exitOK {
		t.Fatalf("resume: %s", stderr)
	}
	if resumed := readFile(t, f.settings); !bytes.Equal(resumed, installed) {
		t.Fatal("resume did not restore the same bytes")
	}

	f.calls = nil
	if code, _, stderr := f.connect("--disconnect", "--managed-settings", f.settings); code != exitOK {
		t.Fatalf("disconnect: %s", stderr)
	}
	if got := readFile(t, f.settings); string(got) != operator {
		t.Fatalf("disconnect left\n%s\nwant the operator's own file\n%s", got, operator)
	}
	if _, err := os.Stat(filepath.Join(f.home, ".innsegl", "client")); !os.IsNotExist(err) {
		t.Error("~/.innsegl/client survived disconnect")
	}
	if _, err := os.Stat(filepath.Join(f.home, "Library", "LaunchAgents", "dev.innsegl.client.plist")); !os.IsNotExist(err) {
		t.Error("the LaunchAgent survived disconnect")
	}
	if !reflect.DeepEqual(f.calls, [][]string{{"launchctl", "bootout", "gui/501/dev.innsegl.client"}}) {
		t.Errorf("disconnect service calls = %v", f.calls)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
