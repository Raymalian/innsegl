// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/client/clienttest"
)

// OAI-019/020/025: connect updates installed Codex's managed defaults, so
// ordinary and resumed sessions do not need the optional capture launcher.
func TestOAI025ConnectInstallsCodexManagedSettings(t *testing.T) {
	f := newConnectFixture(t)
	f.deps.codexSettings = filepath.Join(t.TempDir(), "managed_config.toml")
	f.deps.codexCapabilities = func(context.Context, string) (codexCapabilities, error) {
		return codexCapabilities{Formats: []string{"responses-http"}, Agents: "linked-threads", Signing: true, SigningMode: "structured"}, nil
	}
	f.deps.loadCodex = func(context.Context, client.CodexManagedConfig) error { return nil }
	if code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile, "--managed-settings", f.settings, "--no-service"); code != exitOK {
		t.Fatal(stderr)
	}
	text, err := os.ReadFile(f.deps.codexSettings)
	if err != nil {
		t.Fatalf("ordinary Codex has no managed setup: %v", err)
	}
	for _, want := range []string{"hooks.SessionStart=", "hooks.SubagentStart=", "http://127.0.0.1:28195/backend-api/codex"} {
		if !strings.Contains(string(text), want) {
			t.Errorf("missing %q", want)
		}
	}
	if code, _, stderr := f.connect("--update", "--managed-settings", f.settings); code != exitOK {
		t.Fatal(stderr)
	}
	if code, _, stderr := f.connect("--pause", "--managed-settings", f.settings); code != exitOK {
		t.Fatal(stderr)
	}
	paused := readFile(t, f.deps.codexSettings)
	if strings.Contains(string(paused), "\nmodel_provider=") {
		t.Fatal("Codex still routed while paused")
	}
	if code, _, stderr := f.connect("--resume", "--managed-settings", f.settings); code != exitOK {
		t.Fatal(stderr)
	}
	resumed := readFile(t, f.deps.codexSettings)
	if string(resumed) != string(text) {
		t.Fatal("resume did not restore Codex settings")
	}
	if code, _, stderr := f.connect("--disconnect", "--managed-settings", f.settings, "--no-service"); code != exitOK {
		t.Fatal(stderr)
	}
	removed := readFile(t, f.deps.codexSettings)
	if strings.Contains(string(removed), "INNSEGL CODEX") {
		t.Fatal("disconnect left Codex attached to a missing client")
	}
}

func TestOAI025ManagedCodexDoesNotDuplicateLauncherHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed_config.toml")
	if err := client.InstallCodexSettings(path, client.CodexManagedConfig{LocalURL: "http://127.0.0.1:28195", HookBin: connectTestBin}, time.Now, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	code := codexCommandWithManaged(nil, &out, &stderr, func() (string, error) { t.Fatal("selected hooks for a duplicate launcher"); return "", nil }, path)
	if code != exitUsage || !strings.Contains(stderr.String(), "run `codex`") {
		t.Fatalf("missing ordinary launch guidance: %d %s", code, stderr.String())
	}
}

func TestOAI025ConnectPreservesCodexModeAndChecksLoadedSettings(t *testing.T) {
	f := newConnectFixture(t)
	f.deps.codexSettings = filepath.Join(t.TempDir(), "managed_config.toml")
	f.deps.codexCapabilities = func(context.Context, string) (codexCapabilities, error) {
		return codexCapabilities{Formats: []string{"responses-http"}, Agents: "linked-threads", Signing: true, SigningMode: "structured"}, nil
	}
	f.deps.loadCodex = func(context.Context, client.CodexManagedConfig) error { return nil }
	if code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile, "--managed-settings", f.settings, "--no-service", "--codex-api", "--codex-sign-commits"); code != exitOK {
		t.Fatal(stderr)
	}
	if code, _, stderr := f.connect("--update", "--managed-settings", f.settings); code != exitOK {
		t.Fatal(stderr)
	}
	api, signing, err := client.CodexManagedMode(f.deps.codexSettings)
	if err != nil || !api || !signing {
		t.Fatalf("update lost mode: %v %v %v", api, signing, err)
	}
	f.deps.loadCodex = func(context.Context, client.CodexManagedConfig) error {
		return errors.New("effective configuration differs")
	}
	code, stdout, _ := f.connect("--update", "--managed-settings", f.settings)
	if code == exitOK || strings.Contains(stdout, "ordinary `codex`") {
		t.Fatal("reported routing success without loaded configuration")
	}
	f.deps.loadCodex = func(context.Context, client.CodexManagedConfig) error { return nil }
	if code, _, stderr := f.connect("--update", "--managed-settings", f.settings, "--codex-api=false", "--codex-sign-commits=false"); code != exitOK {
		t.Fatal(stderr)
	}
	api, signing, err = client.CodexManagedMode(f.deps.codexSettings)
	if err != nil || api || signing {
		t.Fatal("explicit mode reset was ignored")
	}
}

// CLI-015/036: privileged Codex settings are preflighted before a token is
// consumed or the previously working harness setup changes.
func TestCLI036CodexSetupFailureDoesNotSpendEnrollmentToken(t *testing.T) {
	f := newConnectFixture(t)
	f.deps.codexSettings = filepath.Join(t.TempDir(), "managed_config.toml")
	f.deps.codexCapabilities = func(context.Context, string) (codexCapabilities, error) {
		return codexCapabilities{Formats: []string{"responses-http"}, Agents: "linked-threads", Signing: true, SigningMode: "structured"}, nil
	}
	f.deps.loadCodex = func(context.Context, client.CodexManagedConfig) error { return nil }
	if err := os.WriteFile(f.deps.codexSettings, []byte("model = ["), 0600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile, "--managed-settings", f.settings, "--no-service"); code == exitOK {
		t.Fatal("accepted invalid Codex setup")
	}
	if err := os.Remove(f.deps.codexSettings); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile, "--managed-settings", f.settings, "--no-service"); code != exitOK {
		t.Fatalf("token was spent before setup preflight: %s", stderr)
	}
}

func TestOAI023ManagedCodexNegotiatesBeforeActivation(t *testing.T) {
	for _, mode := range []string{"root-only", "no-signing", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			f := newConnectFixture(t)
			if code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile, "--managed-settings", f.settings, "--no-service"); code != exitOK {
				t.Fatal(stderr)
			}
			f.deps.codexSettings = filepath.Join(t.TempDir(), "managed_config.toml")
			f.deps.codexCapabilities = func(context.Context, string) (codexCapabilities, error) {
				return codexCapabilities{Formats: []string{"responses-http"}, Agents: "linked-threads", Signing: true, SigningMode: "structured"}, nil
			}
			f.deps.loadCodex = func(context.Context, client.CodexManagedConfig) error {
				t.Fatal("verified unnegotiated settings")
				return nil
			}
			f.deps.codexCapabilities = func(context.Context, string) (codexCapabilities, error) {
				caps := codexCapabilities{Formats: []string{"responses-http"}, Agents: "linked-threads", Signing: true, SigningMode: "structured"}
				if mode == "root-only" {
					caps.Agents = "root-only"
				}
				if mode == "no-signing" {
					caps.Signing = false
				}
				if mode == "unavailable" {
					return caps, errors.New("unavailable")
				}
				return caps, nil
			}
			original := []byte("# administrator defaults\n")
			if err := os.WriteFile(f.deps.codexSettings, original, 0600); err != nil {
				t.Fatal(err)
			}
			if code, _, _ := f.connect("--update", "--managed-settings", f.settings, "--no-service", "--codex-sign-commits"); code == exitOK {
				t.Fatal("unverified managed setup succeeded")
			}
			if got := readFile(t, f.deps.codexSettings); !bytes.Equal(got, original) {
				t.Fatal("activated unsupported managed configuration")
			}
		})
	}
}

func TestOAI025CodexFailureDoesNotSkipEnrolledClientService(t *testing.T) {
	f := newConnectFixture(t)
	f.deps.codexSettings = filepath.Join(t.TempDir(), "managed_config.toml")
	f.deps.codexCapabilities = func(context.Context, string) (codexCapabilities, error) {
		return codexCapabilities{Formats: []string{"responses-http"}, Agents: "linked-threads", Signing: true, SigningMode: "structured"}, nil
	}
	f.deps.codexCapabilities = func(context.Context, string) (codexCapabilities, error) {
		return codexCapabilities{Formats: []string{"responses-http"}, Agents: "linked-threads"}, nil
	}
	f.deps.loadCodex = func(context.Context, client.CodexManagedConfig) error {
		return errors.New("unsupported configuration RPC")
	}
	code, stdout, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile, "--managed-settings", f.settings)
	if code == exitOK {
		t.Fatal("incomplete setup reported success")
	}
	if _, err := os.Stat(f.deps.service().Path()); err != nil {
		t.Fatalf("Codex failure skipped required client service: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "installed and started the client service") || !strings.Contains(stderr, "connect --update") {
		t.Fatalf("missing working-client/recovery guidance: %s\n%s", stdout, stderr)
	}
}

func TestCLI036ManagedCodexPrivilegeRecoveryPreservesOperation(t *testing.T) {
	for _, operation := range []string{"pause", "resume", "disconnect"} {
		t.Run(operation, func(t *testing.T) {
			f := newConnectFixture(t)
			f.deps.codexSettings = filepath.Join(t.TempDir(), "managed_config.toml")
			f.deps.loadCodex = func(context.Context, client.CodexManagedConfig) error { return nil }
			f.deps.codexCapabilities = func(context.Context, string) (codexCapabilities, error) {
				return codexCapabilities{Formats: []string{"responses-http"}, Agents: "linked-threads"}, nil
			}
			if code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile, "--managed-settings", f.settings, "--no-service"); code != exitOK {
				t.Fatal(stderr)
			}
			if operation == "resume" {
				if code, _, stderr := f.connect("--pause", "--managed-settings", f.settings); code != exitOK {
					t.Fatal(stderr)
				}
			}
			before := readFile(t, f.deps.codexSettings)
			if err := os.Chmod(f.deps.codexSettings, 0400); err != nil {
				t.Fatal(err)
			}
			code, _, stderr := f.connect("--"+operation, "--managed-settings", f.settings, "--no-service")
			if code == exitOK || !strings.Contains(stderr, "`innsegl connect --"+operation+"`") || strings.Contains(stderr, "`innsegl connect --update`") {
				t.Fatalf("wrong recovery for %s: %d %s", operation, code, stderr)
			}
			if !bytes.Equal(before, readFile(t, f.deps.codexSettings)) {
				t.Fatal("preflight modified live Codex settings")
			}
		})
	}
}

func TestOAI025AbsentCodexPreservesSharedClientSetup(t *testing.T) {
	f := newConnectFixture(t)
	f.deps.codexSettings = filepath.Join(t.TempDir(), "managed_config.toml")
	f.deps.codexUnavailable = true
	f.deps.loadCodex = func(context.Context, client.CodexManagedConfig) error { t.Fatal("started absent Codex"); return nil }
	before := []byte("# administrator settings\n")
	if err := os.WriteFile(f.deps.codexSettings, before, 0600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile, "--managed-settings", f.settings, "--no-service"); code != exitOK {
		t.Fatal(stderr)
	}
	if !bytes.Equal(before, readFile(t, f.deps.codexSettings)) {
		t.Fatal("changed Codex settings with no installed CLI")
	}
}
