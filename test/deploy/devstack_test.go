// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// OPS-129 — a development stack is never the live one (RM-293, #469;
// ADR-0072).
//
// A machine that develops innsegl also runs a stack of its own. Until this
// test it ran it under the live names: the same compose projects, the same
// containers and networks, and the same trust volumes — so the Fulcio CA key
// that signed its commits was whatever `innsegl-trust-fulcio-pki` held on
// that machine. Nothing marked it as dev, and it could be started by accident.
//
// The mode is an explicit marker (scripts/stack-mode.sh): INNSEGL_STACK=dev,
// or `make dev-stack`, which writes .innsegl/stack-mode in the checkout. No
// marker is live, and live is byte-for-byte what it was. Being an enrolled
// client is a WARNING and never a switch: the core host connects to itself
// (install.sh --local-client), so "has core.json" is not "is not the core".
//
// Read the way OPS-127 reads the bind address: `make -n` and `docker compose
// config`, never a running stack.
// ---------------------------------------------------------------------------

// The live names as they were before this change. A live bring-up must keep
// every one of them: renaming a live project or volume orphans the deployment
// it names.
var (
	liveProjects = map[string]string{
		"spire.yml":    "innsegl-spire",
		"sigstore.yml": "innsegl-sigstore",
		"innsegl.yml":  "innsegl-core",
	}
	liveTrustVolumes = []string{
		"innsegl-trust-ledger-data",
		"innsegl-trust-identity-secret",
		"innsegl-trust-fulcio-pki",
		"innsegl-trust-rekor-key",
		"innsegl-trust-trillian-db",
	}
)

const (
	devPrefix      = "innsegl-dev"
	devTrustPrefix = "innsegl-dev-trust"
)

// stackEnv is the environment a test runs make or a script under: this
// process's, minus everything that chooses a stack or a bind, plus HOME and
// the mode the test asks for ("" leaves INNSEGL_STACK unset).
func stackEnv(home, mode string, extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch {
		case k == "HOME", k == "INNSEGL_BIND", k == "MAKEFLAGS", k == "MFLAGS",
			strings.HasPrefix(k, "INNSEGL_STACK"),
			strings.HasPrefix(k, "INNSEGL_TRUST_"),
			k == "INNSEGL_GATEWAY_CA_HOST_DIR", k == "INNSEGL_LOG_DIR",
			k == "INNSEGL_BACKUP_HOST_DIR":
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "HOME="+home,
		// No docker is asked which containers run: a test never depends on
		// what this machine happens to have up.
		"INNSEGL_STACK_DOCKER=true",
		"INNSEGL_REKOR_PORT=23000")
	if mode != "" {
		env = append(env, "INNSEGL_STACK="+mode)
	}
	return append(env, extra...)
}

// makeDryRun is what `make -n` would run for the targets, in a mode.
func makeDryRun(t *testing.T, mode string, targets ...string) string {
	t.Helper()
	if _, err := exec.LookPath("make"); err != nil {
		t.Skipf("make is not on PATH: %v", err)
	}
	args := append([]string{"-n", "--no-print-directory"}, targets...)
	cmd := exec.CommandContext(t.Context(), "make", args...)
	cmd.Dir = repoRoot(t)
	cmd.Env = stackEnv(t.TempDir(), mode)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n %v (INNSEGL_STACK=%s): %v\n%s", targets, mode, err, out)
	}
	return string(out)
}

// stackMode runs scripts/stack-mode.sh from root.
func stackMode(t *testing.T, root string, env []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), filepath.Join(root, "scripts", "stack-mode.sh"), args...)
	cmd.Dir = root
	cmd.Env = env
	var o, e strings.Builder
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	code = 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("running stack-mode.sh %v: %v", args, err)
		}
		code = ee.ExitCode()
	}
	return o.String(), e.String(), code
}

// envLines parses VAR=value lines.
func envLines(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			out[k] = v
		}
	}
	return out
}

// rawCompose is the part of `docker compose config` this test reads.
type rawCompose struct {
	Name     string `json:"name"`
	Services map[string]struct {
		ContainerName string `json:"container_name"`
		Volumes       []struct {
			Type   string `json:"type"`
			Source string `json:"source"`
			Target string `json:"target"`
		} `json:"volumes"`
	} `json:"services"`
	Networks map[string]struct {
		Name string `json:"name"`
	} `json:"networks"`
	Volumes map[string]struct {
		Name string `json:"name"`
	} `json:"volumes"`
}

// composeAllProfiles interpolates files with every profile on, so that no
// service a profile hides escapes the check.
func composeAllProfiles(ctx context.Context, t *testing.T, env []string, files ...string) rawCompose {
	t.Helper()
	root := repoRoot(t)
	args := []string{"compose", "--profile", "*"}
	for _, f := range files {
		args = append(args, "-f", filepath.Join(root, f))
	}
	args = append(args, "config", "--format", "json")
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = append(append([]string{}, env...),
		"INNSEGL_SPIRE_JWT_ISSUER="+composeJWTIssuer,
		"INNSEGL_SPIRE_PARENT_ID="+composeParentIDPlaceholder,
		"INNSEGL_OBJECT_STORE_ACCESS_KEY="+storeRootUser,
		"INNSEGL_OBJECT_STORE_SECRET_KEY="+storeRootPassword,
		"INNSEGL_OBJECT_STORE_BUCKET=innsegl-segments",
		// The real HOME, last so it wins: the compose plugin is found under
		// it, and a test HOME has none.
		"HOME="+os.Getenv("HOME"))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("interpolating %v: %v: %s", files, err, strings.TrimSpace(stderr.String()))
	}
	var cfg rawCompose
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("reading the interpolated configuration of %v: %v", files, err)
	}
	return cfg
}

// trustEnv is what the Makefile passes compose for the trust volumes under a
// prefix ("" is the default, live, prefix).
func trustEnv(t *testing.T, home, prefix string) []string {
	t.Helper()
	root := repoRoot(t)
	cmd := exec.CommandContext(t.Context(), filepath.Join(root, "deploy", "compose", "trust-volumes.sh"), "env")
	extra := []string{}
	if prefix != "" {
		extra = append(extra, "INNSEGL_TRUST_VOLUME_PREFIX="+prefix)
	}
	cmd.Env = stackEnv(home, "", extra...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("trust-volumes.sh env: %v", err)
	}
	return append(stackEnv(home, "", extra...), strings.Fields(string(out))...)
}

// names lists every container, network and volume name a configuration
// would create or attach to.
func (c rawCompose) names() (containers, networks, volumes []string) {
	for _, s := range c.Services {
		containers = append(containers, s.ContainerName)
	}
	for _, n := range c.Networks {
		networks = append(networks, n.Name)
	}
	for _, v := range c.Volumes {
		volumes = append(volumes, v.Name)
	}
	sort.Strings(containers)
	sort.Strings(networks)
	sort.Strings(volumes)
	return containers, networks, volumes
}

// A live bring-up — no marker — runs exactly the files, names and trust
// volumes it ran before: the base compose files alone, nothing from the dev
// overlays, and every name unprefixed.
func TestOPS129LiveIsUnchanged(t *testing.T) {
	for _, mode := range []string{"", "live"} {
		t.Run("INNSEGL_STACK="+mode, func(t *testing.T) {
			if mode == "" {
				// The marker lives in the checkout; a dev-marked checkout is
				// what this case cannot read, and says so rather than fail.
				if root := repoRoot(t); markerSays(t, root) == "dev" {
					t.Skip("this checkout is marked dev; the unmarked case runs in an unmarked one")
				}
			}
			out := makeDryRun(t, mode, "sigstore-up", "innsegl-here-services")
			for _, want := range []string{
				"docker compose -f deploy/compose/spire.yml up -d",
				"docker compose -f deploy/compose/sigstore.yml up -d",
				"docker compose -f deploy/compose/innsegl.yml up -d --remove-orphans --no-build",
				"INNSEGL_TRUST_FULCIO_PKI_VOLUME=innsegl-trust-fulcio-pki",
				"INNSEGL_TRUST_LEDGER_VOLUME=innsegl-trust-ledger-data",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("a live bring-up no longer runs %q:\n%s", want, out)
				}
			}
			for _, never := range []string{"deploy/compose/dev/", devPrefix} {
				if strings.Contains(out, never) {
					t.Errorf("a live bring-up names %q, which only a dev stack may:\n%s", never, out)
				}
			}
		})
	}

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping OPS-129's compose half: %v", err)
	}
	env := trustEnv(t, t.TempDir(), "")
	for file, project := range liveProjects {
		cfg := composeAllProfiles(ctx, t, env, "deploy/compose/"+file)
		if cfg.Name != project {
			t.Errorf("%s: live project is %q, want %q", file, cfg.Name, project)
		}
		containers, networks, _ := cfg.names()
		for _, n := range append(containers, networks...) {
			if strings.HasPrefix(n, devPrefix) || !strings.HasPrefix(n, "innsegl-") {
				t.Errorf("%s: live name %q is not a live name", file, n)
			}
		}
	}
	sig := composeAllProfiles(ctx, t, env, "deploy/compose/sigstore.yml")
	_, _, vols := sig.names()
	for _, want := range []string{"innsegl-trust-fulcio-pki", "innsegl-trust-rekor-key", "innsegl-trust-trillian-db"} {
		if !contains(vols, want) {
			t.Errorf("live sigstore no longer mounts %s; got %v", want, vols)
		}
	}
}

// A dev bring-up layers deploy/compose/dev/*.yml over each base file, and
// every project, container, network and volume it would create or attach to
// is innsegl-dev-*: none of them is a live name, so it can neither collide
// with a live stack's nor attach to its trust root.
func TestOPS129DevStackHasItsOwnNamesAndTrustRoot(t *testing.T) {
	out := makeDryRun(t, "dev", "sigstore-up", "innsegl-here-services")
	for _, want := range []string{
		"-f deploy/compose/spire.yml -f deploy/compose/dev/spire.yml up -d",
		"-f deploy/compose/sigstore.yml -f deploy/compose/dev/sigstore.yml up -d",
		"-f deploy/compose/innsegl.yml -f deploy/compose/dev/innsegl.yml up -d --remove-orphans --no-build",
		"INNSEGL_TRUST_FULCIO_PKI_VOLUME=" + devTrustPrefix + "-fulcio-pki",
		"INNSEGL_TRUST_LEDGER_VOLUME=" + devTrustPrefix + "-ledger-data",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("a dev bring-up does not run %q:\n%s", want, out)
		}
	}
	for _, live := range liveTrustVolumes {
		if strings.Contains(out, "="+live) {
			t.Errorf("a dev bring-up names the live trust volume %s:\n%s", live, out)
		}
	}

	home := t.TempDir()
	stdout, stderr, code := stackMode(t, repoRoot(t), stackEnv(home, "dev"), "env")
	if code != 0 {
		t.Fatalf("stack-mode.sh env in dev: exit %d: %s", code, stderr)
	}
	devEnv := envLines(stdout)
	if devEnv["INNSEGL_STACK_PREFIX"] != devPrefix || devEnv["INNSEGL_TRUST_VOLUME_PREFIX"] != devTrustPrefix {
		t.Errorf("dev env = %v; want prefix %s and trust prefix %s", devEnv, devPrefix, devTrustPrefix)
	}
	// The gateway publishes its CA certificate into this folder on every
	// start, and $HOME/.innsegl/ca/gateway-ca.pem is what this machine's
	// commit hook trusts for ITS core (internal/commitpath). A dev gateway
	// writing there re-points the client.
	for _, k := range []string{"INNSEGL_GATEWAY_CA_HOST_DIR", "INNSEGL_LOG_DIR", "INNSEGL_BACKUP_HOST_DIR"} {
		v := devEnv[k]
		if v == "" || !strings.HasPrefix(v, filepath.Join(home, ".innsegl", "dev")) {
			t.Errorf("dev %s = %q, want a folder under %s", k, v, filepath.Join(home, ".innsegl", "dev"))
		}
	}

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping OPS-129's compose half: %v", err)
	}
	liveEnv := trustEnv(t, home, "")
	env := trustEnv(t, home, devTrustPrefix)
	for k, v := range devEnv {
		env = append(env, k+"="+v)
	}
	for file := range liveProjects {
		live := composeAllProfiles(ctx, t, liveEnv, "deploy/compose/"+file)
		dev := composeAllProfiles(ctx, t, env, "deploy/compose/"+file, "deploy/compose/dev/"+file)
		if !strings.HasPrefix(dev.Name, devPrefix+"-") {
			t.Errorf("%s: dev project is %q, want %s-*", file, dev.Name, devPrefix)
		}
		lc, ln, lv := live.names()
		liveNames := append(append(append([]string{live.Name}, lc...), ln...), lv...)
		liveNames = append(liveNames, liveTrustVolumes...)
		dc, dn, dv := dev.names()
		if len(dc) != len(lc) || len(dn) != len(ln) {
			t.Errorf("%s: the dev overlay changed what runs: %d containers and %d networks, live has %d and %d",
				file, len(dc), len(dn), len(lc), len(ln))
		}
		for kind, list := range map[string][]string{"container": dc, "network": dn, "volume": dv} {
			for _, n := range list {
				if !strings.HasPrefix(n, devPrefix+"-") {
					t.Errorf("%s: dev %s %q is not %s-*", file, kind, n, devPrefix)
				}
				if contains(liveNames, n) {
					t.Errorf("%s: dev %s %q is a live name", file, kind, n)
				}
			}
		}
		// And nothing the dev stack bind-mounts is the client's folder.
		for svc, s := range dev.Services {
			for _, v := range s.Volumes {
				if v.Type == "bind" && (v.Source == filepath.Join(home, ".innsegl", "ca") ||
					v.Source == filepath.Join(home, ".innsegl", "log")) {
					t.Errorf("%s: dev %s bind-mounts %s, which belongs to this machine's client", file, svc, v.Source)
				}
			}
		}
	}

	// The trust root: the Fulcio CA key, the log's key, the log and the
	// ledger are the dev prefix's. trust-volumes.sh migrates into the
	// DEFAULT prefix only (OPS-033), so a dev set starts empty and mints its
	// own CA: a commit signed by it chains to a root the live Fulcio does not
	// publish, which internal/verify fails (verify_test.go, foreignCA).
	dev := composeAllProfiles(ctx, t, env, "deploy/compose/sigstore.yml", "deploy/compose/dev/sigstore.yml")
	_, _, vols := dev.names()
	for _, want := range []string{devTrustPrefix + "-fulcio-pki", devTrustPrefix + "-rekor-key", devTrustPrefix + "-trillian-db"} {
		if !contains(vols, want) {
			t.Errorf("dev sigstore does not mount %s; got %v", want, vols)
		}
	}
}

// Dev is loopback only: a non-loopback INNSEGL_BIND — in the environment or
// in deploy/compose/.env, which compose reads too — is refused before
// anything starts, and every bring-up target asks.
func TestOPS129DevStackRefusesANonLoopbackBind(t *testing.T) {
	root := repoRoot(t)
	for _, c := range []struct {
		mode, bind string
		refused    bool
	}{
		{"dev", "0.0.0.0", true},
		{"dev", "192.0.2.10", true},
		{"dev", "::", true},
		{"dev", "", false},
		{"dev", "127.0.0.1", false},
		{"dev", "localhost", false},
		{"live", "0.0.0.0", false},
	} {
		_, stderr, code := stackMode(t, root, stackEnv(t.TempDir(), c.mode, "INNSEGL_BIND="+c.bind), "check")
		if c.refused && (code == 0 || !strings.Contains(stderr, "loopback")) {
			t.Errorf("INNSEGL_STACK=%s INNSEGL_BIND=%q: exit %d, stderr %q; want a refusal that says loopback", c.mode, c.bind, code, stderr)
		}
		if !c.refused && code != 0 {
			t.Errorf("INNSEGL_STACK=%s INNSEGL_BIND=%q: refused (exit %d): %s", c.mode, c.bind, code, stderr)
		}
	}

	mk := readFile(t, filepath.Join(root, "Makefile"))
	for _, target := range []string{"start", "update", "innsegl-here-services"} {
		if !strings.Contains(makeRecipe(t, mk, target), "scripts/stack-mode.sh") {
			t.Errorf("make %s does not ask scripts/stack-mode.sh before it starts anything", target)
		}
	}
}

// An enrolled client with no marker is warned, once, and stays live; with
// the marker it says it is starting a DEV stack. Neither writes anything
// under HOME: no managed settings, nothing in the client's folder.
func TestOPS129AnEnrolledClientIsWarnedAndStaysLive(t *testing.T) {
	repo := unmarkedCheckout(t)
	const coreURL = "https://core.example.test:28095"

	for _, c := range []struct {
		mode     string
		wantMode string
		want     []string
	}{
		{"", "live", []string{"this machine is a client of " + coreURL, "make dev-stack"}},
		{"dev", "dev", []string{"this machine is a client of " + coreURL, "starting a DEV stack", devPrefix, devTrustPrefix}},
	} {
		home := enrolledHome(t, coreURL)
		before := tree(t, home)
		env := stackEnv(home, c.mode)

		stdout, stderr, code := stackMode(t, repo, env, "mode")
		if code != 0 || strings.TrimSpace(stdout) != c.wantMode {
			t.Errorf("INNSEGL_STACK=%q on an enrolled client: mode %q (exit %d, %s), want %s", c.mode, stdout, code, stderr, c.wantMode)
		}
		stdout, stderr, code = stackMode(t, repo, env, "announce")
		if code != 0 {
			t.Fatalf("announce: exit %d: %s", code, stderr)
		}
		said := strings.TrimSpace(stdout + stderr)
		if n := len(strings.Split(said, "\n")); said == "" || n != 1 {
			t.Errorf("INNSEGL_STACK=%q: announce said %d lines, want one:\n%s", c.mode, n, said)
		}
		for _, w := range c.want {
			if !strings.Contains(said, w) {
				t.Errorf("INNSEGL_STACK=%q: announce %q does not say %q", c.mode, said, w)
			}
		}
		if after := tree(t, home); strings.Join(after, "\n") != strings.Join(before, "\n") {
			t.Errorf("INNSEGL_STACK=%q: announce changed HOME:\nbefore %v\nafter  %v", c.mode, before, after)
		}
	}

	// Not enrolled, no marker: nothing at all is said.
	stdout, stderr, _ := stackMode(t, repo, stackEnv(t.TempDir(), ""), "announce")
	if s := strings.TrimSpace(stdout + stderr); s != "" {
		t.Errorf("an unenrolled live host was told %q; live says nothing new", s)
	}

	// No target on the bring-up path writes the harness's settings or
	// re-points this machine's client.
	mk := readFile(t, filepath.Join(repoRoot(t), "Makefile"))
	for _, target := range []string{"start", "innsegl-up-here", "sigstore-up", "innsegl-here-services", "update", "dev-stack"} {
		r := makeRecipe(t, mk, target)
		for _, never := range []string{"settings.json", "managed-settings", "innsegl connect", "$(INNSEGL_BIN_PATH)"} {
			if strings.Contains(r, never) {
				t.Errorf("make %s names %q; a bring-up never touches this machine's client", target, never)
			}
		}
	}
}

// unmarkedCheckout is a git repository holding the two scripts the mode is
// decided by, and no marker: the state of a host that never ran
// `make dev-stack`.
func unmarkedCheckout(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	repo := t.TempDir()
	if out, err := exec.CommandContext(t.Context(), "git", "init", "-q", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	for _, s := range []string{"stack-mode.sh", "repo-main-worktree.sh"} {
		body := readFile(t, filepath.Join(root, "scripts", s))
		if err := os.MkdirAll(filepath.Join(repo, "scripts"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(repo, "scripts", s), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return repo
}

// enrolledHome is a HOME holding an enrolment: ~/.innsegl/client/core.json.
func enrolledHome(t *testing.T, coreURL string) string {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, ".innsegl", "client")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := "{\n  \"core_url\": \"" + coreURL + "\",\n  \"installation_id\": \"0123456789abcdef0123456789abcdef\"\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "core.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

// tree lists every path under dir with its size.
func tree(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return rerr
		}
		out = append(out, rel+" "+info.Mode().String()+" "+itoa(info.Size()))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// markerSays is the checkout's marker, as stack-mode.sh would read it.
func markerSays(t *testing.T, root string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), filepath.Join(root, "scripts", "stack-mode.sh"), "mode")
	cmd.Env = stackEnv(t.TempDir(), "")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
