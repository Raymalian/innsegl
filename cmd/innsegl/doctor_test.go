// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"innsegl.dev/innsegl/internal/cacustody"
	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/client/clienttest"
	"innsegl.dev/innsegl/internal/signprobe"
	"innsegl.dev/innsegl/internal/trusthistory"
)

// ---------------------------------------------------------------------------
// CLI-023 (PROPOSED for doc 07's TC-CLI) — `innsegl doctor` (#588) checks
// the signing chain in order, one line per check, runs only the repairs that
// cannot lose data (restart the client service; unlock with Touch ID), and
// prints anything on the core as one line labelled VM. It never runs a
// destructive command: every command goes through a static allow-list, and
// a fake runner records each call it is asked to make.
// ---------------------------------------------------------------------------

// destructiveWords are what no command doctor runs may contain.
var destructiveWords = []string{"down", "volume", "rm", "ca-custody-reset", "reset", "rotate", "restore",
	"destructive", "test/failure", "test/smoke", "docker", "prune", "kill", "bootout", "uninstall"}

// doctorCore is a fake core's view of the signing chain: custody, the
// probe, the readiness components. Locked: the core's handlers run on the
// server's goroutines.
type doctorCore struct {
	mu        sync.Mutex
	custody   cacustody.Status
	material  []byte
	unlocked  []byte
	probeOK   bool
	probeAt   time.Time
	probeWhy  string
	spireUp   bool
	unlockFix bool // an unlock makes the CA able to sign and the next probe pass
	trust     []trusthistory.Expiry
	server    *serverCertStatus
	backup    *ledgerBackupStatus
}

func (c *doctorCore) mount(t *testing.T, f *connectFixture) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(cacustody.PathStatus, func(w http.ResponseWriter, _ *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(c.custody); err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc(cacustody.PathMaterial, func(w http.ResponseWriter, _ *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if _, err := w.Write(c.material); err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc(cacustody.PathUnlock, func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		c.unlocked = b
		if c.unlockFix {
			c.custody = cacustody.Status{Initialized: true, CanSign: true}
			c.probeOK, c.probeAt, c.probeWhy = true, time.Now().Add(time.Second), ""
		}
		w.WriteHeader(http.StatusNoContent)
	})
	custodian := httptest.NewServer(mux)
	t.Cleanup(custodian.Close)
	h := caCustodyHandler(custodian.URL, operatorMachine(), newBackupLimiter(nil), newServeLog(io.Discard))
	f.core.Mux.Handle(coreCACustodyPath, withInstallation("inst-1", h))
	f.core.Mux.Handle(coreCACustodyPath+"/", withInstallation("inst-1", h))
	f.core.Mux.HandleFunc(coreStatusPath, func(w http.ResponseWriter, _ *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		st := signprobe.State{OK: c.probeOK, CheckedAt: c.probeAt, Since: c.probeAt, Reason: c.probeWhy}
		writeCoreJSON(w, http.StatusOK, coreStatus{Version: "test-core",
			Components: []coreComponent{
				{Name: "spire", Up: c.spireUp}, {Name: "ledger", Up: true}, {Name: "sigstore", Up: true},
				{Name: canaryComponent, Up: true, Detail: "passed"},
				{Name: signprobe.ReportName, Up: c.probeOK, Detail: st.Detail()},
			},
			Installation:      coreInstallation{ID: "inst-1", Repos: []string{"*"}},
			TrustExpiries:     c.trust,
			ServerCertificate: c.server,
			LedgerBackup:      c.backup})
	})
}

func (c *doctorCore) unlockedBody() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.unlocked
}

// healthyDoctorCore is a core whose whole signing chain works.
func healthyDoctorCore() *doctorCore {
	return &doctorCore{custody: cacustody.Status{Initialized: true, CanSign: true}, probeOK: true,
		probeAt: time.Now().Add(-time.Minute), spireUp: true}
}

// doctorRun is one doctor run against a fixture, with a fake runner.
type doctorRun struct {
	f        *connectFixture
	mu       sync.Mutex
	calls    [][]string
	onRun    func(argv []string)
	identity string
	now      func() time.Time
	// git is the real git the fake runner hands an allowed git call to,
	// resolved before a test narrows PATH.
	git string
	// self and settings override the fixture's: this binary, and the
	// managed settings connect wrote.
	self, settings string
	// uid is the user doctor checks writability for; zero is 501.
	uid int
}

func newDoctorRun(t *testing.T, core *doctorCore) *doctorRun {
	t.Helper()
	f := newConnectFixture(t)
	f.connectServed(t, nil)
	core.mount(t, f)
	return &doctorRun{f: f}
}

func (d *doctorRun) deps(t *testing.T) doctorDeps {
	t.Helper()
	if d.git == "" {
		g, err := exec.LookPath("git")
		if err != nil {
			t.Fatal(err)
		}
		d.git = g
	}
	self, settings := d.self, d.settings
	if self == "" {
		self = connectTestBin
	}
	if settings == "" {
		settings = d.f.settings
	}
	uid := d.uid
	if uid == 0 {
		uid = 501
	}
	return doctorDeps{
		home: d.f.home, goos: "darwin", uid: uid, cwd: t.TempDir(),
		now: d.now, self: self, settings: settings,
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			argv := append([]string{name}, args...)
			d.mu.Lock()
			d.calls = append(d.calls, argv)
			d.mu.Unlock()
			if d.onRun != nil {
				d.onRun(argv)
			}
			if name == "git" {
				// A read-only call the allow-list admitted: the real git
				// answers it, by its absolute path.
				return exec.CommandContext(ctx, d.git, args...).Output()
			}
			return nil, nil
		},
		poll: 50 * time.Millisecond, serviceWait: 5 * time.Second,
	}
}

// repairs are the calls that changed something: everything but the
// read-only git calls.
func (d *doctorRun) repairs() [][]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out [][]string
	for _, argv := range d.calls {
		if !doctorReadOnly(argv) {
			out = append(out, argv)
		}
	}
	return out
}

func (d *doctorRun) run(t *testing.T, args ...string) (int, string) {
	t.Helper()
	if d.identity != "" {
		args = append([]string{"--identity", d.identity}, args...)
	}
	args = append([]string{"--wait", "5s"}, args...)
	var out, errOut bytes.Buffer
	code := runDoctor(t.Context(), args, &out, &errOut, d.deps(t))
	return code, out.String() + errOut.String()
}

func (d *doctorRun) assertSafe(t *testing.T) {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	uid := d.uid
	if uid == 0 {
		uid = 501
	}
	for _, argv := range d.calls {
		if !doctorCommandAllowed("darwin", uid, argv) {
			t.Errorf("doctor ran %q, which is not on its allow-list", argv)
		}
		if doctorReadOnly(argv) {
			continue
		}
		for _, w := range destructiveWords {
			for _, a := range argv {
				if strings.Contains(a, w) {
					t.Errorf("doctor ran %q, which contains %q", argv, w)
				}
			}
		}
	}
}

// testAgeIdentity writes a test age identity and the unlock material sealed
// to it: the Touch ID path, with a file identity in place of the Secure
// Enclave.
func testAgeIdentity(t *testing.T) (path string, sealed []byte, m cacustody.Material) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "identity.txt")
	if err = os.WriteFile(path, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m = cacustody.Material{UnsealKey: "unseal-key-value", RoleID: "role", SecretID: "secret-id-value",
		BackupRoleID: "backup-role", BackupSecretID: "backup-secret-value"}
	if sealed, err = cacustody.Seal(m, []age.Recipient{id.Recipient()}); err != nil {
		t.Fatal(err)
	}
	return path, sealed, m
}

// CLI-023 — the allow-list itself: two commands, both a restart of this
// user's client service, neither destructive. Anything else is refused
// before a runner sees it.
func TestCLI023TheAllowListHoldsOnlyTheClientRestart(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		argv := doctorRestartArgv(goos, 501)
		if !doctorCommandAllowed(goos, 501, argv) {
			t.Errorf("%s: the client restart %q is not allowed", goos, argv)
		}
		for _, w := range destructiveWords {
			if strings.Contains(strings.Join(argv, " "), w) {
				t.Errorf("%s: the restart %q contains %q", goos, argv, w)
			}
		}
	}
	for _, argv := range [][]string{
		{"docker", "compose", "down", "-v"}, {"docker", "volume", "rm", "innsegl-trust-ca-store"},
		{"make", "ca-custody-reset", "CONFIRM=reset"}, {"make", "innsegl-ca-rotate", "CONFIRM=rotate"},
		{"make", "ca-custody-restore", "CONFIRM=restore"}, {"go", "test", "-tags", "destructive", "./test/failure"},
		{"launchctl", "bootout", "gui/501/" + client.LaunchdLabel}, {"sh", "-c", "launchctl kickstart -k gui/501/x"},
		{"launchctl", "kickstart", "-k", "gui/502/" + client.LaunchdLabel},
	} {
		if doctorCommandAllowed("darwin", 501, argv) || doctorCommandAllowed("linux", 501, argv) {
			t.Errorf("%q is allowed", argv)
		}
	}
	called := false
	d := &doctor{deps: doctorDeps{goos: "darwin", uid: 501, run: func(context.Context, string, ...string) ([]byte, error) {
		called = true
		return nil, nil
	}}}
	if _, err := d.exec(t.Context(), []string{"docker", "compose", "down", "-v"}); err == nil || called {
		t.Fatalf("exec of a command off the allow-list: err %v, runner called %v", err, called)
	}
}

// CLI-023 — a working chain: one line per check in chain order, the final
// OK line, exit 0, and nothing run.
func TestCLI023AWorkingChainIsOneLinePerCheckAndRunsNothing(t *testing.T) {
	d := newDoctorRun(t, healthyDoctorCore())
	code, out := d.run(t)
	if code != exitOK {
		t.Fatalf("a working chain: exit %d\n%s", code, out)
	}
	order := []string{"client service: ok", "hooks:", "core: ok", "clock: ok", "ca custody: ok",
		"spire: ok", "ledger: ok", "sigstore: ok", canaryComponent + ": ok", "signing: OK (probe passed "}
	at := 0
	for _, want := range order {
		i := strings.Index(out[at:], want)
		if i < 0 {
			t.Fatalf("missing %q (in order) in:\n%s", want, out)
		}
		at += i
	}
	if strings.Contains(out, "VM:") {
		t.Errorf("a working chain printed a VM line:\n%s", out)
	}
	if len(d.repairs()) != 0 {
		t.Errorf("a working chain ran %q", d.repairs())
	}
}

// CLI-023 — a client service that does not answer is restarted, through
// the allow-list, and the chain is checked again.
func TestCLI023AClientServiceThatIsDownIsRestarted(t *testing.T) {
	core := healthyDoctorCore()
	f := newConnectFixture(t)
	svc := httptest.NewUnstartedServer(nil)
	if code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile,
		"--managed-settings", f.settings, "--no-service", "--listen", svc.Listener.Addr().String()); code != exitOK {
		t.Fatalf("connect: %s", stderr)
	}
	s, err := client.NewServer(client.ClientPaths(f.home), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	svc.Config.Handler = s.Handler()
	t.Cleanup(svc.Close)
	core.mount(t, f)
	d := &doctorRun{f: f}
	d.onRun = func(argv []string) {
		if !doctorReadOnly(argv) {
			svc.Start()
			serveClientSocket(t, client.SocketPath(client.ClientPaths(f.home)), s.SocketHandler())
		}
	}

	code, out := d.run(t)
	if code != exitOK || !strings.Contains(out, "client service: DOWN") || !strings.Contains(out, "restarted") {
		t.Fatalf("a client service that is down: exit %d\n%s", code, out)
	}
	if len(d.repairs()) != 1 || strings.Join(d.repairs()[0], " ") != "launchctl kickstart -k gui/501/"+client.LaunchdLabel {
		t.Fatalf("doctor ran %q; want the one client restart", d.repairs())
	}
	d.assertSafe(t)
}

// CLI-023 — a sealed store is unlocked through the test age identity (the
// Touch ID path), and doctor exits 0 only once the probe passes after it.
func TestCLI023ASealedStoreIsUnlockedWithTheOperatorsIdentity(t *testing.T) {
	path, sealed, m := testAgeIdentity(t)
	core := &doctorCore{custody: cacustody.Status{Initialized: true, Sealed: true,
		Reason: "the store is sealed; the operator's machine unlocks it"}, material: sealed,
		probeAt: time.Now().Add(-time.Minute), probeWhy: "Fulcio answered HTTP 500", spireUp: true, unlockFix: true}
	d := newDoctorRun(t, core)
	d.identity = path
	code, out := d.run(t)
	if code != exitOK {
		t.Fatalf("a sealed store: exit %d\n%s", code, out)
	}
	for _, want := range []string{"ca custody: SEALED", "Touch ID", "ca custody: ok", "signing: OK (probe passed "} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	var sent cacustody.Material
	if err := json.Unmarshal(core.unlockedBody(), &sent); err != nil || sent != m {
		t.Fatalf("the custodian was sent %q", core.unlockedBody())
	}
	if strings.Contains(out, m.UnsealKey) || strings.Contains(out, m.SecretID) {
		t.Fatal("doctor printed unlock material")
	}
	if len(d.repairs()) != 0 {
		t.Errorf("an unlock ran %q; it is not a command", d.repairs())
	}
}

// CLI-023 — a dead token on an unsealed store is the same repair.
func TestCLI023ADeadTokenIsRepairedByTheUnlock(t *testing.T) {
	path, sealed, _ := testAgeIdentity(t)
	core := &doctorCore{custody: cacustody.Status{Initialized: true, Reason: "the CA's token was refused by the store"},
		material: sealed, probeAt: time.Now().Add(-time.Minute), probeWhy: "Fulcio answered HTTP 500",
		spireUp: true, unlockFix: true}
	d := newDoctorRun(t, core)
	d.identity = path
	code, out := d.run(t)
	if code != exitOK || core.unlockedBody() == nil || !strings.Contains(out, "token was refused") {
		t.Fatalf("a dead token: exit %d, unlocked %v\n%s", code, core.unlockedBody() != nil, out)
	}
}

// CLI-023 — a store key that drifted from chain.pem is never "fixed": no
// unlock, the runbook pointer, exit non-zero.
func TestCLI023ADriftedTrustRootIsNeverRepaired(t *testing.T) {
	path, sealed, _ := testAgeIdentity(t)
	core := &doctorCore{custody: cacustody.Status{Initialized: true,
		Reason: `the CA key "innsegl-ca" in the store is not the key in the certificate the CA presents ` +
			`(/etc/fulcio/chain.pem): they have drifted, and Fulcio refuses to start on them`},
		material: sealed, probeAt: time.Now().Add(-time.Minute), probeWhy: "Fulcio answered HTTP 500",
		spireUp: true, unlockFix: true}
	d := newDoctorRun(t, core)
	d.identity = path
	code, out := d.run(t)
	if code == exitOK || core.unlockedBody() != nil {
		t.Fatalf("drift: exit %d, unlocked %v\n%s", code, core.unlockedBody() != nil, out)
	}
	if !strings.Contains(out, "runbooks/ca-custody.md") || !strings.Contains(out, "drifted") {
		t.Fatalf("drift does not point at the runbook:\n%s", out)
	}
	d.assertSafe(t)
}

// CLI-023 — what is on the core is printed as one VM line, never run: a
// failing probe on a store that is fine, and SPIRE down.
func TestCLI023CoreRepairsArePrintedAsVMLines(t *testing.T) {
	core := healthyDoctorCore()
	core.probeOK, core.probeWhy = false, "Fulcio answered HTTP 500"
	core.spireUp = false
	d := newDoctorRun(t, core)
	code, out := d.run(t)
	if code == exitOK {
		t.Fatalf("a failing probe: exit 0\n%s", out)
	}
	for _, want := range []string{"spire: DOWN", "signing: FAILING", "VM: docker restart innsegl-spire-server",
		"VM: docker restart innsegl-sigstore-fulcio"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "docker ") && !strings.HasPrefix(strings.TrimSpace(line), "VM: ") {
			t.Errorf("a core command not labelled VM: %q", line)
		}
	}
	if len(d.repairs()) != 0 {
		t.Errorf("core repairs were run: %q", d.repairs())
	}
}

// CLI-023 — a Mac clock more than 30 s from the core's is a finding.
func TestCLI023ClockSkewIsAFinding(t *testing.T) {
	d := newDoctorRun(t, healthyDoctorCore())
	d.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	_, out := d.run(t)
	if !strings.Contains(out, "clock: SKEWED") || !strings.Contains(out, "ahead of the core") {
		t.Fatalf("a 2 min skew:\n%s", out)
	}
}

// CLI-023 — a repository that lacks innsegl's hooks is named, with the
// command that links it. Linking is not a repair doctor runs.
func TestCLI023ARepositoryWithoutTheHooksIsNamed(t *testing.T) {
	repo := gitInitRepo(t)
	d := newDoctorRun(t, healthyDoctorCore())
	_, out := d.run(t, "--repo", repo)
	if !strings.Contains(out, "hooks: MISSING") || !strings.Contains(out, "innsegl link "+repo) {
		t.Fatalf("a repository without hooks:\n%s", out)
	}
	if len(d.repairs()) != 0 {
		t.Errorf("doctor ran %q", d.repairs())
	}
}
