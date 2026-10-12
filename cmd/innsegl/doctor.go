// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"innsegl.dev/innsegl/internal/cacustody"
	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/hostdeps"
	"innsegl.dev/innsegl/internal/signprobe"
	"innsegl.dev/innsegl/internal/version"
)

// `innsegl doctor` (#588), on the operator's machine: check every link of
// the signing chain in order, one line each; run the repairs that cannot
// lose data (restart the client service, unlock with Touch ID); print any
// step on the core as one line labelled VM, for the operator to run there.
//
// Every command it runs goes through doctorCommandAllowed (doctorrights.go),
// a static allow-list (CLI-038): the client service restart, which is the
// one repair it runs, and the read-only git calls and age plugins its checks
// need. Never `down`, a volume removal, ca-custody-reset, a rotation, a
// restore, or a destructive test package (CLI-023). The only other change it
// makes on its own is tightening the modes of innsegl's own files (CLI-039).

// exitDoctorFailing: signing did not pass the probe after the repairs.
const exitDoctorFailing = 37

// doctorSkewLimit is the clock difference between this machine and the core
// past which certificates and tokens start to fail.
const doctorSkewLimit = 30 * time.Second

// doctorDefaultWait covers one probe interval and a margin: after a repair,
// the next scheduled probe is what proves signing works.
const doctorDefaultWait = signprobe.DefaultInterval + time.Minute

// doctorRunbook is where a repair doctor must not make is described.
const doctorRunbook = "runbooks/ca-custody.md, section \"Signing stopped\""

const doctorUsage = `usage: innsegl doctor [--identity F] [--managed-settings F] [--repo DIR]... [--wait D]

Check the signing chain from this machine to the core's CA, in order, one
line per check, and the rights innsegl holds on it: the hooks in Claude
Code's managed settings and the binaries they, the git hooks and the client
service run. Repairs it runs itself: restart the client service; unlock the
CA key store (asks for Touch ID); tighten the modes of innsegl's own key
files. Anything else is printed: a line starting "VM:" for you to run on the
core, or the command to run here. Exits 0 only when the signing probe
passes after the repairs; 37 when it does not; 2 on a usage error.
`

type doctorDeps struct {
	home string
	goos string
	uid  int
	// cwd is the repository checked for hooks when no --repo is given.
	cwd string
	// now is this machine's clock; nil is time.Now.
	now func() time.Time
	// run executes one allowed command and returns what it printed on
	// stdout. Nothing else in doctor executes.
	run func(ctx context.Context, name string, args ...string) ([]byte, error)
	// self is this binary's resolved path, which every hook and the client
	// service must run; empty is innseglBinaryPath.
	self string
	// settings is the managed settings file doctor reads by default; empty
	// is the system path connect writes.
	settings string
	// poll is how often doctor asks again while it waits.
	poll time.Duration
	// serviceWait bounds the wait for a restarted client service.
	serviceWait time.Duration
	// host is the machine whose tools the first line checks; nil is this one.
	host *hostdeps.Env
}

func doctorCommand(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	home, err := os.UserHomeDir()
	if err != nil {
		fprintf(stderr, "innsegl doctor: %v\n", err)
		return exitUsage
	}
	cwd, err := os.Getwd()
	if err != nil {
		cwd = ""
	}
	return runDoctor(ctx, args, stdout, stderr, doctorDeps{
		home: home, goos: runtime.GOOS, uid: os.Getuid(), cwd: cwd, now: time.Now,
		run:  execDoctorCommand,
		poll: 15 * time.Second, serviceWait: 20 * time.Second,
	})
}

// execDoctorCommand runs one command that doctorCommandAllowed admitted;
// doctor.exec is its only caller.
func execDoctorCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	// #nosec G204 -- argv only, no shell, and only what the allow-list admitted.
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// doctorRestartArgv restarts this user's client service on goos.
func doctorRestartArgv(goos string, uid int) []string {
	if goos == "darwin" {
		return []string{"launchctl", "kickstart", "-k", "gui/" + strconv.Itoa(uid) + "/" + client.LaunchdLabel}
	}
	return []string{"systemctl", "--user", "restart", client.SystemdUnit}
}

type doctor struct {
	deps     doctorDeps
	out      io.Writer
	paths    client.Paths
	identity string
	settings string
	local    string
}

// exec runs argv through the allow-list and returns its stdout. A command
// off the list never reaches the runner.
func (d *doctor) exec(ctx context.Context, argv []string) ([]byte, error) {
	if err := d.permit(argv); err != nil {
		return nil, err
	}
	return d.deps.run(ctx, argv[0], argv[1:]...)
}

// permit is the allow-list's gate: for what doctor runs, and for what it
// hands to a library that runs it (the age plugin).
func (d *doctor) permit(argv []string) error {
	if !doctorCommandAllowed(d.deps.goos, d.deps.uid, argv) {
		return fmt.Errorf("refusing to run %q: not on innsegl doctor's allow-list", strings.Join(argv, " "))
	}
	return nil
}

func (d *doctor) line(check, state, detail string) {
	if detail == "" {
		fprintf(d.out, "%s: %s\n", check, state)
		return
	}
	fprintf(d.out, "%s: %s — %s\n", check, state, detail)
}

func (d *doctor) vm(cmd string) { fprintf(d.out, "VM: %s\n", cmd) }

func (d *doctor) now() time.Time {
	if d.deps.now == nil {
		return time.Now()
	}
	return d.deps.now()
}

type repoList []string

func (r *repoList) String() string     { return strings.Join(*r, ",") }
func (r *repoList) Set(v string) error { *r = append(*r, v); return nil }

func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer, deps doctorDeps) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fprintf(stderr, "%s\nFlags:\n", doctorUsage)
		fs.PrintDefaults()
	}
	paths := client.ClientPaths(deps.home)
	identity := fs.String("identity", paths.TrustIdentity,
		"the age identity that opens the CA's unlock material (a Secure Enclave identity asks for Touch ID)")
	wait := fs.Duration("wait", doctorDefaultWait, "how long to wait for the signing probe to pass after a repair")
	defaultSettings := deps.settings
	if defaultSettings == "" {
		defaultSettings = defaultManagedSettingsPath(deps.goos)
	}
	settings := fs.String("managed-settings", defaultSettings,
		"the Claude Code managed settings whose innsegl hooks to check")
	var repos repoList
	fs.Var(&repos, "repo", "a repository whose git hooks to check (repeatable; default: the current one)")
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		return exitOK
	} else if err != nil || fs.NArg() != 0 {
		fs.Usage()
		return exitUsage
	}
	if _, err := client.ReadCoreConfig(paths); err != nil {
		fprintf(stderr, "innsegl doctor: this machine is not connected to a core (%v)\n", err)
		return exitDoctorFailing
	}
	d := &doctor{deps: deps, out: stdout, paths: paths, identity: *identity, settings: *settings,
		local: "http://" + enrolledListen(paths)}
	if len(repos) == 0 && deps.cwd != "" {
		repos = repoList{deps.cwd}
	}
	d.hostTools(ctx)
	d.rights()
	if !d.clientService(ctx) {
		return exitDoctorFailing
	}
	d.hooks(ctx, repos)
	st, coreAt, ok := d.core(ctx)
	if !ok {
		return exitDoctorFailing
	}
	unlocked, custodyOK := d.custody(ctx)
	d.components(st)
	return d.signing(ctx, st, coreAt, unlocked, custodyOK, *wait)
}

// hostTools is doctor's first line (CLI-027, #592): what this machine lacks,
// each with the command that installs it. It installs nothing, and the
// checks after it run either way: they say what the gap breaks.
func (d *doctor) hostTools(ctx context.Context) {
	env := hostdeps.Real(d.deps.goos, d.identity)
	// `git --version` goes through the allow-list like every other command.
	env.Output = func(name string, args ...string) (string, error) {
		vctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		out, err := d.exec(vctx, append([]string{name}, args...))
		return string(out), err
	}
	if d.deps.host != nil {
		env = *d.deps.host
	}
	missing := hostdeps.Check(env)
	if len(missing) == 0 {
		d.line("host", "ok", "")
		return
	}
	for _, m := range missing {
		d.line("host", "MISSING", m.Name+" ("+m.Why+"); install: "+m.Install)
	}
}

// clientService checks the client service answers, runs this build, and
// holds a certificate. It restarts a service that does not answer or runs
// another build.
func (d *doctor) clientService(ctx context.Context) bool {
	const check = "client service"
	svc, err := localClientStatus(ctx, d.local)
	problem := ""
	switch {
	case err != nil:
		problem = "not answering at " + d.local
	case svc.Version != version.String():
		problem = fmt.Sprintf("runs build %q, this binary is %q", svc.Version, version.String())
	}
	if problem != "" {
		d.line(check, "DOWN", problem+"; restarting it")
		if _, rerr := d.exec(ctx, doctorRestartArgv(d.deps.goos, d.deps.uid)); rerr != nil {
			d.line(check, "DOWN", "the restart failed: "+rerr.Error())
			return false
		}
		svc, err = d.awaitService(ctx)
		if err != nil {
			d.line(check, "DOWN", "still "+err.Error()+"; its log: "+client.LogHint(d.deps.goos))
			return false
		}
		d.line(check, "ok", "restarted; runs "+svc.Version)
	}
	if svc.Revoked {
		d.line(check, "REVOKED", "the core refused this machine's renewal; enrol again with `innsegl connect`")
		return false
	}
	exp, perr := time.Parse(time.RFC3339, svc.CertificateExpiresAt)
	switch {
	case perr != nil:
		d.line("client certificate", "UNKNOWN", "the service did not say when it expires")
	case !exp.After(d.now()):
		d.line("client certificate", "EXPIRED", "at "+svc.CertificateExpiresAt+
			"; the service renews it while the core answers, or enrol again with `innsegl connect`")
		return false
	}
	if problem == "" {
		d.line(check, "ok", "runs "+svc.Version+", certificate until "+svc.CertificateExpiresAt)
	}
	return true
}

// awaitService waits for a restarted service to answer with this build.
func (d *doctor) awaitService(ctx context.Context) (localStatus, error) {
	deadline := time.Now().Add(d.deps.serviceWait)
	for {
		svc, err := localClientStatus(ctx, d.local)
		if err == nil && svc.Version == version.String() {
			return svc, nil
		}
		if err == nil {
			err = fmt.Errorf("running build %q, not %q: the service starts the binary its definition names; "+
				"run `innsegl connect` again from this binary", svc.Version, version.String())
		}
		if time.Now().After(deadline) {
			return localStatus{}, err
		}
		select {
		case <-ctx.Done():
			return localStatus{}, ctx.Err()
		case <-time.After(d.pollEvery()):
		}
	}
}

func (d *doctor) pollEvery() time.Duration {
	if d.deps.poll <= 0 {
		return time.Second
	}
	return d.deps.poll
}

// hooks checks each repository carries innsegl's git hooks. Linking is not
// a repair doctor runs: it names the command.
func (d *doctor) hooks(ctx context.Context, repos []string) {
	if len(repos) == 0 {
		d.line("hooks", "not checked", "not in a repository; pass --repo DIR")
		return
	}
	for _, repo := range repos {
		if err := d.gitCommonDir(ctx, repo); err != nil {
			d.line("hooks", "not checked", repo+" is not a git repository")
			continue
		}
		var missing []string
		var scripts []hookScript
		for _, h := range managedHooks {
			s, ours := d.managedHook(ctx, repo, h)
			if !ours {
				missing = append(missing, h.name)
				continue
			}
			scripts = append(scripts, s)
		}
		if len(missing) > 0 {
			d.line("hooks", "MISSING", fmt.Sprintf("%s lacks %s; run: innsegl link %s",
				repo, strings.Join(missing, ", "), repo))
			continue
		}
		if d.hookBinaries(repo, scripts) {
			d.line("hooks", "ok", repo)
		}
	}
}

// core reads the core's status: reachable over this machine's certificate,
// and its clock.
func (d *doctor) core(ctx context.Context) (coreStatus, time.Time, bool) {
	body, at, err := client.FetchCoreStatusAt(ctx, d.paths, d.local)
	if err != nil {
		d.line("core", "UNREACHABLE", err.Error())
		d.vm("docker logs --tail 50 innsegl-core")
		return coreStatus{}, time.Time{}, false
	}
	var st coreStatus
	if err := json.Unmarshal(body, &st); err != nil {
		d.line("core", "UNREADABLE", err.Error())
		return coreStatus{}, time.Time{}, false
	}
	d.line("core", "ok", "reachable over this machine's certificate; runs "+st.Version)
	if at.IsZero() {
		d.line("clock", "not checked", "the core's answer carried no time")
		return st, at, true
	}
	skew := d.now().Sub(at)
	switch {
	case skew > doctorSkewLimit:
		d.line("clock", "SKEWED", fmt.Sprintf("this machine is %s ahead of the core; set the clock on whichever "+
			"side is wrong", skew.Round(time.Second)))
		d.vm("timedatectl status")
	case skew < -doctorSkewLimit:
		d.line("clock", "SKEWED", fmt.Sprintf("this machine is %s behind the core; set the clock on whichever "+
			"side is wrong", (-skew).Round(time.Second)))
		d.vm("timedatectl status")
	default:
		d.line("clock", "ok", "within "+doctorSkewLimit.String()+" of the core")
	}
	return st, at, true
}

// custody checks the CA key store, and unlocks it (Touch ID) when that is
// the repair: sealed, or a token that is absent, refused, expired or cannot
// read the key. A key that drifted from the chain is never repaired here.
func (d *doctor) custody(ctx context.Context) (unlocked, ok bool) {
	const check = "ca custody"
	st, err := client.CAStatus(ctx, d.paths)
	if err != nil {
		d.line(check, "UNKNOWN", custodyErr(err))
		return false, false
	}
	if !st.Enabled {
		d.line(check, "ok", "off; this core keeps its CA key in a file")
		return false, true
	}
	if st.CanSign {
		d.line(check, "ok", "unlocked; the CA can sign")
		return false, true
	}
	reason := st.Reason
	switch {
	case st.Sealed && !strings.Contains(reason, "not answering"):
		d.line(check, "SEALED", reason)
	case strings.Contains(reason, cacustody.DriftedPhrase):
		d.line(check, "DRIFTED", reason)
		d.line(check, "not repaired", "a trust root is never changed from here; this is rotation or restore "+
			"drift: see "+doctorRunbook)
		return false, false
	case strings.Contains(reason, "not answering"):
		d.line(check, "DOWN", reason)
		d.vm("docker start innsegl-ca-store innsegl-ca-custodian, then run `innsegl doctor` again here")
		return false, false
	case strings.Contains(reason, "not initialised") || reason == "":
		if reason == "" {
			reason = "the core does not say why its CA cannot sign; update the core"
		}
		d.line(check, "CANNOT SIGN", reason)
		d.line(check, "not repaired", "see "+doctorRunbook)
		return false, false
	default:
		d.line(check, "CANNOT SIGN", reason)
	}
	if perr := d.permitPlugins(); perr != nil {
		d.line(check, "NOT REPAIRED", perr.Error())
		return false, false
	}
	d.line(check, "repairing", "unlocking the CA key store; approve the Touch ID prompt")
	done, err := client.UnlockCAWith(ctx, d.paths, st, operatorIdentities(d.identity, d.out))
	if err != nil {
		d.line(check, "NOT REPAIRED", custodyErr(err))
		return false, false
	}
	if !done {
		d.line(check, "NOT REPAIRED", "the core no longer asked for an unlock; the signing probe decides")
		return false, false
	}
	// No second status read: the core limits custody calls per machine
	// (six per ten minutes), and the signing probe below is the proof.
	d.line(check, "ok", "unlocked; the signing probe confirms it below")
	return true, true
}

// custodyErr says what a custody call's failure means; the core's limit on
// custody calls gets the wait that clears it.
func custodyErr(err error) string {
	if strings.Contains(err.Error(), "answered 429") {
		return err.Error() + "; the core allows six custody calls per machine per ten minutes: " +
			"run `innsegl doctor` again in ten minutes"
	}
	return err.Error()
}

// doctorVMRepair is the one VM line for a core component that is down.
var doctorVMRepair = map[string]string{
	"spire":         "docker restart innsegl-spire-server",
	"ledger":        "docker logs --tail 50 innsegl-postgres",
	"sigstore":      "docker restart innsegl-sigstore-fulcio innsegl-sigstore-rekor",
	canaryComponent: "docker logs --tail 50 innsegl-canary",
}

// components reports the core's readiness checks other than the probe.
func (d *doctor) components(st coreStatus) {
	for _, c := range st.Components {
		if c.Name == signprobe.ReportName || c.Name == repoModeComponent {
			continue
		}
		if c.Up {
			d.line(c.Name, "ok", c.Detail)
			continue
		}
		d.line(c.Name, "DOWN", c.Detail)
		if cmd, ok := doctorVMRepair[c.Name]; ok {
			d.vm(cmd)
		} else {
			d.vm("docker logs --tail 50 innsegl-core")
		}
	}
}

// signing reads the probe. After an unlock it waits for a probe that passed
// after it; otherwise the current reading is the answer.
func (d *doctor) signing(ctx context.Context, st coreStatus, coreAt time.Time, unlocked, custodyOK bool,
	wait time.Duration) int {
	up, detail, found := probeReading(st)
	if !found {
		d.line("signing", "UNKNOWN", "this core reports no signing probe; update the core")
		return exitDoctorFailing
	}
	if up && !unlocked {
		return d.signingOK(detail)
	}
	if !unlocked {
		d.line("signing", "FAILING", strings.TrimPrefix(detail, "FAILING "))
		if custodyOK {
			d.vm("docker restart innsegl-sigstore-fulcio, then run `innsegl doctor` again here")
		}
		return exitDoctorFailing
	}
	d.line("signing", "waiting", "for the next signing probe after the unlock (every "+
		signprobe.DefaultInterval.String()+")")
	deadline := time.Now().Add(wait)
	for {
		body, _, err := client.FetchCoreStatusAt(ctx, d.paths, d.local)
		if err == nil {
			var now coreStatus
			if json.Unmarshal(body, &now) == nil {
				up, detail, _ = probeReading(now)
				if at, ok := signprobe.ParsePassing(detail); up && ok && (coreAt.IsZero() || !at.Before(coreAt)) {
					return d.signingOK(detail)
				}
			}
		}
		if time.Now().After(deadline) {
			d.line("signing", "FAILING", "no probe passed within "+wait.String()+" of the repair: "+detail)
			d.vm("docker exec innsegl-core innsegl signing-probe")
			return exitDoctorFailing
		}
		select {
		case <-ctx.Done():
			return exitDoctorFailing
		case <-time.After(d.pollEvery()):
		}
	}
}

func (d *doctor) signingOK(detail string) int {
	at, ok := signprobe.ParsePassing(detail)
	stamp := detail
	if ok {
		stamp = at.UTC().Format(time.RFC3339)
	}
	fprintf(d.out, "signing: OK (probe passed %s)\n", stamp)
	return exitOK
}

// probeReading is the signing probe's component in a core status.
func probeReading(st coreStatus) (up bool, detail string, found bool) {
	for _, c := range st.Components {
		if c.Name == signprobe.ReportName {
			return c.Up, c.Detail, true
		}
	}
	return false, "", false
}
