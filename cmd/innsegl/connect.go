// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/client"
)

// `innsegl connect` — RM-285 (#461), ADR-0063 decisions 2 and 4. One
// command enrols this machine with a core: it makes a key pair here, sends a
// certificate request with a single-use token, keeps the key and the
// certificate under ~/.innsegl/client, points Claude Code's managed
// settings at the local endpoint `innsegl client serve` runs, and installs
// that service.
//
// The managed settings carry the route and innsegl's own hooks, nothing
// more (RM-312): no sandbox, no allowManagedHooksOnly, no permissions, so
// the user's own status line, gh, git push and go build keep working.
// `--hardened` adds that lockdown, with the sandbox denying an agent's shell
// ~/.innsegl. `--update` moves an enrolled machine between the two without
// a token, and removes lockdown keys an earlier version wrote.
//
// Trust in the core is never taken on first use. The core's certificate is
// issued by its own CA (ADR-0066), and connect needs that CA either as a
// file (--ca) or as a fingerprint it confirms against what the core presents
// (--ca-fingerprint). The token is sent only to a core that verifies.
//
// Nothing is written before the core has answered: a refused token leaves no
// key, no settings and no service behind. And the managed settings are
// checked for writability before the token is spent, so the
// administrator's one command can run first and connect again after.

// connectDeps is what connect reaches outside the process; tests replace
// every one of them.
// exitConnectFailed: connect, pause, resume or disconnect did not complete.
// The message says what, if anything, was changed.
const exitConnectFailed = 24

type connectDeps struct {
	home     string
	binPath  func() (string, error)
	goos     string
	uid      int
	run      func(name string, args ...string) error
	now      func() time.Time
	hostname func() (string, error)
}

func defaultConnectDeps() (connectDeps, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return connectDeps{}, err
	}
	return connectDeps{
		home:    home,
		binPath: innseglBinaryPath,
		goos:    runtime.GOOS,
		uid:     os.Getuid(),
		run: func(name string, args ...string) error {
			out, err := exec.CommandContext(context.Background(), name, args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(out))
			}
			return nil
		},
		now:      time.Now,
		hostname: os.Hostname,
	}, nil
}

func connectCommand(args []string, stdout, stderr io.Writer) int {
	deps, err := defaultConnectDeps()
	if err != nil {
		fprintf(stderr, "innsegl connect: %v\n", err)
		return exitUsage
	}
	return runConnect(context.Background(), args, stdout, stderr, deps)
}

// defaultManagedSettingsPath is the system path Claude Code reads its
// managed settings from, the same one install.sh writes.
func defaultManagedSettingsPath(goos string) string {
	if goos == "darwin" {
		return "/Library/Application Support/ClaudeCode/managed-settings.json"
	}
	return "/etc/claude-code/managed-settings.json"
}

type connectFlags struct {
	token, ca, fingerprint, name, listen, settings     string
	noService, pause, resume, disconnect, update, hard bool
}

func runConnect(ctx context.Context, args []string, stdout, stderr io.Writer, deps connectDeps) int {
	var f connectFlags
	fs := flag.NewFlagSet("innsegl connect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&f.token, "token", "", "the single-use enrolment token (ie_…)")
	fs.StringVar(&f.ca, "ca", "", "a file holding the core's CA certificate")
	fs.StringVar(&f.fingerprint, "ca-fingerprint", "", "the core CA's fingerprint, sha256:<hex>; the CA is fetched once and confirmed against it")
	fs.StringVar(&f.name, "name", "", "this installation's display name (default: the host name)")
	fs.StringVar(&f.listen, "listen", client.DefaultListen, "the loopback address the client service listens on")
	fs.StringVar(&f.settings, "managed-settings", "", "write Claude Code's managed settings here instead of the system path")
	fs.BoolVar(&f.noService, "no-service", false, "do not install or remove the user service")
	fs.BoolVar(&f.pause, "pause", false, "set the managed settings aside, unchanged")
	fs.BoolVar(&f.resume, "resume", false, "put paused managed settings back")
	fs.BoolVar(&f.disconnect, "disconnect", false, "remove what connect wrote: the managed settings keys, the service, ~/.innsegl/client")
	fs.BoolVar(&f.update, "update", false, "rewrite this enrolled machine's managed settings to the chosen mode; no token")
	fs.BoolVar(&f.hard, "hardened", false, "also lock the harness down: managed hooks only, bypass mode disabled, the sandbox; the user's statusLine is copied in")
	fs.Usage = func() {
		fprintf(stderr, "innsegl connect - enrol this machine with an innsegl core (#461)\n\n")
		fprintf(stderr, "Usage:\n"+
			"  innsegl connect <core-url> --token <ie_…> (--ca <file> | --ca-fingerprint sha256:<hex>)\n"+
			"                  [--hardened] [--name <n>] [--listen 127.0.0.1:28195] [--managed-settings <path>] [--no-service] [DIR…]\n"+
			"  innsegl connect --update [--hardened] [--managed-settings <path>]\n"+
			"  innsegl connect --pause | --resume | --disconnect [--managed-settings <path>]\n\n")
		fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if f.settings == "" {
		f.settings = defaultManagedSettingsPath(deps.goos)
	}

	modes := 0
	for _, m := range []bool{f.pause, f.resume, f.disconnect, f.update} {
		if m {
			modes++
		}
	}
	switch {
	case modes > 1:
		fprintf(stderr, "innsegl connect: --pause, --resume, --disconnect and --update are separate steps; give one\n")
		return exitUsage
	case modes == 1 && len(positional) > 0:
		fprintf(stderr, "innsegl connect: --pause, --resume, --disconnect and --update take no other arguments\n")
		return exitUsage
	case f.hard && (f.pause || f.resume || f.disconnect):
		fprintf(stderr, "innsegl connect: --hardened chooses what connect or --update writes; --pause, --resume and --disconnect take no mode\n")
		return exitUsage
	case f.pause || f.resume:
		return connectPauseResume(f, stdout, stderr)
	case f.disconnect:
		return connectDisconnect(f, stdout, stderr, deps)
	case f.update:
		return connectUpdate(f, stdout, stderr, deps)
	}
	return connectEnrol(ctx, f, positional, stdout, stderr, deps)
}

func connectPauseResume(f connectFlags, stdout, stderr io.Writer) int {
	var err error
	verb := "paused"
	if f.pause {
		err = client.Pause(f.settings)
	} else {
		verb = "resumed"
		err = client.Resume(f.settings)
	}
	if code, done := reportNotWritable(err, stderr, ""); done {
		return code
	}
	if err != nil {
		fprintf(stderr, "innsegl connect: %v\n", err)
		return exitConnectFailed
	}
	fprintf(stdout, "innsegl connect: %s %s\ninnsegl connect: restart Claude Code for it to take effect\n", verb, f.settings)
	return exitOK
}

// reportNotWritable prints the administrator's one command for a
// *client.NotWritableError and reports whether err was one.
func reportNotWritable(err error, stderr io.Writer, then string) (int, bool) {
	var nw *client.NotWritableError
	if !errors.As(err, &nw) {
		return 0, false
	}
	fprintf(stderr, "innsegl connect: %s is not writable. Run this once, as an administrator%s:\n\n  %s\n\n", nw.Path, then, nw.Command)
	return exitConnectFailed, true
}

// userSettingsPath is the user's own Claude Code settings file, the one a
// statusLine normally lives in.
func (d connectDeps) userSettingsPath() string {
	return filepath.Join(d.home, ".claude", "settings.json")
}

func (d connectDeps) settingsConfig(listen string, hardened bool) (client.SettingsConfig, error) {
	bin, err := d.binPath()
	if err != nil {
		return client.SettingsConfig{}, fmt.Errorf("resolving this binary's own path: %w", err)
	}
	// The harness runs the hook command through a shell, unquoted, as
	// install.sh has always written it.
	if !isShellSafeForInterpolation(bin) {
		return client.SettingsConfig{}, fmt.Errorf("this binary's path %q holds characters a hook command cannot carry unquoted; install innsegl at a plain path", bin)
	}
	// The user's own statusLine: --hardened copies it into the managed
	// settings, and every other mode removes that copy. A file it cannot
	// read stops only --hardened; elsewhere no copy is assumed, so none is
	// removed.
	line, err := client.ReadStatusLine(d.userSettingsPath())
	if err != nil {
		if hardened {
			return client.SettingsConfig{}, fmt.Errorf("reading the user's statusLine to copy it: %w", err)
		}
		line = nil
	}
	return client.SettingsConfig{
		HookBin:    bin,
		LocalURL:   "http://" + listen,
		LogDeny:    filepath.Join(d.home, ".innsegl"),
		CAAllow:    filepath.Join(d.home, ".innsegl", "ca"),
		Hardened:   hardened,
		StatusLine: line,
	}, nil
}

func (d connectDeps) service() client.Service {
	return client.Service{GOOS: d.goos, Home: d.home, UID: d.uid, Run: d.run}
}

// enrolledListen is the loopback address the enrolment in ~/.innsegl/client
// names, or the default.
func enrolledListen(paths client.Paths) string {
	if cfg, err := client.ReadCoreConfig(paths); err == nil && cfg.Listen != "" {
		return cfg.Listen
	}
	return client.DefaultListen
}

// connectUpdate rewrites an enrolled machine's managed settings to the mode
// chosen now, from the enrolment already in ~/.innsegl/client: no token, no
// core, no service change.
func connectUpdate(f connectFlags, stdout, stderr io.Writer, deps connectDeps) int {
	paths := client.ClientPaths(deps.home)
	if _, err := os.Stat(paths.Core); err != nil {
		fprintf(stderr, "innsegl connect: this machine is not connected (%s is missing); "+
			"--update rewrites an enrolled machine's settings. Run `innsegl connect <core-url> --token ...` first.\n", paths.Core)
		return exitConnectFailed
	}
	settings, err := deps.settingsConfig(enrolledListen(paths), f.hard)
	if err != nil {
		fprintf(stderr, "innsegl connect: %v\n", err)
		return exitConnectFailed
	}
	again := "`innsegl connect --update`"
	if f.hard {
		again = "`innsegl connect --update --hardened`"
	}
	err = client.InstallSettings(f.settings, settings, deps.now, stdout)
	if code, done := reportNotWritable(err, stderr, ", then run "+again+" again"); done {
		return code
	}
	if err != nil {
		fprintf(stderr, "innsegl connect: %v\n", err)
		return exitConnectFailed
	}
	mode := "the route and innsegl's hooks only"
	if f.hard {
		mode = "hardened"
	}
	fprintf(stdout, "innsegl connect: managed settings %s are %s\ninnsegl connect: restart Claude Code for it to take effect\n", f.settings, mode)
	return exitOK
}

func connectDisconnect(f connectFlags, stdout, stderr io.Writer, deps connectDeps) int {
	paths := client.ClientPaths(deps.home)
	settings, err := deps.settingsConfig(enrolledListen(paths), false)
	if err != nil {
		fprintf(stderr, "innsegl connect: %v\n", err)
		return exitConnectFailed
	}
	err = client.UninstallSettings(f.settings, settings, deps.now, stdout)
	if code, done := reportNotWritable(err, stderr, ", then run `innsegl connect --disconnect` again"); done {
		return code
	}
	if err != nil {
		fprintf(stderr, "innsegl connect: %v\n", err)
		return exitConnectFailed
	}
	if !f.noService {
		if err := deps.service().Uninstall(); err != nil {
			fprintf(stderr, "innsegl connect: removing the client service: %v\n", err)
		}
	}
	if err := os.RemoveAll(paths.Dir); err != nil {
		fprintf(stderr, "innsegl connect: removing %s: %v\n", paths.Dir, err)
		return exitConnectFailed
	}
	fprintf(stdout, "innsegl connect: removed %s\n", paths.Dir)
	fprintf(stdout, "innsegl connect: disconnected. The installation stays recorded on the core until a member "+
		"of its organisation revokes it; restart Claude Code for the settings change to take effect.\n")
	return exitOK
}

func connectEnrol(ctx context.Context, f connectFlags, positional []string, stdout, stderr io.Writer, deps connectDeps) int {
	if len(positional) == 0 {
		fprintf(stderr, "innsegl connect: the core's URL is required\n")
		return exitUsage
	}
	coreURL := strings.TrimSuffix(positional[0], "/")
	dirs := positional[1:]
	if u, err := url.Parse(coreURL); err != nil || u.Scheme != "https" || u.Hostname() == "" || (u.Path != "" && u.Path != "/") {
		fprintf(stderr, "innsegl connect: the core URL %q is not https://<name>[:port]\n", positional[0])
		return exitUsage
	}
	if !client.ValidToken(f.token) {
		fprintf(stderr, "innsegl connect: --token must be an enrolment token, ie_<16 hex>_<64 hex>\n")
		return exitUsage
	}
	if (f.ca == "") == (f.fingerprint == "") {
		fprintf(stderr, "innsegl connect: give exactly one of --ca <file> or --ca-fingerprint sha256:<hex>; "+
			"the core's CA is never trusted on first use\n")
		return exitUsage
	}
	if err := client.CheckLoopback(f.listen); err != nil {
		fprintf(stderr, "innsegl connect: %v\n", err)
		return exitUsage
	}
	paths := client.ClientPaths(deps.home)
	if _, err := os.Stat(paths.Core); err == nil {
		fprintf(stderr, "innsegl connect: this machine is already connected (%s). "+
			"Run `innsegl connect --disconnect` first to enrol again.\n", paths.Core)
		return exitConnectFailed
	}
	settings, err := deps.settingsConfig(f.listen, f.hard)
	if err != nil {
		fprintf(stderr, "innsegl connect: %v\n", err)
		return exitConnectFailed
	}
	err = client.CheckSettingsWritable(f.settings, settings)
	if code, done := reportNotWritable(err, stderr, ", then run the same `innsegl connect` again (the token is not spent yet)"); done {
		return code
	}
	if err != nil {
		fprintf(stderr, "innsegl connect: %v\n", err)
		return exitConnectFailed
	}

	ca, err := connectCA(ctx, f, coreURL)
	if err != nil {
		fprintf(stderr, "innsegl connect: %v\nNothing was written.\n", err)
		return exitConnectFailed
	}
	name := f.name
	if name == "" {
		if name, err = deps.hostname(); err != nil || name == "" {
			name = "innsegl-client"
		}
	}
	enrolment, err := client.Enrol(ctx, client.EnrolOptions{CoreURL: coreURL, Token: f.token, Name: name, CA: ca})
	if errors.Is(err, client.ErrUnauthorized) {
		fprintf(stderr, "innsegl connect: %v. Nothing was written; ask for a new token.\n", err)
		return exitConnectFailed
	}
	if err != nil {
		fprintf(stderr, "innsegl connect: enrolling: %v\nNothing was written.\n", err)
		return exitConnectFailed
	}
	if err = client.WriteEnrolment(paths, enrolment, f.listen); err != nil {
		fprintf(stderr, "innsegl connect: writing %s: %v\n", paths.Dir, err)
		return exitConnectFailed
	}
	fprintf(stdout, "innsegl connect: enrolled as installation %s; the certificate expires %s\n",
		enrolment.InstallationID, enrolment.ExpiresAt.UTC().Format(time.RFC3339))

	err = client.InstallSettings(f.settings, settings, deps.now, stdout)
	if code, done := reportNotWritable(err, stderr, ""); done {
		return code
	}
	if err != nil {
		fprintf(stderr, "innsegl connect: %v\n", err)
		return exitConnectFailed
	}

	failed := false
	if f.noService {
		fprintf(stdout, "innsegl connect: --no-service: run `%s client serve` yourself; the managed settings point at http://%s\n",
			settings.HookBin, f.listen)
	} else if err := deps.service().Install(settings.HookBin); err != nil {
		fprintf(stderr, "innsegl connect: installing the client service: %v\n"+
			"  Run `%s client serve` yourself until it is fixed.\n", err, settings.HookBin)
		failed = true
	} else {
		fprintf(stdout, "innsegl connect: installed and started the client service (%s)\n", deps.service().Path())
	}

	for _, dir := range dirs {
		if runLinkInstall(ctx, filepath.Clean(dir), stdout, stderr) != exitOK {
			failed = true
		}
	}

	fprintf(stdout, "\nConnected to %s.\nManaged settings: %s\nLocal endpoint:   http://%s\n"+
		"Restart Claude Code for the settings to take effect.\n", coreURL, f.settings, f.listen)
	if failed {
		return exitConnectFailed
	}
	return exitOK
}

// connectCA returns the core's CA, from --ca or fetched and confirmed by
// --ca-fingerprint.
func connectCA(ctx context.Context, f connectFlags, coreURL string) (*x509.Certificate, error) {
	if f.fingerprint != "" {
		return client.FetchCA(ctx, coreURL, f.fingerprint)
	}
	text, err := os.ReadFile(f.ca)
	if err != nil {
		return nil, fmt.Errorf("reading --ca: %w", err)
	}
	block, _ := pem.Decode(text)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("--ca %s holds no PEM certificate", f.ca)
	}
	return x509.ParseCertificate(block.Bytes)
}
