// SPDX-License-Identifier: Apache-2.0

package client

import (
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"innsegl.dev/innsegl/internal/trustbackup"
)

// LaunchdLabel names the macOS LaunchAgent.
const LaunchdLabel = "dev.innsegl.client"

// LogFileName is the macOS service log, under ~/Library/Logs. On Linux
// the service logs to the user journal.
const LogFileName = "innsegl-client.log"

// SystemdUnit names the Linux systemd --user unit.
const SystemdUnit = "innsegl-client.service"

// ReleaseDir is where `make install-release` (scripts/install-release.sh)
// puts the copy of innsegl that the hooks, the client service and scheduled
// jobs run (#599): a folder owned by root, on macOS and Linux alike. A build
// in a checkout is rewritten by every `go build`, by the operator or by any
// agent working there; this copy changes only through sudo.
const ReleaseDir = "/usr/local/libexec/innsegl"

// ReleaseBinary is the installed copy itself.
func ReleaseBinary() string { return filepath.Join(ReleaseDir, "innsegl") }

// RenderPlist is the LaunchAgent that keeps `innsegl client serve` running
// for the logged-in user. KeepAlive restarts it whenever it exits.
// Interactive, not Background: the service unlocks the CA store with a
// Secure Enclave key, and that asks the operator for Touch ID on screen
// (ADR-0076). path, when set, is the service's PATH (ServicePATH).
func RenderPlist(bin, logPath, path string) string {
	esc := html.EscapeString
	env := ""
	if path != "" {
		env = `  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>` + esc(path) + `</string>
  </dict>
`
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>` + LaunchdLabel + `</string>
  <key>ProgramArguments</key>
  <array>
    <string>` + esc(bin) + `</string>
    <string>client</string>
    <string>serve</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Interactive</string>
` + env + `  <key>StandardOutPath</key>
  <string>` + esc(logPath) + `</string>
  <key>StandardErrorPath</key>
  <string>` + esc(logPath) + `</string>
</dict>
</plist>
`
}

// RenderUnit is the systemd --user unit for `innsegl client serve`. Its
// output goes to the user journal. path, when set, is the service's PATH
// (ServicePATH).
func RenderUnit(bin, path string) string {
	env := ""
	if path != "" {
		// Environment= expands specifiers (%) but not variables ($).
		r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`)
		env = `Environment="PATH=` + r.Replace(path) + `"` + "\n"
	}
	return `[Unit]
Description=innsegl client: the local endpoint for the harness, hooks and git
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
` + env + `ExecStart=` + systemdQuote(bin) + ` client serve
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
`
}

// systemdQuote double-quotes a path for ExecStart, escaping what systemd
// would otherwise read as a quote, an escape, a specifier or a variable.
func systemdQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`, `$`, `$$`)
	return `"` + r.Replace(s) + `"`
}

// Service installs and removes the user-level service. Run executes one
// service-manager command; tests record it instead.
type Service struct {
	GOOS string
	Home string
	UID  int
	Run  func(name string, args ...string) error
	// Log, when set, receives notes about expected failures.
	Log io.Writer
	// PATH, when set, is written into the service definition (ServicePATH);
	// empty leaves the service manager's default.
	PATH string
}

// DefaultServicePATH is the PATH a user service gets when its definition
// sets none: launchd's for a LaunchAgent (measured on macOS), systemd's
// for a --user unit.
func DefaultServicePATH(goos string) string {
	if goos == "darwin" {
		return "/usr/bin:/bin:/usr/sbin:/sbin"
	}
	return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
}

// PluginPinsFile is where connect records the age plugins it pinned
// (#598): beside core.json, in the client's 0700 folder.
func PluginPinsFile(p Paths) string {
	return filepath.Join(p.Dir, "age-plugins.json")
}

// PinPlugins resolves each age plugin the operator's identity file names,
// once, as lookPath finds it now, and pins its file and hash (CLI-046,
// CLI-047, #598). No identity file, or one with no plugin identity, pins
// nothing. problems names each plugin not pinned and why: not found, or
// replaceable by someone other than its owner.
func PinPlugins(identityFile string, lookPath func(string) (string, error)) (pins []trustbackup.PluginPin, problems []string, err error) {
	f, err := os.Open(identityFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	names, err := trustbackup.PluginNames(f)
	if err != nil {
		return nil, nil, err
	}
	for _, n := range names {
		pin, perr := trustbackup.PinPlugin(n, lookPath)
		if perr != nil {
			problems = append(problems, perr.Error())
			continue
		}
		pins = append(pins, pin)
	}
	return pins, problems, nil
}

// ServicePATH is the PATH the client service needs to run the pinned age
// plugins (CLI-025, #592; #598): the service manager's default with each
// pinned plugin's own directory added after it. That is the directory of
// the file the pin names, symlinks resolved, not a shared bin folder, so
// the service's PATH holds nothing else the plugin's installer put there.
// It is empty when the default already finds every plugin.
func ServicePATH(goos string, pins []trustbackup.PluginPin) string {
	dirs := filepath.SplitList(DefaultServicePATH(goos))
	added := false
	for _, p := range pins {
		if d := filepath.Dir(p.Path); !slices.Contains(dirs, d) {
			dirs = append(dirs, d)
			added = true
		}
	}
	if !added {
		return ""
	}
	return strings.Join(dirs, string(os.PathListSeparator))
}

// Path is where the service definition is written.
func (s Service) Path() string {
	switch s.GOOS {
	case "darwin":
		return filepath.Join(s.Home, "Library", "LaunchAgents", LaunchdLabel+".plist")
	case "linux":
		return filepath.Join(s.Home, ".config", "systemd", "user", SystemdUnit)
	}
	return ""
}

func (s Service) unsupported() error {
	return fmt.Errorf("no user service is known for %s; run `innsegl client serve` yourself, or pass --no-service", s.GOOS)
}

// Install writes the service definition for bin and (re)starts it.
func (s Service) Install(bin string) error {
	path := s.Path()
	if path == "" {
		return s.unsupported()
	}
	var content string
	switch s.GOOS {
	case "darwin":
		logs := filepath.Join(s.Home, "Library", "Logs")
		if err := os.MkdirAll(logs, 0o755); err != nil {
			return err
		}
		logPath := filepath.Join(logs, LogFileName)
		// launchd opens the log only when it starts the process, so a
		// service that never started leaves no file at all. Create it here:
		// the file then always exists where the person is told to look.
		// #nosec G302 G304 -- the user's own log, under their home.
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fmt.Errorf("creating the service log: %w", err)
		}
		if err := f.Close(); err != nil {
			return err
		}
		content = RenderPlist(bin, logPath, s.PATH)
	default:
		content = RenderUnit(bin, s.PATH)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// #nosec G306 -- a service definition the user's service manager reads.
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return err
	}
	switch s.GOOS {
	case "darwin":
		// A service already loaded keeps its old definition: unload it
		// first. Its failure when nothing was loaded is expected.
		s.try("launchctl", "bootout", s.launchdTarget())
		return s.Run("launchctl", "bootstrap", "gui/"+strconv.Itoa(s.UID), path)
	default:
		if err := s.Run("systemctl", "--user", "daemon-reload"); err != nil {
			return err
		}
		if err := s.Run("systemctl", "--user", "enable", SystemdUnit); err != nil {
			return err
		}
		return s.Run("systemctl", "--user", "restart", SystemdUnit)
	}
}

// try runs a command whose failure is expected and harmless: unloading a
// service that was never loaded, or reloading after it is gone.
// Its failure is noted on Log, when one is set, and changes nothing else.
func (s Service) try(name string, args ...string) {
	if err := s.Run(name, args...); err != nil && s.Log != nil {
		fmt.Fprintf(s.Log, "innsegl: note: %v (expected when the service was not loaded)\n", err)
	}
}

func (s Service) launchdTarget() string {
	return "gui/" + strconv.Itoa(s.UID) + "/" + LaunchdLabel
}

// LegacyBackupLabel names the host timer that ran scripts/backup-ledger.sh
// from a checkout until #237 moved the ledger backup into the deployment.
// Nothing installs it any more; a machine that had it keeps it until it is
// removed.
const LegacyBackupLabel = "dev.innsegl.backup-ledger"

// LeftoverBackupJob is that timer's unit file and the one command that
// removes it (#599). ok is false when no such file is there; path is where
// it would be all the same. The job runs a script from a checkout, which
// any agent working there can change, every day with nobody watching.
func (s Service) LeftoverBackupJob() (path, remove string, ok bool) {
	switch s.GOOS {
	case "darwin":
		path = filepath.Join(s.Home, "Library", "LaunchAgents", LegacyBackupLabel+".plist")
		remove = "launchctl bootout gui/" + strconv.Itoa(s.UID) + "/" + LegacyBackupLabel + "; rm -f " + shellQuote(path)
	case "linux":
		dir := filepath.Join(s.Home, ".config", "systemd", "user")
		path = filepath.Join(dir, LegacyBackupLabel+".timer")
		remove = "systemctl --user disable --now " + LegacyBackupLabel + ".timer; rm -f " + shellQuote(path) + " " +
			shellQuote(filepath.Join(dir, LegacyBackupLabel+".service")) + "; systemctl --user daemon-reload"
	default:
		return "", "", false
	}
	_, err := os.Lstat(path)
	return path, remove, err == nil
}

// Uninstall stops the service and removes its definition. A service that
// was never installed is not an error.
func (s Service) Uninstall() error {
	path := s.Path()
	if path == "" {
		return s.unsupported()
	}
	switch s.GOOS {
	case "darwin":
		s.try("launchctl", "bootout", s.launchdTarget())
	default:
		s.try("systemctl", "--user", "disable", "--now", SystemdUnit)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if s.GOOS == "linux" {
		s.try("systemctl", "--user", "daemon-reload")
	}
	return nil
}
