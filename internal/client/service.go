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
	"strconv"
	"strings"
)

// LaunchdLabel names the macOS LaunchAgent.
const LaunchdLabel = "dev.innsegl.client"

// LogFileName is the macOS service log, under ~/Library/Logs. On Linux
// the service logs to the user journal.
const LogFileName = "innsegl-client.log"

// SystemdUnit names the Linux systemd --user unit.
const SystemdUnit = "innsegl-client.service"

// RenderPlist is the LaunchAgent that keeps `innsegl client serve` running
// for the logged-in user. KeepAlive restarts it whenever it exits.
// Interactive, not Background: the service unlocks the CA store with a
// Secure Enclave key, and that asks the operator for Touch ID on screen
// (ADR-0076).
func RenderPlist(bin, logPath string) string {
	esc := html.EscapeString
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
  <key>StandardOutPath</key>
  <string>` + esc(logPath) + `</string>
  <key>StandardErrorPath</key>
  <string>` + esc(logPath) + `</string>
</dict>
</plist>
`
}

// RenderUnit is the systemd --user unit for `innsegl client serve`. Its
// output goes to the user journal.
func RenderUnit(bin string) string {
	return `[Unit]
Description=innsegl client: the local endpoint for the harness, hooks and git
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=` + systemdQuote(bin) + ` client serve
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
		content = RenderPlist(bin, logPath)
	default:
		content = RenderUnit(bin)
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
