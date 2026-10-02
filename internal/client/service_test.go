// SPDX-License-Identifier: Apache-2.0

package client

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const goldenPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.innsegl.client</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/innsegl &amp; co/innsegl</string>
    <string>client</string>
    <string>serve</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StandardOutPath</key>
  <string>/opt/home-dev/Library/Logs/innsegl-client.log</string>
  <key>StandardErrorPath</key>
  <string>/opt/home-dev/Library/Logs/innsegl-client.log</string>
</dict>
</plist>
`

const goldenUnit = `[Unit]
Description=innsegl client: the local endpoint for the harness, hooks and git
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart="/opt/innsegl/bin/innsegl" client serve
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
`

func TestServicePlistGolden(t *testing.T) {
	got := RenderPlist("/opt/innsegl & co/innsegl", "/opt/home-dev/Library/Logs/innsegl-client.log")
	if got != goldenPlist {
		t.Fatalf("plist differs\n--- got\n%s\n--- want\n%s", got, goldenPlist)
	}
}

func TestServiceUnitGolden(t *testing.T) {
	got := RenderUnit("/opt/innsegl/bin/innsegl")
	if got != goldenUnit {
		t.Fatalf("unit differs\n--- got\n%s\n--- want\n%s", got, goldenUnit)
	}
}

type recorder struct{ calls [][]string }

func (r *recorder) run(name string, args ...string) error {
	r.calls = append(r.calls, append([]string{name}, args...))
	return nil
}

func TestServiceInstallAndUninstallOnDarwin(t *testing.T) {
	home := t.TempDir()
	rec := &recorder{}
	svc := Service{GOOS: "darwin", Home: home, UID: 501, Run: rec.run}
	if err := svc.Install("/opt/innsegl/bin/innsegl"); err != nil {
		t.Fatalf("Install: %v", err)
	}
	plist := filepath.Join(home, "Library", "LaunchAgents", "dev.innsegl.client.plist")
	if svc.Path() != plist {
		t.Fatalf("Path = %q", svc.Path())
	}
	text, err := os.ReadFile(plist)
	if err != nil || string(text) != RenderPlist("/opt/innsegl/bin/innsegl", filepath.Join(home, "Library", "Logs", "innsegl-client.log")) {
		t.Fatalf("plist not written as rendered (err=%v)", err)
	}
	// The log exists before launchd starts anything, so a service that
	// never ran still leaves the file the person is told to read.
	logPath := filepath.Join(home, "Library", "Logs", "innsegl-client.log")
	if fi, err := os.Stat(logPath); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("the service log %s was not created: %v", logPath, err)
	}
	want := [][]string{
		{"launchctl", "bootout", "gui/501/dev.innsegl.client"},
		{"launchctl", "bootstrap", "gui/501", plist},
	}
	if !reflect.DeepEqual(rec.calls, want) {
		t.Fatalf("calls = %v, want %v", rec.calls, want)
	}
	rec.calls = nil
	if err := svc.Uninstall(); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if _, err := os.Stat(plist); !os.IsNotExist(err) {
		t.Fatal("the plist is still there")
	}
	if !reflect.DeepEqual(rec.calls, [][]string{{"launchctl", "bootout", "gui/501/dev.innsegl.client"}}) {
		t.Fatalf("calls = %v", rec.calls)
	}
}

func TestServiceInstallAndUninstallOnLinux(t *testing.T) {
	home := t.TempDir()
	rec := &recorder{}
	svc := Service{GOOS: "linux", Home: home, UID: 1000, Run: rec.run}
	if err := svc.Install("/opt/innsegl/bin/innsegl"); err != nil {
		t.Fatalf("Install: %v", err)
	}
	unit := filepath.Join(home, ".config", "systemd", "user", "innsegl-client.service")
	if text, err := os.ReadFile(unit); err != nil || string(text) != goldenUnit {
		t.Fatalf("unit not written as rendered (err=%v)", err)
	}
	want := [][]string{
		{"systemctl", "--user", "daemon-reload"},
		{"systemctl", "--user", "enable", "innsegl-client.service"},
		{"systemctl", "--user", "restart", "innsegl-client.service"},
	}
	if !reflect.DeepEqual(rec.calls, want) {
		t.Fatalf("calls = %v, want %v", rec.calls, want)
	}
	rec.calls = nil
	if err := svc.Uninstall(); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if _, err := os.Stat(unit); !os.IsNotExist(err) {
		t.Fatal("the unit is still there")
	}
	want = [][]string{
		{"systemctl", "--user", "disable", "--now", "innsegl-client.service"},
		{"systemctl", "--user", "daemon-reload"},
	}
	if !reflect.DeepEqual(rec.calls, want) {
		t.Fatalf("calls = %v, want %v", rec.calls, want)
	}
}

func TestServiceRefusesAnUnsupportedPlatform(t *testing.T) {
	svc := Service{GOOS: "windows", Home: t.TempDir(), Run: (&recorder{}).run}
	if err := svc.Install("/x"); err == nil || !strings.Contains(err.Error(), "windows") {
		t.Fatalf("err = %v", err)
	}
}
