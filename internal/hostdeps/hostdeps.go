// SPDX-License-Identifier: Apache-2.0

// Package hostdeps names what a client machine needs from its host before
// innsegl acts on it (#592): each missing program, why it is needed, and the
// one command that installs it on this OS. It installs nothing; the person
// runs the command.
//
// The core host's tools (Docker, compose, Go, openssl, jq) are checked by
// install.sh, which runs before there is a binary to run this.
package hostdeps

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"innsegl.dev/innsegl/internal/trustbackup"
)

// MinGit is the oldest git innsegl's hooks work with: `git rev-parse
// --path-format=absolute` arrived in 2.31.
const MinGit = "2.31"

// Env is the machine being checked. Tests replace every field; Real is this
// one.
type Env struct {
	GOOS string
	// OSRelease is /etc/os-release, which names a Linux distribution.
	OSRelease string
	LookPath  func(string) (string, error)
	// Output runs a program and returns what it printed.
	Output func(name string, args ...string) (string, error)
	// IdentityFile is the operator's age identity file; each plugin it
	// names must be on PATH to open the CA's unlock material. Empty or
	// absent: no plugin is needed.
	IdentityFile string
}

// Real is this machine.
func Real(goos, identityFile string) Env {
	release, _ := os.ReadFile("/etc/os-release")
	return Env{
		GOOS: goos, OSRelease: string(release), IdentityFile: identityFile,
		LookPath: exec.LookPath,
		Output: func(name string, args ...string) (string, error) {
			out, err := exec.Command(name, args...).Output() //nolint:gosec // G204: fixed program names
			return string(out), err
		},
	}
}

// Missing is one dependency this machine lacks.
type Missing struct {
	Name    string
	Why     string
	Install string
	// Required: innsegl cannot work without it. Otherwise one feature
	// cannot (the CA unlock, for a plugin).
	Required bool
}

// Family is the OS's package family: macos, debian, fedora or other.
func Family(goos, osRelease string) string {
	if goos == "darwin" {
		return "macos"
	}
	if goos != "linux" {
		return "other"
	}
	ids := []string{}
	for _, line := range strings.Split(osRelease, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && (k == "ID" || k == "ID_LIKE") {
			ids = append(ids, strings.Fields(strings.Trim(v, `"'`))...)
		}
	}
	for _, id := range ids {
		switch id {
		case "debian", "ubuntu":
			return "debian"
		case "fedora", "rhel", "centos":
			return "fedora"
		}
	}
	return "other"
}

// commands is one install command per family.
type commands struct{ macos, debian, fedora string }

func (c commands) pick(family string) string {
	switch family {
	case "macos":
		return c.macos
	case "debian":
		return c.debian
	case "fedora":
		return c.fedora
	}
	return "Debian/Ubuntu: " + c.debian + "; Fedora: " + c.fedora
}

var gitInstall = commands{
	macos:  "xcode-select --install",
	debian: "sudo apt-get install -y git",
	fedora: "sudo dnf install -y git",
}

// pluginInstall is how to install age-plugin-<name>.
func pluginInstall(name, family string) string {
	switch name {
	case "se":
		if family == "macos" {
			return "brew install age-plugin-se"
		}
		return "age-plugin-se needs a Mac's Secure Enclave; on this machine use an identity for another plugin"
	case "yubikey":
		if family == "macos" {
			return "brew install age-plugin-yubikey"
		}
		return "cargo install age-plugin-yubikey"
	}
	return "install age-plugin-" + name + " and put it on PATH"
}

var gitVersion = regexp.MustCompile(`git version (\d+)\.(\d+)`)

// atLeast says whether major.minor is at least min ("2.31").
func atLeast(major, minor int, min string) bool {
	mj, mn, _ := strings.Cut(min, ".")
	wantMajor, _ := strconv.Atoi(mj)
	wantMinor, _ := strconv.Atoi(mn)
	return major > wantMajor || (major == wantMajor && minor >= wantMinor)
}

// Check names every dependency the machine lacks, in one pass.
func Check(e Env) []Missing {
	family := Family(e.GOOS, e.OSRelease)
	var out []Missing

	gitWhy := "git " + MinGit + " or later: hooks, linking and signing"
	if _, err := e.LookPath("git"); err != nil {
		out = append(out, Missing{Name: "git", Why: gitWhy, Install: gitInstall.pick(family), Required: true})
	} else {
		v, _ := e.Output("git", "--version")
		m := gitVersion.FindStringSubmatch(v)
		ok := false
		if m != nil {
			major, _ := strconv.Atoi(m[1])
			minor, _ := strconv.Atoi(m[2])
			ok = atLeast(major, minor, MinGit)
		}
		if !ok {
			out = append(out, Missing{Name: "git", Why: gitWhy + "; this one says " + strings.TrimSpace(v),
				Install: gitInstall.pick(family), Required: true})
		}
	}

	for _, name := range identityPlugins(e.IdentityFile) {
		bin := "age-plugin-" + name
		if _, err := e.LookPath(bin); err != nil {
			out = append(out, Missing{Name: bin, Why: "the identity file " + e.IdentityFile +
				" names it; it opens the CA's unlock material", Install: pluginInstall(name, family)})
		}
	}
	return out
}

// identityPlugins are the plugins the identity file names; none when it is
// absent or unreadable (the command that uses it says why).
func identityPlugins(path string) []string {
	if path == "" {
		return nil
	}
	f, err := os.Open(path) //nolint:gosec // G304: the operator's own identity file
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	names, err := trustbackup.PluginNames(f)
	if err != nil {
		return nil
	}
	return names
}

// Report writes one line per missing dependency, each with its command.
func Report(w io.Writer, prefix string, missing []Missing) {
	for _, m := range missing {
		scope := ""
		if !m.Required {
			scope = ", needed for the CA unlock only"
		}
		_, _ = fmt.Fprintf(w, "%s: missing %s (%s)%s; install: %s\n", prefix, m.Name, m.Why, scope, m.Install)
	}
}

// AnyRequired says whether something innsegl cannot work without is missing.
func AnyRequired(missing []Missing) bool {
	for _, m := range missing {
		if m.Required {
			return true
		}
	}
	return false
}
