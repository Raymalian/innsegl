// SPDX-License-Identifier: Apache-2.0

package hostdeps

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age/plugin"
)

// CLI-027 (PROPOSED for doc 07, #592) — before connect or doctor acts, every
// dependency this machine's role needs and does not have is named in one run,
// each with the one command that installs it on this OS. Nothing is
// installed: the commands are printed for the person to run.

const debianRelease = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nID=debian\n"
const ubuntuRelease = "NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\n"
const fedoraRelease = "NAME=\"Fedora Linux\"\nID=fedora\n"
const rockyRelease = "NAME=\"Rocky Linux\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n"

func TestCLI027TheOSFamilyComesFromOSRelease(t *testing.T) {
	for _, c := range []struct{ goos, release, want string }{
		{"darwin", "", "macos"},
		{"linux", debianRelease, "debian"},
		{"linux", ubuntuRelease, "debian"},
		{"linux", fedoraRelease, "fedora"},
		{"linux", rockyRelease, "fedora"},
		{"linux", "ID=arch\n", "other"},
		{"linux", "", "other"},
		{"freebsd", "", "other"},
	} {
		if got := Family(c.goos, c.release); got != c.want {
			t.Errorf("Family(%s, %q) = %s, want %s", c.goos, c.release, got, c.want)
		}
	}
}

// env is a machine with the given programs, each answering --version.
func env(goos, release string, programs map[string]string) Env {
	return Env{
		GOOS: goos, OSRelease: release,
		LookPath: func(name string) (string, error) {
			if _, ok := programs[name]; ok {
				return "/usr/bin/" + name, nil
			}
			return "", exec.ErrNotFound
		},
		Output: func(name string, _ ...string) (string, error) {
			if v, ok := programs[name]; ok {
				return v, nil
			}
			return "", errors.New("not found")
		},
	}
}

func pluginIdentity(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(p, []byte(plugin.EncodeIdentity(name, []byte("h"))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCLI027EveryMissingDependencyIsNamedInOneRun(t *testing.T) {
	e := env("linux", debianRelease, map[string]string{})
	e.IdentityFile = pluginIdentity(t, "yubikey")
	missing := Check(e)
	names := map[string]Missing{}
	for _, m := range missing {
		names[m.Name] = m
	}
	git, ok := names["git"]
	if !ok || !git.Required || git.Install != "sudo apt-get install -y git" {
		t.Fatalf("git not named as required with the apt line: %+v", missing)
	}
	p, ok := names["age-plugin-yubikey"]
	if !ok || p.Required || p.Install == "" {
		t.Fatalf("the identity file's plugin not named, as needed for the CA unlock: %+v", missing)
	}
}

func TestCLI027TheInstallCommandIsTheOnesForThisOS(t *testing.T) {
	for release, want := range map[string]string{
		"":            "xcode-select --install",
		debianRelease: "sudo apt-get install -y git",
		fedoraRelease: "sudo dnf install -y git",
	} {
		goos := "linux"
		if release == "" {
			goos = "darwin"
		}
		missing := Check(env(goos, release, nil))
		if len(missing) != 1 || missing[0].Install != want {
			t.Errorf("%s %q: %+v, want git with %q", goos, release, missing, want)
		}
	}
	// An OS with no known package manager gets every line, labelled.
	missing := Check(env("linux", "ID=arch\n", nil))
	if len(missing) != 1 || !strings.Contains(missing[0].Install, "apt-get") || !strings.Contains(missing[0].Install, "dnf") {
		t.Fatalf("an unknown Linux: %+v", missing)
	}
}

func TestCLI027GitOlderThanTheMinimumIsNamed(t *testing.T) {
	for v, ok := range map[string]bool{
		"git version 2.30.9":                 false,
		"git version 2.31.0":                 true,
		"git version 2.54.0 (Apple Git-157)": true,
		"git version 3.0.0":                  true,
		"not a version":                      false,
	} {
		missing := Check(env("darwin", "", map[string]string{"git": v}))
		if (len(missing) == 0) != ok {
			t.Errorf("%q: %+v", v, missing)
		}
		if !ok && (len(missing) != 1 || !strings.Contains(missing[0].Why, MinGit)) {
			t.Errorf("%q: the minimum is not said: %+v", v, missing)
		}
	}
}

func TestCLI027APluginOnPATHAndAWorkingMachineNameNothing(t *testing.T) {
	e := env("darwin", "", map[string]string{"git": "git version 2.40.0", "age-plugin-se": ""})
	e.IdentityFile = pluginIdentity(t, "se")
	if missing := Check(e); len(missing) != 0 {
		t.Fatalf("a complete machine: %+v", missing)
	}
	e = env("darwin", "", map[string]string{"git": "git version 2.40.0"})
	e.IdentityFile = pluginIdentity(t, "se")
	missing := Check(e)
	if len(missing) != 1 || missing[0].Install != "brew install age-plugin-se" {
		t.Fatalf("age-plugin-se on macOS: %+v", missing)
	}
	// No identity file: no plugin is needed.
	e.IdentityFile = filepath.Join(t.TempDir(), "absent")
	if missing := Check(e); len(missing) != 0 {
		t.Fatalf("no identity file: %+v", missing)
	}
}

func TestCLI027TheReportIsOneLinePerDependency(t *testing.T) {
	var b strings.Builder
	Report(&b, "innsegl connect", []Missing{
		{Name: "git", Why: "git " + MinGit + " or later: hooks and signing", Install: "sudo apt-get install -y git", Required: true},
		{Name: "age-plugin-x", Why: "opens the CA unlock material", Install: "install age-plugin-x", Required: false},
	})
	want := "innsegl connect: missing git (git " + MinGit + " or later: hooks and signing); install: sudo apt-get install -y git\n" +
		"innsegl connect: missing age-plugin-x (opens the CA unlock material), needed for the CA unlock only; install: install age-plugin-x\n"
	if b.String() != want {
		t.Fatalf("report:\n%s\nwant:\n%s", b.String(), want)
	}
	if AnyRequired([]Missing{{Required: false}}) || !AnyRequired([]Missing{{}, {Required: true}}) {
		t.Fatal("AnyRequired")
	}
}
