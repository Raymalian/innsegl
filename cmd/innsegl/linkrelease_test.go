// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CLI-041 (PROPOSED for doc 07, #599), git hooks: `innsegl link` writes the
// installed copy's path into a repository's hooks under the same rule as
// connect, and linkEnsure (the session hook's link on first use) rewrites
// hooks an earlier link pointed at another binary. Every path is a
// temporary one; which count as root's is the stand-in deps say.

// useLinkBinary has link pick its binary as connect would, from deps, for
// the rest of the test.
func useLinkBinary(t *testing.T, deps connectDeps) {
	t.Helper()
	prev := linkBinary
	linkBinary = deps.hookBinary
	t.Cleanup(func() { linkBinary = prev })
}

// releaseDeps is a build at a path the user owns, and an installed copy
// holding content, which counts as root's when rootOwned.
func releaseDeps(t *testing.T, self, content string, rootOwned bool) (connectDeps, string) {
	t.Helper()
	f := &connectFixture{}
	selfBuild(t, f, self)
	release := releaseCopy(t, f, content, rootOwned)
	return f.deps, release
}

func hookBins(t *testing.T, repo string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, h := range managedHooks {
		p, _, err := linkHookPathsFor(context.Background(), repo, h.name)
		if err != nil {
			t.Fatal(err)
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(repo, p)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			out[h.name] = ""
			continue
		}
		out[h.name] = hookScriptBin(string(b))
	}
	return out
}

func TestCLI041LinkRefusesABinaryTheUserCanChange(t *testing.T) {
	deps, _ := releaseDeps(t, "build-1", "", true)
	useLinkBinary(t, deps)
	repo := gitInitRepo(t)
	var stdout, stderr bytes.Buffer
	if code := runLinkInstall(context.Background(), repo, &stdout, &stderr); code == exitOK {
		t.Fatalf("link with a changeable binary succeeded:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "make install-release") {
		t.Errorf("the refusal does not name make install-release:\n%s", stderr.String())
	}
	for name, bin := range hookBins(t, repo) {
		if bin != "" {
			t.Errorf("%s was written, running %s", name, bin)
		}
	}
}

func TestCLI041LinkWritesTheInstalledCopy(t *testing.T) {
	deps, release := releaseDeps(t, "build-1", "build-1", true)
	useLinkBinary(t, deps)
	repo := gitInitRepo(t)
	var stdout, stderr bytes.Buffer
	if code := runLinkInstall(context.Background(), repo, &stdout, &stderr); code != exitOK {
		t.Fatalf("link = %d:\n%s", code, stderr.String())
	}
	for name, bin := range hookBins(t, repo) {
		if bin != release {
			t.Errorf("%s runs %q, want the installed copy %s", name, bin, release)
		}
	}
}

// A repository linked by an earlier build names that build; the session
// hook's linkEnsure moves every hook onto the installed copy.
func TestCLI041LinkEnsureRewritesHooksNamingAnotherBinary(t *testing.T) {
	repo := gitInitRepo(t)
	prev := linkBinary
	linkBinary = func() (string, error) { return "/old/checkout/innsegl", nil }
	var out bytes.Buffer
	if code := runLinkInstall(context.Background(), repo, &out, &out); code != exitOK {
		t.Fatalf("setup link: %s", out.String())
	}
	linkBinary = prev
	deps, release := releaseDeps(t, "build-1", "build-1", true)
	useLinkBinary(t, deps)
	installed, err := linkEnsure(context.Background(), repo)
	if err != nil || !installed {
		t.Fatalf("linkEnsure = %v, %v; want the hooks rewritten", installed, err)
	}
	for name, bin := range hookBins(t, repo) {
		if bin != release {
			t.Errorf("%s runs %q, want %s", name, bin, release)
		}
	}
	if installed, err := linkEnsure(context.Background(), repo); err != nil || installed {
		t.Fatalf("a second linkEnsure rewrote again: %v, %v", installed, err)
	}
}

// With no installed copy to name, linkEnsure leaves complete hooks as they
// are: it has nothing better to write.
func TestCLI041LinkEnsureLeavesHooksWhenNothingIsInstalled(t *testing.T) {
	repo := gitInitRepo(t)
	prev := linkBinary
	linkBinary = func() (string, error) { return "/old/checkout/innsegl", nil }
	var out bytes.Buffer
	if code := runLinkInstall(context.Background(), repo, &out, &out); code != exitOK {
		t.Fatalf("setup link: %s", out.String())
	}
	linkBinary = prev
	deps, _ := releaseDeps(t, "build-1", "", true)
	useLinkBinary(t, deps)
	if installed, err := linkEnsure(context.Background(), repo); err != nil || installed {
		t.Fatalf("linkEnsure = %v, %v; want the hooks left alone", installed, err)
	}
	for name, bin := range hookBins(t, repo) {
		if bin != "/old/checkout/innsegl" {
			t.Errorf("%s runs %q", name, bin)
		}
	}
}
