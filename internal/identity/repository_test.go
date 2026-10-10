// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
)

// PRI-007 (ADR-0080 decisions 1 and 2): the repository and branch
// pseudonyms schema 5 lets the chain carry.

const (
	testRepoKey      = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	otherTestRepoKey = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	testRepo         = "github.com/acme/payments"
	testBranch       = "feature/quiet-acquisition"
)

func mustRepositories(t *testing.T, mode Mode, key string) *Repositories {
	t.Helper()
	r, err := NewRepositories(mode, key)
	if err != nil {
		t.Fatalf("NewRepositories(%q): %v", mode, err)
	}
	return r
}

func TestPRI007RepositoryPseudonyms(t *testing.T) {
	p := mustRepositories(t, ModePseudonymous, testRepoKey)

	repo, err := p.Repo(testRepo)
	if err != nil {
		t.Fatalf("Repo: %v", err)
	}
	branch, err := p.Branch(testRepo, testBranch)
	if err != nil {
		t.Fatalf("Branch: %v", err)
	}

	t.Run("both satisfy the schema-5 grammar and name the key id", func(t *testing.T) {
		for _, v := range []string{repo, branch} {
			if err := event.ValidatePseudonym(v); err != nil {
				t.Errorf("%q: %v", v, err)
			}
			if !strings.HasPrefix(v, "pn:"+p.KeyID()+":") {
				t.Errorf("%q does not carry key id %q", v, p.KeyID())
			}
		}
	})

	t.Run("the key id is derived from the key, and fits the identifier grammar", func(t *testing.T) {
		sum := sha256.Sum256([]byte("innsegl-repo-key-id:" + testRepoKey))
		if want := "rk-" + hex.EncodeToString(sum[:])[:8]; p.KeyID() != want {
			t.Errorf("KeyID = %q, want %q", p.KeyID(), want)
		}
		if err := event.ValidateIdentifier(p.KeyID()); err != nil {
			t.Errorf("KeyID %q: %v", p.KeyID(), err)
		}
	})

	t.Run("never contains the input", func(t *testing.T) {
		for _, part := range []string{"github", "acme", "payments", "feature", "quiet"} {
			if strings.Contains(repo, part) || strings.Contains(branch, part) {
				t.Errorf("a pseudonym carries %q", part)
			}
		}
	})

	t.Run("stable for one key", func(t *testing.T) {
		again := mustRepositories(t, ModePseudonymous, testRepoKey)
		r2, _ := again.Repo(testRepo)
		b2, _ := again.Branch(testRepo, testBranch)
		if r2 != repo || b2 != branch {
			t.Errorf("a second instance on the same key gave %q, %q", r2, b2)
		}
	})

	t.Run("different under another key, and under another key id", func(t *testing.T) {
		other := mustRepositories(t, ModePseudonymous, otherTestRepoKey)
		r2, _ := other.Repo(testRepo)
		if r2 == repo || other.KeyID() == p.KeyID() {
			t.Errorf("two keys gave %q and %q (ids %q, %q)", repo, r2, p.KeyID(), other.KeyID())
		}
		if r2[strings.LastIndex(r2, ":"):] == repo[strings.LastIndex(repo, ":"):] {
			t.Error("two keys gave the same digest")
		}
	})

	t.Run("repo and branch are domain-separated", func(t *testing.T) {
		// A branch spelled like the repository is still a different
		// pseudonym, and so is the agent_type domain ADR-0041 uses.
		b, _ := p.Branch(testRepo, "github.com/acme/payments")
		if b == repo {
			t.Error("a branch named like its repository pseudonymises to the repository")
		}
	})

	t.Run("one branch name in two repositories gives two values", func(t *testing.T) {
		a, _ := p.Branch("github.com/acme/api", "main")
		b, _ := p.Branch("github.com/acme/web", "main")
		if a == b {
			t.Errorf("main has one pseudonym across repositories: %q", a)
		}
	})

	t.Run("a detached HEAD stays literal", func(t *testing.T) {
		if b, err := p.Branch(testRepo, "detached"); err != nil || b != "detached" {
			t.Errorf("Branch(detached) = %q, %v", b, err)
		}
	})

	t.Run("the literal is checked before it is hidden", func(t *testing.T) {
		if _, err := p.Repo("../../etc/passwd"); !errors.Is(err, event.ErrInvalidRepo) {
			t.Errorf("Repo(traversal) = %v, want %v", err, event.ErrInvalidRepo)
		}
		if _, err := p.Branch(testRepo, "a..b"); !errors.Is(err, event.ErrInvalidBranch) {
			t.Errorf("Branch(a..b) = %v, want %v", err, event.ErrInvalidBranch)
		}
		if _, err := p.Branch(testRepo, strings.Repeat("b", 256)); !errors.Is(err, event.ErrInvalidBranch) {
			t.Errorf("Branch(256 bytes) = %v, want %v", err, event.ErrInvalidBranch)
		}
		if _, err := p.Repo(repo); !errors.Is(err, event.ErrInvalidRepo) {
			t.Errorf("Repo(a pseudonym) = %v, want %v: a pseudonym is never re-hidden", err, event.ErrInvalidRepo)
		}
		if _, err := p.Branch("not-a-repo", "main"); !errors.Is(err, event.ErrInvalidRepo) {
			t.Errorf("Branch under a bad repository = %v, want %v", err, event.ErrInvalidRepo)
		}
	})

	t.Run("literal mode returns the literal, checked", func(t *testing.T) {
		l := mustRepositories(t, ModeLiteral, "")
		if r, err := l.Repo(testRepo); err != nil || r != testRepo {
			t.Errorf("literal Repo = %q, %v", r, err)
		}
		if b, err := l.Branch(testRepo, testBranch); err != nil || b != testBranch {
			t.Errorf("literal Branch = %q, %v", b, err)
		}
		if _, err := l.Repo("not-a-repo"); !errors.Is(err, event.ErrInvalidRepo) {
			t.Errorf("literal Repo(bad) = %v", err)
		}
		if l.Mode() != ModeLiteral || p.Mode() != ModePseudonymous {
			t.Error("Mode() does not report the mode")
		}
	})

	t.Run("literal mode may hold a key, because the generator always writes one", func(t *testing.T) {
		l := mustRepositories(t, ModeLiteral, testRepoKey)
		if r, _ := l.Repo(testRepo); r != testRepo {
			t.Errorf("literal mode with a key hid the repository: %q", r)
		}
	})
}

func TestPRI007RepositoryModeRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode Mode
		key  string
	}{
		{"pseudonymous with no key", ModePseudonymous, ""},
		{"pseudonymous with a short key", ModePseudonymous, strings.Repeat("k", MinRepoKeyBytes-1)},
		{"an unknown mode", Mode("hashed"), testRepoKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewRepositories(tc.mode, tc.key); err == nil {
				t.Error("accepted")
			}
		})
	}
	t.Run("the refusal for a missing key names the literal mode", func(t *testing.T) {
		_, err := NewRepositories(ModePseudonymous, "")
		if err == nil || !strings.Contains(err.Error(), string(ModeLiteral)) {
			t.Errorf("err = %v, want it to name %q", err, ModeLiteral)
		}
	})
}
