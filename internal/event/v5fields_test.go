// SPDX-License-Identifier: Apache-2.0

package event

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// ADR-0080 -- schema 5, #483 (RM-304).
//
// Schema 5 adds no member and no event type. It changes the values two
// existing members may take: from schema "5", `repo` and `branch` are either
// doc 02 §5's literal form or a keyed pseudonym `pn:<key-id>:<32 hex>`. At
// schema "1" to "4" only the literal form is valid.

// v5Pseudonym is a well-formed pseudonym. The hex is arbitrary: the event
// package checks the grammar and never holds a key.
func v5Pseudonym(hexChar string) string {
	return "pn:rk-0a1b2c3d:" + strings.Repeat(hexChar, 32)
}

// TestSER028PseudonymFormIsValidOnlyFromSchema5 is the version rule of doc 02
// §5's schema-5 errata and §7's second paragraph: a value is validated by the
// rule of its own event's schema_version.
func TestSER028PseudonymFormIsValidOnlyFromSchema5(t *testing.T) {
	t.Run("schema 5 accepts the pseudonymous form on all three members", func(t *testing.T) {
		reg := fixtureFor(t, EventTypeRunRegistered)
		reg[FieldRepo] = v5Pseudonym("a")
		reg[FieldBranch] = v5Pseudonym("b")
		if err := ValidateEvent(reg); err != nil {
			t.Errorf("run_registered with pseudonymous repo and branch: %v", err)
		}
		for _, et := range []string{EventTypeCommitIntent, EventTypeCommitRecorded} {
			f := fixtureFor(t, et)
			f[FieldRepo] = v5Pseudonym("c")
			if err := ValidateEvent(f); err != nil {
				t.Errorf("%s with a pseudonymous repo: %v", et, err)
			}
		}
	})

	t.Run("schema 5 still accepts the literal form", func(t *testing.T) {
		reg := fixtureFor(t, EventTypeRunRegistered)
		if !strings.Contains(fixtureString(t, reg, FieldRepo), "/") {
			t.Fatalf("the re-versioned run_registered vector should be literal, has %q", reg[FieldRepo])
		}
		if err := ValidateEvent(reg); err != nil {
			t.Errorf("literal run_registered at schema 5: %v", err)
		}
	})

	t.Run("a detached HEAD stays literal beside a pseudonymous repo", func(t *testing.T) {
		reg := fixtureFor(t, EventTypeRunRegistered)
		reg[FieldRepo] = v5Pseudonym("a")
		reg[FieldBranch] = "detached"
		if err := ValidateEvent(reg); err != nil {
			t.Errorf("detached branch: %v", err)
		}
	})

	for _, version := range []string{"2", "3", "4"} {
		dir := filepath.Join("testdata", "fixtures", "v"+version)
		t.Run("schema "+version+" refuses a pseudonymous repo", func(t *testing.T) {
			f := loadFixtureFrom(t, dir, "01-run_registered").input.Clone()
			f[FieldRepo] = v5Pseudonym("a")
			if err := ValidateEventForVerification(f); !errors.Is(err, ErrInvalidRepo) {
				t.Errorf("err = %v, want %v", err, ErrInvalidRepo)
			}
		})
		t.Run("schema "+version+" refuses a pseudonymous branch", func(t *testing.T) {
			f := loadFixtureFrom(t, dir, "01-run_registered").input.Clone()
			f[FieldBranch] = v5Pseudonym("b")
			if err := ValidateEventForVerification(f); !errors.Is(err, ErrInvalidBranch) {
				t.Errorf("err = %v, want %v", err, ErrInvalidBranch)
			}
		})
		t.Run("schema "+version+" still verifies its own literal vector", func(t *testing.T) {
			f := loadFixtureFrom(t, dir, "01-run_registered").input.Clone()
			if err := ValidateEventForVerification(f); err != nil {
				t.Errorf("err = %v, want nil", err)
			}
		})
	}

	for _, tc := range []struct{ name, value string }{
		{"uppercase hex", "pn:rk-0a1b2c3d:" + strings.Repeat("A", 32)},
		{"31 hex digits", "pn:rk-0a1b2c3d:" + strings.Repeat("a", 31)},
		{"33 hex digits", "pn:rk-0a1b2c3d:" + strings.Repeat("a", 33)},
		{"an empty key id", "pn::" + strings.Repeat("a", 32)},
		{"a key id with an uppercase character", "pn:Rk-0a1b2c3d:" + strings.Repeat("a", 32)},
		{"a key id beginning with a hyphen", "pn:-rk:" + strings.Repeat("a", 32)},
		{"a key id of 64 characters", "pn:" + strings.Repeat("k", 64) + ":" + strings.Repeat("a", 32)},
		{"no key id separator", "pn:" + strings.Repeat("a", 32)},
		{"a sha256 tag in its place", "pn:sha256:" + strings.Repeat("a", 64)},
		{"a trailing member", v5Pseudonym("a") + ":x"},
	} {
		t.Run("malformed: "+tc.name, func(t *testing.T) {
			if err := ValidatePseudonym(tc.value); !errors.Is(err, ErrInvalidPseudonym) {
				t.Errorf("ValidatePseudonym(%q) = %v, want %v", tc.value, err, ErrInvalidPseudonym)
			}
			reg := fixtureFor(t, EventTypeRunRegistered)
			reg[FieldRepo] = tc.value
			if err := ValidateEvent(reg); !errors.Is(err, ErrInvalidPseudonym) {
				t.Errorf("repo %q: err = %v, want %v", tc.value, err, ErrInvalidPseudonym)
			}
			reg = fixtureFor(t, EventTypeRunRegistered)
			reg[FieldBranch] = tc.value
			if err := ValidateEvent(reg); !errors.Is(err, ErrInvalidPseudonym) {
				t.Errorf("branch %q: err = %v, want %v", tc.value, err, ErrInvalidPseudonym)
			}
		})
	}

	t.Run("a 63-character key id is the longest allowed", func(t *testing.T) {
		v := "pn:k" + strings.Repeat("0", 62) + ":" + strings.Repeat("a", 32)
		if err := ValidatePseudonym(v); err != nil {
			t.Errorf("ValidatePseudonym: %v", err)
		}
	})

	t.Run("the literal validators never take a pseudonym", func(t *testing.T) {
		// ValidateRepo and ValidateBranch check what a CLIENT sends, which is
		// always the literal: a pseudonym arriving as input is refused, never
		// passed through as though it named a repository.
		if err := ValidateRepo(v5Pseudonym("a")); !errors.Is(err, ErrInvalidRepo) {
			t.Errorf("ValidateRepo(pn:…) = %v, want %v", err, ErrInvalidRepo)
		}
		if err := ValidateBranch(v5Pseudonym("a")); !errors.Is(err, ErrInvalidBranch) {
			t.Errorf("ValidateBranch(pn:…) = %v, want %v", err, ErrInvalidBranch)
		}
	})

	t.Run("IsPseudonym reads the form, not the grammar", func(t *testing.T) {
		if !IsPseudonym(v5Pseudonym("a")) || IsPseudonym("github.com/acme/api") || IsPseudonym("detached") {
			t.Error("IsPseudonym misclassifies")
		}
	})
}

// v5FixtureRepoKey is the key the committed v5 vectors' pseudonyms were made
// under. It is a test vector, published on purpose: fixtures pin bytes, not
// a secret (doc02-v5 amendment, golden fixtures).
const v5FixtureRepoKey = "innsegl-v5-fixture-repository-key-not-a-secret-0001"

// TestSER027V5FixturesRederiveTheirPseudonyms recomputes every pn: value in
// the v5 set from the fixture key with HMAC-SHA256 written out here, not
// through any production code, and holds the set to the vectors the
// amendment lists.
func TestSER027V5FixturesRederiveTheirPseudonyms(t *testing.T) {
	dir := filepath.Join("testdata", "fixtures", "v5")
	pn := func(keyID, msg string) string {
		mac := hmac.New(sha256.New, []byte(v5FixtureRepoKey))
		mac.Write([]byte(msg))
		return "pn:" + keyID + ":" + hex.EncodeToString(mac.Sum(nil))[:32]
	}

	reg := loadFixtureFrom(t, dir, v5PseudonymousRunFixture).input
	if got, want := fixtureString(t, reg, FieldRepo), pn(v5KeyID, "repo:"+v5LiteralRepo); got != want {
		t.Errorf("run_registered repo = %q, want %q", got, want)
	}
	if got, want := fixtureString(t, reg, FieldBranch), pn(v5KeyID, "branch:"+v5LiteralRepo+"\n"+v5LiteralBranch); got != want {
		t.Errorf("run_registered branch = %q, want %q", got, want)
	}

	intent := loadFixtureFrom(t, dir, v5PseudonymousIntentFixture).input
	if got, want := fixtureString(t, intent, FieldRepo), pn(v5KeyID, "repo:"+v5LiteralRepo); got != want {
		t.Errorf("commit_intent repo = %q, want %q", got, want)
	}

	rec := loadFixtureFrom(t, dir, v5PseudonymousRecordedFixture).input
	if got, want := fixtureString(t, rec, FieldRepo), pn(v5LongKeyID, "repo:"+v5LiteralRepo); got != want {
		t.Errorf("commit_recorded repo (63-character key id) = %q, want %q", got, want)
	}

	det := loadFixtureFrom(t, dir, v5DetachedFixture).input
	if got := fixtureString(t, det, FieldBranch); got != "detached" {
		t.Errorf("detached vector branch = %q, want detached", got)
	}
	if got, want := fixtureString(t, det, FieldRepo), pn(v5KeyID, "repo:"+v5LiteralRepo); got != want {
		t.Errorf("detached vector repo = %q, want %q", got, want)
	}

	att := loadFixtureFrom(t, dir, v5MigrationFixture).input
	if fixtureString(t, att, FieldFromSchemaVersion) != "4" || fixtureString(t, att, FieldToSchemaVersion) != "5" {
		t.Errorf("the v5 attestation records %v -> %v, want 4 -> 5",
			att[FieldFromSchemaVersion], att[FieldToSchemaVersion])
	}

	// No literal repository or branch name of the pseudonymous vectors leaks
	// into their canonical bytes.
	for _, name := range []string{v5PseudonymousRunFixture, v5PseudonymousIntentFixture,
		v5PseudonymousRecordedFixture, v5DetachedFixture} {
		c := string(loadFixtureFrom(t, dir, name).canonical)
		if strings.Contains(c, v5LiteralRepo) || strings.Contains(c, "acme") {
			t.Errorf("%s carries the literal repository", name)
		}
		if strings.Contains(c, v5LiteralBranch) {
			t.Errorf("%s carries the literal branch", name)
		}
	}
}
