// SPDX-License-Identifier: Apache-2.0

package event

import (
	"strings"
	"testing"
	"unicode/utf8"

	"pgregory.net/rapid"
)

// SER-021 (RM-314): a harness's agent-type names fold into doc 02 §5's
// identifier grammar instead of being refused by it.
func TestFoldIdentifierTable(t *testing.T) {
	long := strings.Repeat("abcdefghij", 7) // 70 characters
	for _, c := range []struct{ in, want string }{
		{"Plan", "plan"},
		{"Explore", "explore"},
		{"general-purpose", "general-purpose"},
		{"flutter-all:flutter-architect", "flutter-all-flutter-architect"},
		{long, long[:63]},
		{"ÆØÅ日本語", "unnamed"},
		{"", "unnamed"},
		{"---", "unnamed"},
		{"  Code Reviewer  ", "code-reviewer"},
		{"a__--__b", "a-b"},
		{"Ünïcode-Agent", "n-code-agent"},
		// The cut lands on a separator: the trailing hyphen is trimmed again.
		{strings.Repeat("a", 62) + ":bcd", strings.Repeat("a", 62)},
	} {
		got := FoldIdentifier(c.in)
		if got != c.want {
			t.Errorf("FoldIdentifier(%q) = %q, want %q", c.in, got, c.want)
		}
		if err := ValidateIdentifier(got); err != nil {
			t.Errorf("FoldIdentifier(%q) = %q, which the identifier grammar refuses: %v", c.in, got, err)
		}
	}
}

// SER-021 (RM-314): whatever string a harness sends, the fold always passes
// the identifier validator, and folding is idempotent.
func TestFoldIdentifierAlwaysPassesTheValidator(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var in string
		if rapid.Bool().Draw(t, "raw") {
			in = string(rapid.SliceOfN(rapid.Byte(), 0, 200).Draw(t, "bytes"))
		} else {
			in = rapid.StringN(0, 200, -1).Draw(t, "utf8")
		}
		got := FoldIdentifier(in)
		if err := ValidateIdentifier(got); err != nil {
			t.Fatalf("FoldIdentifier(%q) = %q: %v", in, got, err)
		}
		if again := FoldIdentifier(got); again != got {
			t.Fatalf("FoldIdentifier is not idempotent: %q -> %q -> %q", in, got, again)
		}
		if !utf8.ValidString(got) {
			t.Fatalf("FoldIdentifier(%q) = %q is not UTF-8", in, got)
		}
	})
}

// An identifier already in the grammar folds to itself, except where the
// grammar admits what the fold removes (a doubled or trailing hyphen).
func TestFoldIdentifierKeepsAValidIdentifier(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		in := rapid.StringMatching(`[a-z0-9]([a-z0-9]|-[a-z0-9]){0,30}`).Draw(t, "id")
		if got := FoldIdentifier(in); got != in {
			t.Fatalf("FoldIdentifier(%q) = %q, want it unchanged", in, got)
		}
	})
}
