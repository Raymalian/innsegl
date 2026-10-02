// SPDX-License-Identifier: Apache-2.0

package event

import "strings"

// unnamedIdentifier is FoldIdentifier's answer for a string with no
// character the grammar keeps.
const unnamedIdentifier = "unnamed"

// maxIdentifierBytes is doc 02 §5's bound: [a-z0-9][a-z0-9-]{0,62}.
const maxIdentifierBytes = 63

// FoldIdentifier turns any string into one doc 02 §5's identifier grammar
// accepts (RM-314). A harness names its agent types as it likes -- "Plan",
// "flutter-all:flutter-architect" -- and the grammar is protected, so the
// name is folded rather than the grammar loosened or the agent refused.
//
// ASCII letters are lowercased; every run of bytes outside [a-z0-9] becomes
// one hyphen; leading and trailing hyphens go; the result is cut to 63 bytes
// and a hyphen the cut leaves at the end goes too. A string with nothing left
// is "unnamed". It works byte by byte, so every byte of a non-ASCII character
// is a separator. The answer always passes ValidateIdentifier.
//
// The fold loses information ("Plan" and "plan" are one type). A caller that
// needs the original keeps it beside the chain, never in it.
func FoldIdentifier(raw string) string {
	var b strings.Builder
	b.Grow(min(len(raw), maxIdentifierBytes+1))
	pending := false
	for i := 0; i < len(raw) && b.Len() < maxIdentifierBytes; i++ {
		c := raw[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			if pending && b.Len() > 0 {
				b.WriteByte('-')
			}
			pending = false
			if b.Len() < maxIdentifierBytes {
				b.WriteByte(c)
			}
			continue
		}
		pending = true
	}
	folded := strings.TrimRight(b.String(), "-")
	if folded == "" {
		return unnamedIdentifier
	}
	return folded
}
