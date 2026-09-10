// SPDX-License-Identifier: Apache-2.0

package event

import (
	"slices"
	"strings"
	"testing"
)

// SER-020 through SER-022 (proposed for doc 07; doc 07 is not modified here).
//
// The three grammars schema 2 adds, and the reasons each is its own.
//
// ADR-0045 puts `repo`, `branch` and `parent_run_id` on `run_registered`,
// because a run that signs nothing currently records nowhere it worked — 26
// subagent runs, 1979 tool calls, and not one of them says which repository.
// ADR-0047 puts `patch_id` on `commit_intent` and `commit_recorded`, because a
// gitsign signature does not survive a rebase and the content identity does.
//
// `repo` already exists with a grammar (doc 02 §5) and is reused, not
// redefined. These three are new.
func TestSER020ABranchIsStoredVerbatim(t *testing.T) {
	// A BRANCH IS NOT AN IDENTIFIER, and this is the whole point of the field.
	//
	// The harness hook used to fold the branch into `task_ref` through the
	// SPIFFE grammar, which is [a-z0-9][a-z0-9-]{0,62}. That turns
	// `dev/rm105-caller-split` into `dev-rm105-caller-split` — a different
	// branch, and one that may also exist. The value is stored as git holds it
	// or it is not the branch.
	for _, ok := range []string{
		"main",
		"dev/rm105-caller-split",
		"release/2026.09",
		"feature/UPPER-and-dots.v2",
		"detached",
		strings.Repeat("a", 255),
	} {
		if err := ValidateBranch(ok); err != nil {
			t.Errorf("ValidateBranch(%q) = %v, want nil", ok, err)
		}
	}

	for _, bad := range []struct{ in, why string }{
		{"", "empty"},
		{strings.Repeat("a", 256), "longer than"},
		{"has space", "space"},
		{"trailing/", "cannot end"},
		{"/leading", "cannot begin"},
		{"double//slash", "empty segment"},
		{"dot.lock/end.lock", ".lock"},
		{"back\\slash", "backslash"},
		{"tilde~1", "~"},
		{"caret^", "^"},
		{"colon:x", ":"},
		{"question?", "?"},
		{"star*", "*"},
		{"bracket[0]", "["},
		{"at{}brace", "{"},
		{"..", "cannot begin"},
		{"a/../b", ".."},
	} {
		err := ValidateBranch(bad.in)
		if err == nil {
			t.Errorf("ValidateBranch(%q) was accepted; git would refuse it", bad.in)
			continue
		}
		if !strings.Contains(err.Error(), bad.why) {
			t.Errorf("ValidateBranch(%q) said %q, which does not say %q", bad.in, err, bad.why)
		}
	}
}

// TestSER021APatchIDIsAFullObjectID. `git patch-id --verbatim` writes a 40-hex
// SHA-1 over the diff. Abbreviation is refused for the same reason
// ValidateGitObjectID refuses it: a prefix names whatever happens to be unique
// in one repository at one moment.
func TestSER021APatchIDIsAFullObjectID(t *testing.T) {
	const good = "05d508d997e3c1f2a4b6d8e0f2a4b6d8e0f2a4b6"
	if err := ValidatePatchID(good); err != nil {
		t.Errorf("ValidatePatchID(%q) = %v, want nil", good, err)
	}
	for _, bad := range []string{
		"",
		"05d508d9", // abbreviated
		"05D508D997E3C1F2A4B6D8E0F2A4B6D8E0F2A4B6", // uppercase
		"05d508d997e3c1f2a4b6d8e0f2a4b6d8e0f2a4b",  // 39
		"zzd508d997e3c1f2a4b6d8e0f2a4b6d8e0f2a4b6", // not hex
	} {
		if err := ValidatePatchID(bad); err == nil {
			t.Errorf("ValidatePatchID(%q) was accepted", bad)
		}
	}
}

// TestSER022AParentRunIDIsARunID. A subagent's parent is a run, so it is held
// to the run grammar rather than to a second one that could drift from it.
func TestSER022AParentRunIDIsARunID(t *testing.T) {
	if err := ValidateParentRunID("run-1ca2195901b6fe3acf2b0caa9ce90a67"); err != nil {
		t.Errorf("a run id was refused as a parent: %v", err)
	}
	for _, bad := range []string{"", "Run-Upper", "run id", strings.Repeat("r", 64)} {
		if err := ValidateParentRunID(bad); err == nil {
			t.Errorf("ValidateParentRunID(%q) was accepted; it must match the run grammar", bad)
		}
	}
}

// TestSER023TheV2MembersExistOnlyInV2 (proposed for doc 07).
//
// A member schema 2 introduced is not "optional under 1" — under 1 it is NOT A
// MEMBER. The schema is closed (doc 02 §1), so a v1 event carrying one is
// refused, and a v1 event lacking one is complete.
//
// That is what lets one table validate both versions without either judging
// the other by its own rules, which doc 08 requires without exception:
// "verification of old records is supported forever".
func TestSER023TheV2MembersExistOnlyInV2(t *testing.T) {
	for _, tc := range []struct {
		eventType string
		member    string
		required  bool
	}{
		{EventTypeRunRegistered, FieldRepo, true},
		{EventTypeRunRegistered, FieldBranch, true},
		{EventTypeRunRegistered, FieldParentRunID, false},
		{EventTypeCommitIntent, FieldPatchID, true},
		{EventTypeCommitRecorded, FieldPatchID, true},
	} {
		t.Run(tc.eventType+"/"+tc.member, func(t *testing.T) {
			spec, err := lookupType(tc.eventType)
			if err != nil {
				t.Fatalf("lookupType: %v", err)
			}

			if _, ok := allowedFor(spec, "1")[tc.member]; ok && tc.member != FieldRepo {
				t.Errorf("%s is a member of %s under schema 1; it was introduced by "+
					"schema 2 and a v1 event carrying it must be refused",
					tc.member, tc.eventType)
			}
			if _, ok := allowedFor(spec, "2")[tc.member]; !ok {
				t.Errorf("%s is not a member of %s under schema 2", tc.member, tc.eventType)
			}

			inV1 := slices.Contains(requiredFor(spec, "1"), tc.member)
			inV2 := slices.Contains(requiredFor(spec, "2"), tc.member)
			if inV1 && tc.member != FieldRepo {
				t.Errorf("%s is required on %s under schema 1, which would make every "+
					"existing event invalid", tc.member, tc.eventType)
			}
			if inV2 != tc.required {
				t.Errorf("%s required on %s under schema 2 = %v, want %v",
					tc.member, tc.eventType, inV2, tc.required)
			}
		})
	}
}
