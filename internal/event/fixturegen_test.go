// SPDX-License-Identifier: Apache-2.0

package event

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The v2 golden fixture generator (RM-117, #189).
//
// # Why a generator and not fifteen hand-written files
//
// A fixture set is a claim about one thing: that a verifier re-deriving these
// bytes from this input gets this hash. Hand-writing the canonical bytes and
// the hashes would make the files a transcription of what the serializer
// already does, with transcription errors indistinguishable from serializer
// bugs. The INPUTS are the fixture; the other two files are derived, and
// deriving them is what this does.
//
// # And why it starts from v1 rather than from nothing
//
// The v2 set has to be comparable to the v1 set, member for member, or the
// question "what did schema 2 change?" has no answer in the fixtures. Each v2
// vector is its v1 counterpart plus exactly what ADR-0045 and ADR-0047 add, so
// a diff between the two directories IS the schema change, and anything else
// showing up in that diff is a bug this generator would have introduced.
//
// # It is not a gate
//
// Run it deliberately, with INNSEGL_WRITE_V2_FIXTURES=1. Once written the files
// are immutable exactly as v1's are: a failing fixture test means the
// serializer changed, and the serializer is what must be reverted. Never run
// this to make a test pass.

// v2Additions is the whole of the schema change, per event type: the members
// ADR-0045 and ADR-0047 add, with the values the vectors carry.
//
// One table, so the generator cannot add a member the README does not describe
// and TestV2FixturesAddOnlyWhatTheADRsSpecify cannot miss one.
var v2Additions = map[string]map[string]any{
	EventTypeRunRegistered: {
		// ADR-0045: a run that signs nothing currently records nowhere it
		// worked. The repository is the same grammar `commit_intent` already
		// uses (doc 02 §5), so 01 and 04 carry the same value and a verifier
		// reading both sees one repository rather than two spellings.
		FieldRepo: "github.com/acme/api",
		// Stored verbatim, and the slash is the point: a branch folded into an
		// identifier grammar becomes a DIFFERENT branch that may also exist.
		FieldBranch: "dev/rm115-caller-split",
	},
	EventTypeCommitIntent: {
		// ADR-0047: `git patch-id --verbatim` over the diff. It survives the
		// rebase that destroys the gitsign signature, which is the only reason
		// attribution can outlive a merge button.
		FieldPatchID: "5e4c6c1f0a2d9b3e8f7a1c4d6b0e9f2a3c5d7e81",
	},
	EventTypeCommitRecorded: {
		// The same patch id as the intent it fulfils: one change, recorded
		// twice, and a verifier can join them on it.
		FieldPatchID: "5e4c6c1f0a2d9b3e8f7a1c4d6b0e9f2a3c5d7e81",
	},
}

// v2SubagentFixture is the vector v1 has no counterpart for: a run registered
// BY another run.
//
// `parent_run_id` is the one v2 member that is optional, and an optional member
// no fixture carries is an untested member — the anchor fields on
// `segment_sealed` are the precedent, which is why v1 committed both 11 and 12.
// Its position in the chain is the last, so adding it disturbs no earlier hash.
const v2SubagentFixture = "15-run_registered_subagent"

func TestGenerateV2Fixtures(t *testing.T) {
	if os.Getenv("INNSEGL_WRITE_V2_FIXTURES") == "" {
		t.Skip("a generator, not a gate: set INNSEGL_WRITE_V2_FIXTURES=1 to rewrite " +
			"testdata/fixtures/v2, and read the README there before you do")
	}
	dst := filepath.Join("testdata", "fixtures", "v"+SchemaVersion)
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}

	// 00-doc02-example stays out. It reproduces doc 02 §6's example "member for
	// member and byte for byte", and §6's example is a version 1 event: adding
	// v2's members to it would make it reproduce nothing. doc 02 is normative
	// and is not edited to match this package (project rule), so the vector
	// that pins it lives where it has always lived.
	prev := GenesisPrevEventHash()
	written := 0
	for _, name := range fixtureNamesV1(t) {
		if name == "00-doc02-example" || name == "format-probe" {
			continue
		}
		f := loadFixtureV1(t, name).input.Clone()
		f[FieldSchemaVersion] = SchemaVersion
		f[FieldPrevEventHash] = prev

		eventType, ok := f[FieldEventType].(string)
		if !ok {
			t.Fatalf("%s: the v1 vector has no string event_type", name)
		}
		for member, value := range v2Additions[eventType] {
			f[member] = value
		}

		hash := writeV2Fixture(t, dst, name, f)
		prev = hash
		written++
	}

	// The subagent vector, chained on the end.
	sub := loadFixtureV1(t, "01-run_registered").input.Clone()
	sub[FieldSchemaVersion] = SchemaVersion
	sub[FieldPrevEventHash] = prev
	sub[FieldChainPosition] = int64(written + 1)
	sub[FieldEventID] = "01a047a5-cc41-7c45-86fd-a88c8c2b5399"
	sub[FieldIdempotencyKey] = "reg-8f21c-sub"
	sub[FieldRunID] = "run-43"
	sub[FieldSpiffeID] = "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-43"
	sub[FieldParentRunID] = "run-42"
	for member, value := range v2Additions[EventTypeRunRegistered] {
		sub[member] = value
	}
	prev = writeV2Fixture(t, dst, v2SubagentFixture, sub)

	// The migration attestation, last in the chain and last for a reason: it
	// records the position where events began carrying this version, so it can
	// only be written once that position is known. doc 02 §3 gives it `system`
	// as its source and no run -- the bump is a property of the chain, not of
	// anything an agent did.
	att := Fields{
		FieldSchemaVersion:     SchemaVersion,
		FieldEventType:         EventTypeSchemaMigrated,
		FieldSource:            SourceSystem,
		FieldEventID:           "01a047a5-cc41-7c45-86fd-a88c8c2b5400",
		FieldChainPosition:     int64(written + 2),
		FieldTS:                "2026-09-09T12:00:00.000Z",
		FieldPrevEventHash:     prev,
		FieldFromSchemaVersion: "1",
		FieldToSchemaVersion:   SchemaVersion,
		FieldCutoverPosition:   int64(1),
	}
	writeV2Fixture(t, dst, "16-schema_migrated", att)

	// The serializer's own probe. Its v2 form is already frozen as
	// formatFingerprintV2; committing it here gives SER-005 the same
	// byte-level vector v1 has, rather than only a constant to compare
	// a constant against.
	writeProbeFixture(t, dst)
	t.Logf("wrote %d event vectors plus the subagent vector and the format probe to %s",
		written, dst)
}

// writeV2Fixture writes one vector's three files and returns its event_hash.
//
// The three conventions are v1's, and they are load-bearing rather than
// cosmetic (see the v1 README):
//
//   - the input carries NO event_hash, because the input IS the preimage;
//   - its members are in REVERSE-sorted order, so every fixture doubles as an
//     ordering-independence vector (SER-002);
//   - the canonical bytes and the hash carry no trailing newline, because the
//     file is the preimage and a newline would be part of it.
func writeV2Fixture(t *testing.T, dir, name string, f Fields) string {
	t.Helper()

	delete(f, EventHashField)
	// Preimage, not Canonicalize: doc 02 §4.2 excludes event_hash from its own
	// preimage, and the committed canonical file IS the preimage.
	canonical, err := f.Preimage()
	if err != nil {
		t.Fatalf("%s: preimage: %v", name, err)
	}
	hash, err := f.EventHash()
	if err != nil {
		t.Fatalf("%s: hash: %v", name, err)
	}

	write(t, filepath.Join(dir, name+".input.json"), []byte(prettyReversed(t, name, f)))
	write(t, filepath.Join(dir, name+".canonical.json"), canonical)
	write(t, filepath.Join(dir, name+".hash"), []byte(hash))
	return hash
}

// writeProbeFixture commits the serializer probe under the current version.
func writeProbeFixture(t *testing.T, dir string) {
	t.Helper()

	probe := formatProbe()
	canonical, err := Canonicalize(probe)
	if err != nil {
		t.Fatalf("canonicalize the probe: %v", err)
	}
	fingerprint, err := FormatFingerprint()
	if err != nil {
		t.Fatalf("FormatFingerprint: %v", err)
	}
	// All three files, as v1 has them: the input is what an oracle outside Go
	// re-derives the other two from, and a probe committed without one could
	// only ever be checked by the code that wrote it.
	write(t, filepath.Join(dir, "format-probe.input.json"), []byte(prettyReversed(t, "format-probe", probe)))
	write(t, filepath.Join(dir, "format-probe.canonical.json"), canonical)
	write(t, filepath.Join(dir, "format-probe.hash"), []byte(fingerprint))
}

// prettyReversed renders a fixture input in v1's shape: pretty-printed with
// its members in REVERSE-sorted order. Nothing reads that ordering; it is
// scrambled on purpose so every fixture doubles as an ordering-independence
// vector (SER-002), and reverse order is the cheapest scramble that is also
// deterministic.
func prettyReversed(t *testing.T, name string, f Fields) string {
	t.Helper()

	names := make([]string, 0, len(f))
	for member := range f {
		names = append(names, member)
	}
	slices.Sort(names)
	slices.Reverse(names)

	var b strings.Builder
	b.WriteString("{\n")
	for i, member := range names {
		value, err := json.Marshal(f[member])
		if err != nil {
			t.Fatalf("%s: marshal %q: %v", name, member, err)
		}
		key, kerr := json.Marshal(member)
		if kerr != nil {
			t.Fatalf("%s: marshal the member name %q: %v", name, member, kerr)
		}
		fmt.Fprintf(&b, "  %s: %s", key, value)
		if i < len(names)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
