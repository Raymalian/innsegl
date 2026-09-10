// SPDX-License-Identifier: Apache-2.0

package event

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"testing"
)

// SER-024 through SER-026 (proposed for doc 07; doc 07 is not modified here) —
// RM-116, #188.
//
// doc 08 is unconditional: a new schema version is accepted ALONGSIDE all
// previous ones, and verification of old records is supported forever, without
// exception. The ledger holds every version-1 event ever appended and I4
// forbids rewriting them, so this is not a courtesy to old deployments — it is
// the difference between a chain that can still be verified and one that
// cannot.
//
// The tests above this one check the version the build EMITS. These check every
// version it must still READ, which is a different claim and needs its own
// gate: nothing in a suite that only exercises the current version would go red
// if support for the previous one were deleted tomorrow.

// releasedSchemaVersions is every version ever released, oldest first.
//
// Entries are never removed. A version dropped from this slice is a version
// whose records this build no longer promises to read, and doc 08 has no
// process for that because there is no such thing.
var releasedSchemaVersions = []string{"1", "2"}

// TestSER024EveryReleasedVersionHasAFixtureSetThatStillVerifies is the gate.
//
// For each released version: the committed vectors re-derive to their committed
// canonical bytes and hashes, and each one is still accepted by the verifier.
// The last part is what a byte comparison alone would miss — a record can
// serialize exactly as it always did and still be refused by a validator that
// has learnt to require a member the record predates.
func TestSER024EveryReleasedVersionHasAFixtureSetThatStillVerifies(t *testing.T) {
	if !slices.Contains(releasedSchemaVersions, SchemaVersion) {
		t.Fatalf("this build emits schema %q, which is not in releasedSchemaVersions %q; "+
			"a version nothing lists is a version nothing gates",
			SchemaVersion, releasedSchemaVersions)
	}

	for _, version := range releasedSchemaVersions {
		dir := "testdata/fixtures/v" + version
		names := fixtureNamesIn(t, dir)
		if len(names) == 0 {
			t.Errorf("schema %s has no committed vectors", version)
			continue
		}

		for _, name := range names {
			if name == "format-probe" {
				continue // the serializer's vector, not an event
			}
			t.Run("v"+version+"/"+name, func(t *testing.T) {
				f := loadFixtureFrom(t, dir, name)

				// The two committed files agree with each other, checked with
				// crypto/sha256 rather than this package's helper: a fixture
				// verified by the code it exists to pin proves only that the
				// code agrees with itself.
				sum := sha256.Sum256(f.canonical)
				if want := HashPrefix + hex.EncodeToString(sum[:]); want != f.hash {
					t.Errorf("the committed vector is internally inconsistent:\n"+
						" .hash             = %s\n sha256(canonical) = %s", f.hash, want)
				}

				// And this build still re-derives them.
				pre, err := f.input.Preimage()
				if err != nil {
					t.Fatalf("Preimage: %v", err)
				}
				if !bytes.Equal(pre, f.canonical) {
					t.Errorf("schema %s no longer serializes to its committed bytes\n"+
						" got  %s\n want %s\nThe serializer changed. Revert it; do not "+
						"regenerate the fixture.", version, pre, f.canonical)
				}

				// And still accepts them. ValidateEventForVerification, not
				// ValidateEvent: the append path emits one version and refuses
				// every other by design, which is doc 08's other half.
				if verr := ValidateEventForVerification(f.input); verr != nil {
					t.Errorf("a schema %s record is no longer verifiable: %v\n"+
						"Every event of this version already in the chain has just "+
						"become unreadable, and I4 forbids rewriting them.", version, verr)
				}

				if got := f.input[FieldSchemaVersion]; got != version {
					t.Errorf("the vector in %s declares schema_version %v", dir, got)
				}
			})
		}
	}
}

// TestSER025AnOlderRecordIsJudgedByItsOwnVersion is the rule that makes the
// above possible rather than lucky.
//
// A v1 `run_registered` carries neither `repo` nor `branch`, and under v2 both
// are required. If the verifier judged every record by the build's own table,
// every v1 record in the chain would fail the moment v2 shipped — the failure
// mode doc 08 exists to prevent, and one that would be discovered in
// production rather than here.
func TestSER025AnOlderRecordIsJudgedByItsOwnVersion(t *testing.T) {
	v1 := loadFixtureV1(t, "01-run_registered").input
	for _, member := range []string{FieldRepo, FieldBranch} {
		if _, present := v1[member]; present {
			t.Fatalf("the v1 vector already carries %q, so it cannot show that a "+
				"record without it still verifies", member)
		}
	}
	if err := ValidateEventForVerification(v1); err != nil {
		t.Errorf("a v1 run_registered without %s or %s was refused: %v",
			FieldRepo, FieldBranch, err)
	}

	// The same record relabelled as v2 IS refused, which is what proves the
	// acceptance above comes from the version and not from the requirement
	// having been quietly dropped.
	relabelled := v1.Clone()
	relabelled[FieldSchemaVersion] = "2"
	if err := ValidateEventForVerification(relabelled); err == nil {
		t.Error("a v2 run_registered with neither repo nor branch was accepted; " +
			"the v2 requirement is not enforced, and the v1 acceptance above " +
			"proves nothing")
	}

	// And the reverse: a v1 record carrying a v2 member is refused, because
	// under v1 it is not a member at all and the schema is closed (doc 02 §1).
	backdated := loadFixture(t, "01-run_registered").input.Clone()
	backdated[FieldSchemaVersion] = "1"
	if err := ValidateEventForVerification(backdated); err == nil {
		t.Error("a v1 event carrying repo and branch was accepted; the schema is " +
			"closed, and a member from the future is not a member")
	}
}

// TestSER026TheCurrentVersionIsTheOnlyOneAppended. Reading many, writing one:
// a build that accepted an older version at append would let two writers
// disagree about what a record contains, and the chain would carry both
// answers forever.
func TestSER026TheCurrentVersionIsTheOnlyOneAppended(t *testing.T) {
	current, err := strconv.Atoi(SchemaVersion)
	if err != nil {
		t.Fatalf("SchemaVersion %q is not a major version number", SchemaVersion)
	}
	if current != currentSchemaVersion {
		t.Fatalf("SchemaVersion is %q but currentSchemaVersion is %d; the verifier "+
			"and the emitter disagree about what version this build is",
			SchemaVersion, currentSchemaVersion)
	}

	for _, version := range releasedSchemaVersions {
		if version == SchemaVersion {
			continue
		}
		f := loadFixtureFrom(t, "testdata/fixtures/v"+version, "01-run_registered").input
		if err := ValidateEvent(f); err == nil {
			t.Errorf("ValidateEvent accepted a schema %s record at append; this build "+
				"emits %s", version, SchemaVersion)
		}
	}
}
