// SPDX-License-Identifier: Apache-2.0

package event

import (
	"os"
	"path/filepath"
	"testing"
)

// The v3 golden fixture generator (ADR-0051, #298).
//
// Schema 3 changes nothing an existing event carries. So the v3 set is the v2
// set re-versioned and re-chained, member for member, and then three vectors
// chained on the end: the new type, the one intent that carries an adoption,
// and the attestation of the 2 -> 3 cutover. "What did schema 3 change?" is
// answered by those three and nothing else, which TestADP006 holds it to.

const (
	v3AdoptedFixture      = "17-run_adopted"
	v3AdoptedIntent       = "18-commit_intent_adopted"
	v3MigrationFixture    = "19-schema_migrated"
	v3AdoptedEventID      = "01a047b1-0d3e-7a21-9c4f-5b8e2d7f6a10"
	v3ClaimDigestInVector = "sha256:9b3c1f6e2a7d4b8c0e5f1a3d6c9b2e7f4a8d1c5e0b3f6a9d2c7e4b1f8a5d3c60"
)

func TestGenerateV3Fixtures(t *testing.T) {
	if os.Getenv("INNSEGL_WRITE_V3_FIXTURES") == "" {
		t.Skip("a generator, not a gate: set INNSEGL_WRITE_V3_FIXTURES=1 to rewrite " +
			"testdata/fixtures/v3, and read the README there before you do")
	}
	src := filepath.Join("testdata", "fixtures", "v2")
	dst := filepath.Join("testdata", "fixtures", "v3")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}

	prev := GenesisPrevEventHash()
	var position int64
	for _, name := range fixtureNamesIn(t, src) {
		// The probe is rewritten below under this version; the v2 attestation
		// records the 1 -> 2 cutover, which is not this set's.
		if name == "format-probe" || name == "16-schema_migrated" {
			continue
		}
		f := loadFixtureFrom(t, src, name).input.Clone()
		f[FieldSchemaVersion] = SchemaVersion
		f[FieldPrevEventHash] = prev
		prev = writeV2Fixture(t, dst, name, f)
		if p := fixtureInt(t, f, FieldChainPosition); p > position {
			position = p
		}
	}

	// The adoption: run-42 takes over what run-41 left. run-42 signs it, so it
	// is the event's run; run-41 is what the event is about.
	adopted := loadFixtureFrom(t, src, "07-run_retired").input.Clone()
	adopted[FieldSchemaVersion] = SchemaVersion
	adopted[FieldEventType] = EventTypeRunAdopted
	adopted[FieldEventID] = v3AdoptedEventID
	adopted[FieldChainPosition] = position + 1
	adopted[FieldPrevEventHash] = prev
	adopted[FieldAdoptedRunID] = "run-41"
	adopted[FieldAdoptedRunState] = "retired"
	adopted[FieldPayloadDigest] = v3ClaimDigestInVector
	prev = writeV2Fixture(t, dst, v3AdoptedFixture, adopted)

	intent := loadFixtureFrom(t, src, "04-commit_intent").input.Clone()
	intent[FieldSchemaVersion] = SchemaVersion
	intent[FieldEventID] = "01a047b1-0d3e-7a21-9c4f-5b8e2d7f6a11"
	intent[FieldIdempotencyKey] = "sign-2c5e1-adopted"
	intent[FieldChainPosition] = position + 2
	intent[FieldPrevEventHash] = prev
	intent[FieldAdoptionEventID] = v3AdoptedEventID
	prev = writeV2Fixture(t, dst, v3AdoptedIntent, intent)

	att := loadFixtureFrom(t, src, "16-schema_migrated").input.Clone()
	att[FieldSchemaVersion] = SchemaVersion
	att[FieldEventID] = "01a047b1-0d3e-7a21-9c4f-5b8e2d7f6a12"
	att[FieldChainPosition] = position + 3
	att[FieldPrevEventHash] = prev
	att[FieldFromSchemaVersion] = "2"
	att[FieldToSchemaVersion] = SchemaVersion
	writeV2Fixture(t, dst, v3MigrationFixture, att)

	writeProbeFixture(t, dst)
}
