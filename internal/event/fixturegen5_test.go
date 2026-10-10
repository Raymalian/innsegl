// SPDX-License-Identifier: Apache-2.0

package event

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The v5 golden fixture generator (ADR-0080, #483).
//
// Schema 5 adds no member and no event type: it widens the values `repo` and
// `branch` may take. So the v5 set is the v4 set -- minus v4's OWN 3 -> 4
// attestation, for the reason v3 and v4 excluded theirs -- re-versioned and
// re-chained, member for member (its repositories stay literal, which is the
// literal-mode vector at schema 5), plus five vectors chained on the end: a
// pseudonymous run_registered, commit_intent and commit_recorded, a detached
// HEAD beside a pseudonymous repository, and the 4 -> 5 attestation.

const (
	v5PseudonymousRunFixture      = "24-run_registered_pseudonymous"
	v5PseudonymousIntentFixture   = "25-commit_intent_pseudonymous"
	v5PseudonymousRecordedFixture = "26-commit_recorded_pseudonymous"
	v5DetachedFixture             = "27-run_registered_detached"
	v5MigrationFixture            = "28-schema_migrated"

	// v5KeyID and v5LongKeyID name the fixture key under two ids, the second
	// the longest the identifier grammar allows. Neither is derived from a
	// real key.
	v5KeyID     = "rk-fixture1"
	v5LongKeyID = "k00000000000000000000000000000000000000000000000000000000000000"

	v5LiteralRepo   = "github.com/acme/payments"
	v5LiteralBranch = "feature/quiet-acquisition"
)

func v5FixturePseudonym(keyID, msg string) string {
	mac := hmac.New(sha256.New, []byte(v5FixtureRepoKey))
	mac.Write([]byte(msg))
	return "pn:" + keyID + ":" + hex.EncodeToString(mac.Sum(nil))[:32]
}

func TestGenerateV5Fixtures(t *testing.T) {
	if os.Getenv("INNSEGL_WRITE_V5_FIXTURES") == "" {
		t.Skip("a generator, not a gate: set INNSEGL_WRITE_V5_FIXTURES=1 to rewrite " +
			"testdata/fixtures/v5, and read the README there before you do")
	}
	if len(v5LongKeyID) != 63 || strings.Trim(v5LongKeyID[1:], "0") != "" {
		t.Fatalf("v5LongKeyID must be k followed by 62 zeros, is %d long", len(v5LongKeyID))
	}
	src := filepath.Join("testdata", "fixtures", "v4")
	dst := filepath.Join("testdata", "fixtures", "v5")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}

	prev := GenesisPrevEventHash()
	var position int64
	for _, name := range fixtureNamesIn(t, src) {
		if name == "format-probe" || name == v4MigrationFixture {
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

	repoPN := v5FixturePseudonym(v5KeyID, "repo:"+v5LiteralRepo)
	branchPN := v5FixturePseudonym(v5KeyID, "branch:"+v5LiteralRepo+"\n"+v5LiteralBranch)

	reg := loadFixtureFrom(t, src, "01-run_registered").input.Clone()
	reg[FieldSchemaVersion] = SchemaVersion
	reg[FieldEventID] = "01a047b3-0a1e-7c41-9d2b-5e6f7a8b9c01"
	reg[FieldIdempotencyKey] = "reg-8f21c-pn"
	reg[FieldChainPosition] = position + 1
	reg[FieldPrevEventHash] = prev
	reg[FieldRunID] = "run-45"
	reg[FieldSpiffeID] = "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-45"
	reg[FieldRepo] = repoPN
	reg[FieldBranch] = branchPN
	prev = writeV2Fixture(t, dst, v5PseudonymousRunFixture, reg)

	intent := loadFixtureFrom(t, src, "04-commit_intent").input.Clone()
	intent[FieldSchemaVersion] = SchemaVersion
	intent[FieldEventID] = "01a047b3-0a1e-7c41-9d2b-5e6f7a8b9c02"
	intent[FieldIdempotencyKey] = "sign-2c5e1-pn"
	intent[FieldChainPosition] = position + 2
	intent[FieldPrevEventHash] = prev
	intent[FieldRunID] = "run-45"
	intent[FieldSpiffeID] = "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-45"
	intent[FieldRepo] = repoPN
	prev = writeV2Fixture(t, dst, v5PseudonymousIntentFixture, intent)

	// The same repository under a rotated key, whose id is the longest the
	// grammar allows: a second pseudonym for one repository, resolved by the
	// alias table and never by recomputation (ADR-0080 decision 2).
	rec := loadFixtureFrom(t, src, "05-commit_recorded").input.Clone()
	rec[FieldSchemaVersion] = SchemaVersion
	rec[FieldEventID] = "01a047b3-0a1e-7c41-9d2b-5e6f7a8b9c03"
	rec[FieldIdempotencyKey] = "sign-2c5e1-pn-c"
	rec[FieldChainPosition] = position + 3
	rec[FieldPrevEventHash] = prev
	rec[FieldRunID] = "run-45"
	rec[FieldSpiffeID] = "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-45"
	rec[FieldIntentEventID] = intent[FieldEventID]
	rec[FieldRepo] = v5FixturePseudonym(v5LongKeyID, "repo:"+v5LiteralRepo)
	prev = writeV2Fixture(t, dst, v5PseudonymousRecordedFixture, rec)

	det := reg.Clone()
	det[FieldEventID] = "01a047b3-0a1e-7c41-9d2b-5e6f7a8b9c04"
	det[FieldIdempotencyKey] = "reg-8f21c-pn-detached"
	det[FieldChainPosition] = position + 4
	det[FieldPrevEventHash] = prev
	det[FieldRunID] = "run-46"
	det[FieldSpiffeID] = "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-46"
	det[FieldBranch] = "detached"
	prev = writeV2Fixture(t, dst, v5DetachedFixture, det)

	att := loadFixtureFrom(t, src, v4MigrationFixture).input.Clone()
	att[FieldSchemaVersion] = SchemaVersion
	att[FieldEventID] = "01a047b3-0a1e-7c41-9d2b-5e6f7a8b9c05"
	att[FieldChainPosition] = position + 5
	att[FieldPrevEventHash] = prev
	att[FieldFromSchemaVersion] = "4"
	att[FieldToSchemaVersion] = SchemaVersion
	writeV2Fixture(t, dst, v5MigrationFixture, att)

	writeProbeFixture(t, dst)
}
