// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"strings"
	"testing"
)

// ADP-012 — the verifier and an adopting commit, ADR-0051 decision 5, #298.
//
// An adopting commit names two runs: the signer, and in Agent-Adopted-Run the
// dead run whose work it carries. The trailer is a line anybody can type, so
// on its own it proves nothing; the content check holds it to the ledger's
// run_adopted, and the two must agree exactly — a trailer naming an adoption
// the ledger never recorded is refused, and so is a recorded adoption whose
// commit no longer says so.

func TestADP012ReadClaimReadsTheAdoptionTrailer(t *testing.T) {
	c, err := ReadClaim("fix: x\n\nAgent-Run: run-live\nAgent-Adopted-Run: run-dead\n")
	if err != nil || c.AdoptedRun != "run-dead" || c.Run != "run-live" {
		t.Errorf("claim = %+v, %v; want run-live adopting run-dead", c, err)
	}
	if _, err = ReadClaim("fix: x\n\nAgent-Adopted-Run: run-a\nagent-adopted-run: run-b\n"); err == nil {
		t.Error("two adoption trailers were read as one claim")
	}
	only, err := ReadClaim("fix: x\n\nAgent-Adopted-Run: run-dead\n")
	if err != nil || !only.Present() {
		t.Errorf("an adoption trailer alone is not a claim: %+v, %v", only, err)
	}
}

func TestADP012TheContentCheckHoldsTheTrailerToTheLedger(t *testing.T) {
	dir := t.TempDir()
	original, rebased := contentRebase(t, dir)
	patchID := contentPatchID(t, dir, rebased)
	recorded := func(adopted string) *contentStub {
		return &contentStub{records: []ContentRecord{{
			RunID: "run-42", PatchID: patchID, CommitSHA: original,
			EventID: "01a047a5-cc41-7c45-86fd-a88c8c2b5320", AdoptedRun: adopted,
		}}}
	}
	check := func(claimed string, ledger *contentStub) ContentAttribution {
		return checkContent(t.Context(), contentInput{
			gitPath: "git", repo: dir, sha: rebased, runID: "run-42", adoptedRun: claimed,
		}, ledger)
	}

	got := check("run-dead", recorded("run-dead"))
	if got.Result != Verified || got.AdoptedRun != "run-dead" || !strings.Contains(got.Detail, "run-dead") {
		t.Errorf("an adoption the ledger recorded = %s, %q (%s); want verified and named",
			got.Result, got.AdoptedRun, got.Detail)
	}

	for _, tc := range []struct{ name, claimed, recorded string }{
		{"a trailer naming an adoption the ledger never recorded", "run-dead", ""},
		{"a recorded adoption whose commit no longer says so", "", "run-dead"},
		{"a trailer naming a different dead run", "run-other", "run-dead"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := check(tc.claimed, recorded(tc.recorded))
			if got.Result != Failed {
				t.Errorf("= %s (%s), want %s", got.Result, got.Detail, Failed)
			}
			if !strings.Contains(got.Detail, "adopt") {
				t.Errorf("detail %q does not say the adoption is what disagrees", got.Detail)
			}
		})
	}

	// The control: a plain change, claimed plainly, is exactly VER-010.
	if got := check("", recorded("")); got.Result != Verified || got.AdoptedRun != "" {
		t.Errorf("a plain change = %s, %q", got.Result, got.AdoptedRun)
	}
}
