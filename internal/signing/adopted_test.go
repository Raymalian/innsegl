// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"errors"
	"strings"
	"testing"
)

// ADP-007 — the fourth trailer, ADR-0051 decision 4, #298 (RM-187).
//
// An adopting commit names both runs. The signer is the claim's own run, as
// always; the dead run whose work it carries is Agent-Adopted-Run. Only the
// server writes it, so a caller that spells it is refused exactly as a
// caller-spelled Agent-Run is.

func TestADP007AnAdoptingClaimNamesTheDeadRunInItsOwnTrailer(t *testing.T) {
	plain, err := refClaim.Trailers()
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	for _, tr := range plain {
		if tr.Key == TrailerAgentAdoptedRun {
			t.Fatalf("a claim adopting nothing rendered %s", tr)
		}
	}

	adopting := refClaim
	adopting.AdoptedRun = "run-41"
	got, err := adopting.Trailers()
	if err != nil {
		t.Fatalf("Trailers: %v", err)
	}
	if len(got) != 4 || got[3] != (Trailer{Key: TrailerAgentAdoptedRun, Value: "run-41"}) {
		t.Errorf("trailers = %v, want the three plus %s: run-41", got, TrailerAgentAdoptedRun)
	}

	for _, tc := range []struct{ name, run string }{
		{"the signing run adopting itself", refClaim.Run},
		{"a run id that is not one", "run 41"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := refClaim
			c.AdoptedRun = tc.run
			if _, err := c.Trailers(); !errors.Is(err, ErrClaim) {
				t.Errorf("err = %v, want %v", err, ErrClaim)
			}
		})
	}
}

func TestADP007ACallerMaySupplyNeitherHalfOfAnAdoption(t *testing.T) {
	for _, line := range []string{
		"Agent-Adopted-Run: run-41",
		"agent-adopted-run:run-41",
	} {
		_, _, err := prepareMessage("fix: something\n\n" + line + "\n")
		if !errors.Is(err, ErrTrailerAlreadyPresent) {
			t.Errorf("%q: err = %v, want %v", line, err, ErrTrailerAlreadyPresent)
		}
	}
	if _, _, err := prepareMessage("fix: adopted work from a run that died\n"); err != nil {
		t.Errorf("control: a message that mentions adoption in prose refused: %v", err)
	}
	if !strings.HasPrefix(TrailerAgentAdoptedRun, "Agent-") {
		t.Error("the adoption trailer is outside the Agent-* family")
	}
}
