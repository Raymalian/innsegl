// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
)

// goldenChainDir holds the TC-SER golden vectors. They are read-only here and
// immutable everywhere (doc 02 §7): fixtures 01-14 are one valid hash chain
// rooted at the genesis constant, and they were derived by an oracle that is
// not this code. Verifying them end to end is the closest thing to an
// independent check of the chain walk that exists in this repository.
const goldenChainDir = "../event/testdata/fixtures/v1"

// chainFixturePattern matches the fixture inputs that form the chain: 01-14.
var chainFixturePattern = regexp.MustCompile(`^(0[1-9]|1[0-4])-.*\.input\.json$`)

// loadGoldenChain returns fixtures 01-14 as appended records: the committed
// input object plus the committed event_hash.
//
// It deliberately avoids event.ParseFields, so a fixture is decoded by
// something other than the code the fixture is meant to hold to account.
func loadGoldenChain(t *testing.T) []event.Fields {
	t.Helper()

	entries, err := os.ReadDir(goldenChainDir)
	if err != nil {
		t.Fatalf("read %s: %v", goldenChainDir, err)
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		// The chain is the numbered vectors 01-14. 00-doc02-example keeps the
		// spec's chain_position of 412 and is not part of it; format-probe is
		// not an event at all.
		if !chainFixturePattern.MatchString(n) {
			continue
		}
		names = append(names, strings.TrimSuffix(n, ".input.json"))
	}
	slices.Sort(names)
	if len(names) != 14 {
		t.Fatalf("found %d chain fixtures in %s, want 14", len(names), goldenChainDir)
	}

	records := make([]event.Fields, 0, len(names))
	for _, name := range names {
		raw, rerr := os.ReadFile(filepath.Join(goldenChainDir, name+".input.json"))
		if rerr != nil {
			t.Fatalf("read %s: %v", name, rerr)
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var m map[string]any
		if derr := dec.Decode(&m); derr != nil {
			t.Fatalf("%s: decode: %v", name, derr)
		}
		f := make(event.Fields, len(m)+1)
		for k, v := range m {
			if n, ok := v.(json.Number); ok {
				i, ierr := n.Int64()
				if ierr != nil {
					t.Fatalf("%s: member %q is not an integer: %v", name, k, ierr)
				}
				f[k] = i
				continue
			}
			f[k] = v
		}
		hash, herr := os.ReadFile(filepath.Join(goldenChainDir, name+".hash"))
		if herr != nil {
			t.Fatalf("read %s.hash: %v", name, herr)
		}
		f[event.EventHashField] = string(hash)
		records = append(records, f)
	}
	return records
}

// goldenTip is the head the golden chain ends at: position 14 carrying the
// committed event_hash of fixture 14.
func goldenTip(t *testing.T, records []event.Fields) Head {
	t.Helper()
	head, err := RecordHead(records[len(records)-1])
	if err != nil {
		t.Fatalf("RecordHead of the last fixture: %v", err)
	}
	return head
}

// TestGoldenChainVerifies walks the committed 14-event chain from the genesis
// constant to its tip. Nothing in this test was produced by the code under
// test: the bytes, the hashes and the links all come from the fixtures.
func TestGoldenChainVerifies(t *testing.T) {
	records := loadGoldenChain(t)

	head, err := Verify(records)
	if err != nil {
		t.Fatalf("the golden chain does not verify: %v", err)
	}
	if head.Position != 14 {
		t.Errorf("golden chain tip is at position %d, want 14", head.Position)
	}
	if err := VerifyTip(records, goldenTip(t, records)); err != nil {
		t.Errorf("VerifyTip on the golden chain: %v", err)
	}

	// Position 1 carries the genesis constant, computed rather than copied.
	if got := memberString(t, records[0], event.FieldPrevEventHash); got != event.GenesisPrevEventHash() {
		t.Errorf("fixture 01 %s = %s, want the genesis constant %s",
			event.FieldPrevEventHash, got, event.GenesisPrevEventHash())
	}
}

// TestGoldenChainTamperingBreaksIt tampers with each fixture in turn and
// asserts the walk fails from exactly that position onward.
func TestGoldenChainTamperingBreaksIt(t *testing.T) {
	records := loadGoldenChain(t)

	for i := range records {
		t.Run(fmt.Sprintf("position_%d", i+1), func(t *testing.T) {
			edited := records[i].Clone()
			edited[event.FieldTS] = "2026-08-28T09:14:03.202Z"

			damaged := make([]event.Fields, len(records))
			copy(damaged, records)
			damaged[i] = edited
			assertBreaksFrom(t, damaged, i+1)
		})
	}
}

// TestGoldenChainRemovalBreaksIt removes each fixture in turn.
func TestGoldenChainRemovalBreaksIt(t *testing.T) {
	records := loadGoldenChain(t)
	tip := goldenTip(t, records)
	for i := range records {
		t.Run(fmt.Sprintf("position_%d", i+1), func(t *testing.T) {
			assertRemovalDetected(t, records, tip, i)
		})
	}
}

// TestGoldenCorrectionLeavesTheOriginalUntouched is LED-004 against committed
// bytes: fixture 12 is a segment_sealed update that supersedes fixture 11, and
// fixture 11's canonical bytes are exactly what they were before it existed.
func TestGoldenCorrectionLeavesTheOriginalUntouched(t *testing.T) {
	records := loadGoldenChain(t)
	original, correction := records[10], records[11]

	if got := memberString(t, correction, event.FieldSupersedes); got != memberString(t, original, event.FieldEventID) {
		t.Fatalf("fixture 12 supersedes %s, want fixture 11's event_id %s",
			got, memberString(t, original, event.FieldEventID))
	}

	// The superseded event's preimage is byte-identical to its committed
	// canonical form. A correction that had edited it could not be.
	want, err := os.ReadFile(filepath.Join(goldenChainDir, "11-segment_sealed.canonical.json"))
	if err != nil {
		t.Fatalf("read committed canonical bytes: %v", err)
	}
	got, err := original.Preimage()
	if err != nil {
		t.Fatalf("Preimage: %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("the superseded event's canonical bytes changed\n want %s\n got  %s", want, got)
	}

	// And both still sit in a chain that verifies.
	if _, err := Verify(records); err != nil {
		t.Errorf("the chain carrying the correction does not verify: %v", err)
	}
}

// TestGoldenChainDetectsAByteFlip flips one byte of a committed canonical
// record and re-parses it, proving the golden data is not special-cased.
func TestGoldenChainDetectsAByteFlip(t *testing.T) {
	records := loadGoldenChain(t)

	raw, err := event.Canonicalize(records[6])
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	// Byte 40 sits inside a member value in every fixture at this size; the
	// assertion below does not depend on which.
	mutated := make([]byte, len(raw))
	copy(mutated, raw)
	mutated[40]++

	parsed, err := event.ParseFields(mutated)
	if err != nil {
		t.Fatalf("the flipped record no longer parses, which is a weaker check: %v", err)
	}
	damaged := make([]event.Fields, len(records))
	copy(damaged, records)
	damaged[6] = parsed

	_, err = Verify(damaged)
	var verr *VerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("Verify error = %v, want a *VerificationError", err)
	}
	if verr.Position != 7 {
		t.Errorf("failed at position %d, want 7", verr.Position)
	}
}
