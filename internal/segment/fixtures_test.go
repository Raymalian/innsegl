// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
)

// The TC-SER golden fixtures are a free end-to-end test for this package.
// Fixtures 01-14 are one real hash chain, their event_hash values were derived
// by an oracle that is not Go, and they are immutable (doc 02 §7). Sealing them
// exercises the whole path — leaves, promotion, root, object, content address,
// proofs — against bytes this package had no hand in producing.
//
// This directory is read-only from here. Nothing below writes to it.
const goldenDir = "../event/testdata/fixtures/v1"

// The two values below came from the same Python oracle as the roots in
// merkle_test.go, run over the committed .hash files:
//
//	root   = merkle(open(f).read() for f in sorted(01..14 .hash))
//	object = json.dumps({"event_hashes": [...], "first_position": 1,
//	                     "last_position": 14, "segment_format_version": "1",
//	                     "segment_merkle_root": root},
//	                    sort_keys=True, separators=(",", ":"), ensure_ascii=False)
//	id     = "sha256:" + sha256(object.encode()).hexdigest()
const (
	goldenMerkleRoot = "sha256:1a3a08ee2021f778d13e8356740245621b1ea3ecc761a4e42714c42ce86dd14b"
	goldenSegmentID  = "sha256:86c80ddc52dda7c1b4db79204e677005893e9a5f1cd0f5ff8042de45fd518dc2"
)

var goldenChainPattern = regexp.MustCompile(`^(0[1-9]|1[0-4])-.*\.input\.json$`)

// loadGoldenChain returns fixtures 01-14 as ledger records: the committed input
// object plus the committed event_hash. It decodes with encoding/json rather
// than event.ParseFields so that the fixtures are read by something other than
// the package they are meant to hold to account.
func loadGoldenChain(t *testing.T) []event.Fields {
	t.Helper()

	entries, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Fatalf("read %s: %v", goldenDir, err)
	}
	var names []string
	for _, e := range entries {
		if goldenChainPattern.MatchString(e.Name()) {
			names = append(names, strings.TrimSuffix(e.Name(), ".input.json"))
		}
	}
	slices.Sort(names)
	if len(names) != 14 {
		t.Fatalf("found %d chain fixtures in %s, want 14", len(names), goldenDir)
	}

	records := make([]event.Fields, 0, len(names))
	for _, name := range names {
		raw, rerr := os.ReadFile(filepath.Join(goldenDir, name+".input.json"))
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
		hash, herr := os.ReadFile(filepath.Join(goldenDir, name+".hash"))
		if herr != nil {
			t.Fatalf("read %s.hash: %v", name, herr)
		}
		f[event.EventHashField] = string(hash)
		records = append(records, f)
	}
	return records
}

// TestGoldenFixturesAreWhatTheySay is the precondition for everything below:
// each fixture's committed event_hash really is the hash of its committed
// input, so the leaves this package seals are real event hashes and not file
// contents that happen to look like them.
func TestGoldenFixturesAreWhatTheySay(t *testing.T) {
	records := loadGoldenChain(t)
	for i, record := range records {
		if err := record.Verify(); err != nil {
			t.Errorf("fixture %02d: %v", i+1, err)
		}
	}
}

// TestGoldenSegmentSealsToADeterministicRoot is the end-to-end vector.
func TestGoldenSegmentSealsToADeterministicRoot(t *testing.T) {
	records := loadGoldenChain(t)

	first := mustSeal(t, newMemStore(), records)
	if first.MerkleRoot != goldenMerkleRoot {
		t.Errorf("merkle root\n got  %s\n want %s (Python oracle over the committed .hash files)",
			first.MerkleRoot, goldenMerkleRoot)
	}
	if first.SegmentID != goldenSegmentID {
		t.Errorf("segment id\n got  %s\n want %s (Python oracle over the canonical object)",
			first.SegmentID, goldenSegmentID)
	}
	if first.FirstPosition != 1 || first.LastPosition != 14 {
		t.Errorf("sealed range %d..%d, want 1..14", first.FirstPosition, first.LastPosition)
	}

	// Deterministic across runs, and across stores.
	second := mustSeal(t, newMemStore(), loadGoldenChain(t))
	if second.SegmentID != first.SegmentID || !bytes.Equal(second.Object, first.Object) {
		t.Errorf("a second seal of the same fixtures produced a different segment:\n %s\n %s",
			first.SegmentID, second.SegmentID)
	}
}

// TestGoldenSegmentProvesEveryEvent: fourteen events, fourteen proofs.
func TestGoldenSegmentProvesEveryEvent(t *testing.T) {
	records := loadGoldenChain(t)
	store := newMemStore()
	sealed := mustSeal(t, store, records)

	seg, err := Open(store, sealed.SegmentID)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	for i, record := range records {
		digest, ok := record[event.EventHashField].(string)
		if !ok {
			t.Fatalf("fixture %02d has no event_hash", i+1)
		}
		position, ok := record[event.FieldChainPosition].(int64)
		if !ok {
			t.Fatalf("fixture %02d has no chain_position", i+1)
		}

		proof, perr := seg.ProofForPosition(position)
		if perr != nil {
			t.Fatalf("ProofForPosition(%d): %v", position, perr)
		}
		if err := VerifyProof(goldenMerkleRoot, digest, proof); err != nil {
			t.Errorf("fixture %02d does not prove into the golden root: %v", i+1, err)
		}

		// And tampering with that one event breaks that one proof, while the
		// proof itself is unchanged — which is what an inclusion proof is for.
		tampered := flipDigestNibble(t, digest)
		if err := VerifyProof(goldenMerkleRoot, tampered, proof); err == nil {
			t.Errorf("fixture %02d proved into the golden root after being altered", i+1)
		}
	}
}

// TestGoldenSegmentTamperedInStorage runs SEG-006 over the golden data: alter
// one event hash inside the stored object and the read fails, twice over.
func TestGoldenSegmentTamperedInStorage(t *testing.T) {
	records := loadGoldenChain(t)
	store := newMemStore()
	sealed := mustSeal(t, store, records)

	original, err := store.Get(sealed.SegmentID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Swap fixture 03's event_hash for fixture 04's inside the object. The
	// object stays well-formed JSON and every member keeps its type.
	third, ok := records[2][event.EventHashField].(string)
	if !ok {
		t.Fatal("fixture 03 has no event_hash")
	}
	fourth, ok := records[3][event.EventHashField].(string)
	if !ok {
		t.Fatal("fixture 04 has no event_hash")
	}
	edited := bytes.Replace(original, []byte(third), []byte(fourth), 1)
	if bytes.Equal(edited, original) {
		t.Fatal("the edit changed nothing; the test would prove nothing")
	}
	if terr := store.tamper(sealed.SegmentID, func([]byte) []byte { return edited }); terr != nil {
		t.Fatalf("tamper: %v", terr)
	}

	// 1. The content address no longer matches.
	_, err = Open(store, sealed.SegmentID)
	var terr *TamperError
	if !errors.As(err, &terr) {
		t.Fatalf("Open error = %v, want a *TamperError", err)
	}

	// 2. And relocating the object to its new content address does not save it:
	//    the root it still records is not the root of the leaves it now holds.
	moved := newMemStore()
	if perr := moved.Put(digestOf(edited), edited); perr != nil {
		t.Fatalf("Put: %v", perr)
	}
	if _, oerr := Open(moved, digestOf(edited)); !errors.As(oerr, &terr) {
		t.Fatalf("the relocated object opened: error = %v, want a *TamperError", oerr)
	}

	// 3. And a tamperer who repairs the recorded root as well produces an
	//    object that is internally consistent and still fails, because the root
	//    is not the one the ledger's segment_sealed event claims.
	leaves := make([]string, len(records))
	for i, record := range records {
		digest, dok := record[event.EventHashField].(string)
		if !dok {
			t.Fatalf("fixture %02d has no event_hash", i+1)
		}
		leaves[i] = digest
	}
	leaves[2] = leaves[3]
	repairedRoot, err := Root(leaves)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	repaired := Object{
		EventHashes:   leaves,
		FirstPosition: 1,
		LastPosition:  14,
		FormatVersion: ObjectFormatVersion,
		MerkleRoot:    repairedRoot,
	}
	raw, err := repaired.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	forged := newMemStore()
	if perr := forged.Put(digestOf(raw), raw); perr != nil {
		t.Fatalf("Put: %v", perr)
	}
	seg, err := Open(forged, digestOf(raw))
	if err != nil {
		t.Fatalf("the repaired object is internally consistent and must open: %v", err)
	}
	claim, err := sealed.Event(EventMeta{EventID: subjectEventID, TS: alertTS(t)})
	if err != nil {
		t.Fatalf("Event: %v", err)
	}
	if err := seg.VerifyAgainst(claim); !errors.Is(err, ErrObjectMismatch) {
		t.Errorf("VerifyAgainst error = %v, want ErrObjectMismatch", err)
	}
}
