// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// SEG-003 (doc 07, layer I): "Anchor sealed root in local Rekor; verify
// inclusion → inclusion proof retrievable and valid." Proves I5.
//
// This is the invariant's moment for the ledger. Everything else the ledger
// does — the hash chain, the sealed object, the WORM bucket — is our word
// against a reader's. The anchor is the one artefact an operator cannot
// retract: once a segment's Merkle root is in a transparency log somebody else
// runs, rewriting history stops being a database operation and starts being a
// thing the public record contradicts.
//
// So the verification below deliberately trusts nothing Rekor asserts *about*
// the proof. Rekor returns a root hash; this test does not take its word for
// it. The leaf is re-hashed from the entry body, the path is walked to a root
// with the RFC 6962 rules, the checkpoint is parsed, and the checkpoint's
// signature is checked against the log's public key. What is trusted is
// exactly one thing: that the key belongs to the log — which is what a trust
// root is for.

func rekorClient(t *testing.T, stack *rekorStack) *RekorClient {
	t.Helper()
	signer, err := GenerateAnchorSigner()
	if err != nil {
		t.Fatalf("GenerateAnchorSigner: %v", err)
	}
	return &RekorClient{BaseURL: stack.BaseURL(), Signer: signer}
}

type anchoredSegment struct {
	sealed *Sealed
	record event.Fields
	anchor Anchor
}

func TestSEG003AnchorSealedRootInLocalRekor(t *testing.T) {
	stack := requireRekor(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	client := rekorClient(t, stack)
	logKey, err := client.PublicKey(ctx)
	if err != nil {
		t.Fatalf("fetch the log's public key: %v", err)
	}

	clock := newTestClock(t, "2026-08-28T10:10:00.000Z")
	anchorer := &Anchorer{
		Log:    client,
		Policy: RetryPolicy{Attempts: 3, Base: 200 * time.Millisecond, Max: time.Second, Multiplier: 2},
		Bound:  5 * time.Minute,
		Now:    clock.Now,
	}

	store := newMemStore()
	sealer := &Sealer{Store: store}
	chain := &testChain{}

	// Three segments, not one. A log of size one has an empty inclusion path,
	// and an empty path verifies against any single-leaf tree — it would prove
	// the plumbing works and nothing about the walk.
	var segments []anchoredSegment
	for i := range 3 {
		first := int64(1 + i*8)
		sealed, record := sealAndAppend(t, sealer, chain, first, 8,
			"2026-08-28T10:0"+string(rune('0'+i))+":00.000Z")
		anchor, aerr := anchorer.Anchor(ctx, record)
		if aerr != nil {
			t.Fatalf("Anchor segment %d (%s): %v", i, sealed.SegmentID, aerr)
		}
		if anchor.EntryUUID == "" {
			t.Fatalf("segment %d anchored with no entry uuid", i)
		}
		if anchor.MerkleRoot != sealed.MerkleRoot {
			t.Fatalf("segment %d anchored root %s, sealed root is %s",
				i, anchor.MerkleRoot, sealed.MerkleRoot)
		}
		if err := event.ValidateDigest(anchor.MerkleRoot); err != nil {
			t.Fatalf("anchored root is not a digest: %v", err)
		}
		segments = append(segments, anchoredSegment{sealed, record, anchor})
	}
	chain.verify(t)

	t.Run("inclusion_proof_is_retrievable_and_valid", func(t *testing.T) {
		// Retrieved by a client with no signing key at all: a third party
		// verifying our claim has our segment id and nothing else (I5).
		reader := &RekorClient{BaseURL: stack.BaseURL()}

		for i, seg := range segments {
			proof, perr := reader.InclusionProof(ctx, seg.anchor.EntryUUID)
			if perr != nil {
				t.Fatalf("segment %d: InclusionProof: %v", i, perr)
			}
			if proof.TreeSize < 3 {
				t.Fatalf("segment %d: tree size %d, want at least the 3 entries anchored",
					i, proof.TreeSize)
			}
			if len(proof.Hashes) == 0 {
				t.Fatalf("segment %d: empty inclusion path in a tree of %d; "+
					"an empty path proves nothing", i, proof.TreeSize)
			}
			if err := proof.Verify(logKey); err != nil {
				t.Fatalf("segment %d: the inclusion proof does not verify: %v", i, err)
			}

			root, rerr := proof.MerkleRoot()
			if rerr != nil {
				t.Fatalf("segment %d: reading the anchored root: %v", i, rerr)
			}
			if root != seg.sealed.MerkleRoot {
				t.Fatalf("segment %d: the log entry attests %s, the segment root is %s",
					i, root, seg.sealed.MerkleRoot)
			}
			// The ledger's own claim and the log entry have to agree, or the
			// anchor names some other segment.
			if root != seg.record[event.FieldSegmentMerkleRoot] {
				t.Fatalf("segment %d: the ledger claims %v, the log attests %s",
					i, seg.record[event.FieldSegmentMerkleRoot], root)
			}
			t.Logf("segment %d anchored: uuid=%s log_index=%d tree_size=%d path=%d root=%s",
				i, seg.anchor.EntryUUID, proof.LogIndex, proof.TreeSize, len(proof.Hashes), proof.RootHash)
		}
	})

	t.Run("a_tampered_proof_is_refused", func(t *testing.T) {
		reader := &RekorClient{BaseURL: stack.BaseURL()}
		base, perr := reader.InclusionProof(ctx, segments[0].anchor.EntryUUID)
		if perr != nil {
			t.Fatalf("InclusionProof: %v", perr)
		}
		if err := base.Verify(logKey); err != nil {
			t.Fatalf("the untampered proof does not verify: %v", err)
		}

		cases := []struct {
			name string
			edit func(InclusionProof) InclusionProof
		}{
			{"a sibling hash is flipped", func(p InclusionProof) InclusionProof {
				p.Hashes = append([]string(nil), p.Hashes...)
				p.Hashes[0] = flipHexNibble(p.Hashes[0])
				return p
			}},
			{"the entry body is edited", func(p InclusionProof) InclusionProof {
				p.Body = append(append([]byte(nil), p.Body...), ' ')
				return p
			}},
			{"the claimed root is changed", func(p InclusionProof) InclusionProof {
				p.RootHash = flipHexNibble(p.RootHash)
				return p
			}},
			{"the tree size is inflated", func(p InclusionProof) InclusionProof {
				p.TreeSize += 4
				return p
			}},
			{"the leaf is moved to another index", func(p InclusionProof) InclusionProof {
				p.LogIndex = (p.LogIndex + 1) % p.TreeSize
				return p
			}},
			{"the checkpoint claims another tree size", func(p InclusionProof) InclusionProof {
				// Line 2 of a signed note checkpoint is the tree size. Bumping
				// it leaves a well-formed, correctly-signed-looking checkpoint
				// that disagrees with the proof it accompanies.
				lines := strings.Split(p.Checkpoint, "\n")
				if len(lines) < 3 {
					t.Fatalf("checkpoint has %d lines: %q", len(lines), p.Checkpoint)
				}
				lines[1] = strconv.FormatInt(p.TreeSize+1, 10)
				p.Checkpoint = strings.Join(lines, "\n")
				return p
			}},
			{"a path step is dropped", func(p InclusionProof) InclusionProof {
				p.Hashes = append([]string(nil), p.Hashes[1:]...)
				return p
			}},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				if err := c.edit(base).Verify(logKey); err == nil {
					t.Fatal("the tampered proof verified")
				}
			})
		}

		t.Run("another log's key is refused", func(t *testing.T) {
			other, kerr := GenerateAnchorSigner()
			if kerr != nil {
				t.Fatalf("GenerateAnchorSigner: %v", kerr)
			}
			if err := base.Verify(&other.key.PublicKey); err == nil {
				t.Fatal("the proof verified under a key the log does not hold")
			}
		})

		t.Run("no key at all is refused", func(t *testing.T) {
			if err := base.Verify(nil); err == nil {
				t.Fatal("the proof verified with no trust root")
			}
		})
	})

	t.Run("re_anchoring_is_harmless_at_least_once", func(t *testing.T) {
		// A submission that succeeds at the log but times out at the client
		// leaves an entry the caller never learned the id of, and the retry
		// adds a second: ECDSA nonces are random, so two submissions of one
		// root are two entry bodies and Rekor keeps both (ADR-0007). The
		// property that makes that survivable — rather than a second, weaker
		// claim — is that the extra entry attests exactly the same root and
		// proves it exactly as well.
		again, aerr := anchorer.Anchor(ctx, segments[0].record)
		if aerr != nil {
			t.Fatalf("re-anchoring an already anchored root: %v", aerr)
		}
		if again.EntryUUID == segments[0].anchor.EntryUUID {
			t.Skip("the log deduplicated the submission; nothing to check about the duplicate")
		}
		if again.MerkleRoot != segments[0].anchor.MerkleRoot {
			t.Fatalf("the second entry is for root %s, the first is for %s",
				again.MerkleRoot, segments[0].anchor.MerkleRoot)
		}

		proof, perr := client.InclusionProof(ctx, again.EntryUUID)
		if perr != nil {
			t.Fatalf("InclusionProof for the second entry: %v", perr)
		}
		if err := proof.Verify(logKey); err != nil {
			t.Fatalf("the second entry's inclusion proof does not verify: %v", err)
		}
		root, rerr := proof.MerkleRoot()
		if rerr != nil {
			t.Fatalf("reading the second entry's root: %v", rerr)
		}
		if root != segments[0].sealed.MerkleRoot {
			t.Fatalf("the second entry attests %s, the segment root is %s",
				root, segments[0].sealed.MerkleRoot)
		}

		// The heartbeat must not walk backwards because an older segment was
		// re-anchored.
		if snap := anchorer.Lag(); snap.SegmentID != segments[2].sealed.SegmentID {
			t.Fatalf("re-anchoring segment 0 moved the heartbeat to %s, want %s",
				snap.SegmentID, segments[2].sealed.SegmentID)
		}
	})

	t.Run("the_anchor_lands_as_a_superseding_event", func(t *testing.T) {
		// Doc 02 §3: the anchoring members "appended via a superseding
		// segment_sealed update event once Rekor confirms — the original stays
		// untouched". Golden fixtures 11 and 12 are the committed pair.
		original := segments[0].record
		before, cerr := event.Canonicalize(original)
		if cerr != nil {
			t.Fatalf("Canonicalize: %v", cerr)
		}

		body, aerr := AnchorEvent(EventMeta{
			EventID: newEventID(t),
			TS:      mustTS(t, "2026-08-28T10:20:31.442Z"),
		}, original, segments[0].anchor)
		if aerr != nil {
			t.Fatalf("AnchorEvent: %v", aerr)
		}
		if _, present := body[event.FieldSupersedes]; present {
			t.Fatal("AnchorEvent set supersedes itself; ledger.Correct owns that member")
		}

		record := chain.correct(t, original, body)

		if got := record[event.FieldSupersedes]; got != original[event.FieldEventID] {
			t.Fatalf("supersedes is %v, want the original event %v", got, original[event.FieldEventID])
		}
		if got := record[event.FieldEventType]; got != event.EventTypeSegmentSealed {
			t.Fatalf("the superseding event is a %v, want a %s", got, event.EventTypeSegmentSealed)
		}
		if got := record[event.FieldAnchorRekorEntryUUID]; got != segments[0].anchor.EntryUUID {
			t.Fatalf("anchor_rekor_entry_uuid is %v, want %s", got, segments[0].anchor.EntryUUID)
		}
		if got := record[event.FieldAnchorRekorLogIndex]; got != segments[0].anchor.LogIndex {
			t.Fatalf("anchor_rekor_log_index is %v (%T), want %d",
				got, got, segments[0].anchor.LogIndex)
		}
		// The four members that describe the segment carry across unchanged:
		// the superseding event is the same claim plus its proof.
		for _, name := range []string{
			event.FieldSegmentID, event.FieldSegmentMerkleRoot,
			event.FieldFirstPosition, event.FieldLastPosition,
		} {
			if record[name] != original[name] {
				t.Fatalf("%s is %v on the superseding event and %v on the original",
					name, record[name], original[name])
			}
		}
		if err := event.ValidateEvent(record); err != nil {
			t.Fatalf("the superseding event is not valid: %v", err)
		}

		after, cerr := event.Canonicalize(original)
		if cerr != nil {
			t.Fatalf("Canonicalize: %v", cerr)
		}
		if string(before) != string(after) {
			t.Fatalf("the original event changed:\n before %s\n after  %s", before, after)
		}
		chain.verify(t)
	})

	t.Run("an_anchor_for_another_segment_is_refused", func(t *testing.T) {
		wrong := segments[1].anchor
		if _, err := AnchorEvent(EventMeta{
			EventID: newEventID(t),
			TS:      mustTS(t, "2026-08-28T10:21:00.000Z"),
		}, segments[0].record, wrong); !errors.Is(err, ErrAnchorMismatch) {
			t.Fatalf("attaching segment 1's anchor to segment 0 returned %v, "+
				"want an error wrapping ErrAnchorMismatch", err)
		}
	})

	t.Run("lag_reports_the_log_as_current_once_anchored", func(t *testing.T) {
		snap := anchorer.Lag()
		if !snap.Anchored {
			t.Fatal("the snapshot does not report the segments as anchored")
		}
		if snap.PendingSegments != 0 {
			t.Fatalf("%d segments still pending after all three anchored", snap.PendingSegments)
		}
		if snap.SegmentID != segments[2].sealed.SegmentID {
			t.Fatalf("the heartbeat names segment %s, want the last anchored %s",
				snap.SegmentID, segments[2].sealed.SegmentID)
		}
		if snap.LastPosition != segments[2].sealed.LastPosition {
			t.Fatalf("the heartbeat covers up to position %d, want %d",
				snap.LastPosition, segments[2].sealed.LastPosition)
		}
		if snap.OverBound {
			t.Fatalf("a lag of %vs is over a bound of %vs", snap.LagSeconds, snap.BoundSeconds)
		}
		if snap.ObservedAt != clock.Now() {
			t.Fatalf("ObservedAt is %v, want %v", snap.ObservedAt, clock.Now())
		}
	})

	// SEG-004's other half: the degradation is bounded, which means it ends.
	// The outage above (a closed port) is verified there; what needs a real log
	// is that the lag actually closes once one is reachable again.
	t.Run("SEG-004_lag_closes_when_the_log_comes_back", func(t *testing.T) {
		dead, counter := deadRekor(t)
		outageClock := newTestClock(t, "2026-08-28T11:00:00.000Z")
		recovering := &Anchorer{
			Log:    dead,
			Policy: RetryPolicy{Attempts: 2, Base: time.Millisecond},
			Bound:  30 * time.Second,
			Now:    outageClock.Now,
			Sleep:  func(context.Context, time.Duration) error { return nil },
		}

		sealed, record := sealAndAppend(t, sealer, chain, 25, 8, "2026-08-28T10:59:00.000Z")
		if _, err := recovering.Anchor(ctx, record); !errors.Is(err, ErrAnchorUnavailable) {
			t.Fatalf("Anchor against a closed port returned %v, want ErrAnchorUnavailable", err)
		}
		if attempts, _ := counter.count(); attempts != 2 {
			t.Fatalf("%d connection attempts during the outage, want 2", attempts)
		}
		if outage := recovering.Lag(); !outage.OverBound || outage.PendingSegments != 1 {
			t.Fatalf("during the outage the heartbeat reads %+v; want one pending segment over bound", outage)
		}

		recovering.Log = client
		anchor, err := recovering.Anchor(ctx, record)
		if err != nil {
			t.Fatalf("Anchor once the log is reachable again: %v", err)
		}
		if anchor.MerkleRoot != sealed.MerkleRoot {
			t.Fatalf("recovered anchor is for root %s, want %s", anchor.MerkleRoot, sealed.MerkleRoot)
		}

		recovered := recovering.Lag()
		if !recovered.Anchored {
			t.Fatal("the heartbeat still reports the segment unanchored")
		}
		if recovered.PendingSegments != 0 {
			t.Fatalf("%d segments still pending after recovery", recovered.PendingSegments)
		}
		if recovered.OverBound {
			t.Fatalf("the heartbeat is still amber after recovery: %+v", recovered)
		}

		proof, perr := client.InclusionProof(ctx, anchor.EntryUUID)
		if perr != nil {
			t.Fatalf("InclusionProof after recovery: %v", perr)
		}
		if err := proof.Verify(logKey); err != nil {
			t.Fatalf("the recovered anchor's proof does not verify: %v", err)
		}
	})
}

// flipHexNibble changes one hex digit, leaving the string a valid hex string of
// the same length — so what a verifier rejects is the value, not the shape.
func flipHexNibble(s string) string {
	if s == "" {
		return "0"
	}
	out := []byte(s)
	last := len(out) - 1
	if out[last] == '0' {
		out[last] = '1'
	} else {
		out[last] = '0'
	}
	return string(out)
}
