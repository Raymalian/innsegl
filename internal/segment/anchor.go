// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
	"sync"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// Rekor anchoring and the lag it is measured by.
//
// # Why this exists
//
// Every other guarantee in this package is ours to make and ours to break. The
// hash chain is our code, the sealed object is in our bucket, the WORM policy
// is on our account. A reader who suspects the operator has nothing to check
// any of it against. The anchor is the one thing that leaves: once a segment's
// Merkle root is an entry in a transparency log somebody else runs, rewriting
// history stops being a database operation and becomes a claim the public
// record contradicts. That is invariant I5, and SEG-003 is where it is proven.
//
// # Why failing to anchor is survivable
//
// IP §6.4: "Rekor anchoring of a sealed segment fails → retry with backoff and
// alert; appends to the *next* segment continue (anchoring lag is a monitored,
// bounded degradation — it delays public tamper-evidence, it does not lose or
// weaken records)." Nothing here is on the append path, and nothing here holds
// a lock the sealer takes. An unanchored segment is a segment whose proof is
// late, not a segment that is worth less; the events in it are chained, sealed
// and stored exactly as they would have been.
//
// The cost of the outage is therefore a number, and the number has to be
// visible: FD §3.1 renders it in the persistent header, amber past the bound,
// "never hidden". Lag() is that number, with the timestamp it was taken at —
// a boolean could not say how far behind the log the ledger is.
//
// # Why the anchoring members arrive later
//
// Doc 02 §3 puts them on a *superseding* segment_sealed event: "anchoring
// fields appended via a superseding segment_sealed update event once Rekor
// confirms — the original stays untouched". The original cannot carry them,
// because at seal time they do not exist, and it cannot be edited to carry
// them afterwards, because nothing in this ledger is ever edited (I4). Golden
// fixtures 11 and 12 are the committed pair. AnchorEvent builds the second of
// them; ledger.Correct attaches the `supersedes` that links it to the first.

var (
	// ErrAnchorUnavailable reports a transparency log that could not be
	// reached, or that answered that it is broken. It is the retryable class.
	ErrAnchorUnavailable = errors.New("transparency log unavailable")

	// ErrAnchorMismatch reports an anchor that does not belong to the segment
	// it is being attached to.
	ErrAnchorMismatch = errors.New("anchor does not match the segment it claims")

	// ErrInclusionProof reports a Rekor inclusion proof that does not verify.
	ErrInclusionProof = errors.New("rekor inclusion proof does not verify")
)

// Anchor is a sealed segment's entry in the transparency log.
//
// LogIndex and EntryUUID are the two members doc 02 §3 records on the
// superseding segment_sealed event; the rest is what the anchorer needed to
// produce them and what a later reader finds useful in a log line.
type Anchor struct {
	// SegmentID is the segment this anchor is for. Set by the Anchorer, which
	// knows it; the log client does not.
	SegmentID string
	// MerkleRoot is the root that was anchored, `sha256:`-prefixed.
	MerkleRoot string
	// LogIndex is the entry's index in the log (anchor_rekor_log_index).
	LogIndex int64
	// EntryUUID identifies the entry (anchor_rekor_entry_uuid).
	EntryUUID string
	// IntegratedAt is when the log says it integrated the entry.
	IntegratedAt time.Time
}

// InclusionProof is Rekor's proof that an entry is in the log.
//
// Everything here is what the log said. Verify is what makes it worth
// something.
type InclusionProof struct {
	// EntryUUID is the entry the proof is for. Rekor spells it as an optional
	// 16-hex tree-id prefix followed by the 64-hex leaf hash.
	EntryUUID string
	// Body is the entry's canonical bytes — the log's leaf value.
	Body []byte
	// LogIndex is the leaf's index inside the tree the proof is against.
	LogIndex int64
	// TreeSize is the size of that tree.
	TreeSize int64
	// RootHash is the root the log claims, hex.
	RootHash string
	// Hashes is the inclusion path, hex, leaf-ward first.
	Hashes []string
	// Checkpoint is the log's signed note over TreeSize and RootHash.
	Checkpoint string
}

// Verify checks the proof from first principles against a pinned log key.
//
// Nothing Rekor asserts *about* the proof is taken on trust. In order:
//
//  1. The entry body is re-hashed and must be the leaf the uuid names, so the
//     proof cannot be for some other entry.
//  2. The path is walked to a root under RFC 6962's rules, and must reach the
//     root the log claims. The path length is derived from index and tree size
//     rather than read from the proof, so a step cannot be added or dropped.
//  3. The checkpoint must be over the same tree — same size, same root.
//  4. The checkpoint's signature must verify under logKey.
//
// Only step 4 involves trusting anything, and what it trusts is a key, which
// is what a trust root is. A nil key is refused rather than treated as "skip
// the signature": a proof checked without one says only that Rekor's arithmetic
// is self-consistent, which an attacker who controls the response can arrange.
//
// # Not the doc 02 §4.6 tree
//
// Rekor's tree is RFC 6962's, which splits at the largest power of two below
// the size. A segment's tree (merkle.go) builds level by level and promotes an
// odd node. The leaf and node hash constructions are the same, so hashLeaf and
// hashNode are shared, but the shapes differ and VerifyProof must never be
// pointed at a Rekor proof or the other way round.
func (p InclusionProof) Verify(logKey *ecdsa.PublicKey) error {
	if logKey == nil {
		return fmt.Errorf(
			"%w: no log key to check the checkpoint against; an unsigned proof "+
				"only shows the log agrees with itself", ErrInclusionProof)
	}
	if len(p.Body) == 0 {
		return fmt.Errorf("%w: the proof carries no entry body to hash", ErrInclusionProof)
	}
	if p.TreeSize < 1 || p.LogIndex < 0 || p.LogIndex >= p.TreeSize {
		return fmt.Errorf("%w: leaf %d of a tree of %d", ErrInclusionProof, p.LogIndex, p.TreeSize)
	}

	leaf := hashLeaf(p.Body)
	if err := p.checkEntryUUID(leaf); err != nil {
		return err
	}

	path, err := decodeProofPath(p.Hashes)
	if err != nil {
		return err
	}
	root, err := rekorInclusionRoot(uint64(p.LogIndex), uint64(p.TreeSize), leaf, path)
	if err != nil {
		return err
	}
	if got := hex.EncodeToString(root[:]); got != p.RootHash {
		return fmt.Errorf("%w: the path reaches %s, the log claims %s",
			ErrInclusionProof, got, p.RootHash)
	}

	cp, err := parseCheckpoint(p.Checkpoint)
	if err != nil {
		return err
	}
	if cp.size != p.TreeSize {
		return fmt.Errorf("%w: the checkpoint is over a tree of %d, the proof is over %d",
			ErrInclusionProof, cp.size, p.TreeSize)
	}
	if cp.rootHex != p.RootHash {
		return fmt.Errorf("%w: the checkpoint's root is %s, the proof's is %s",
			ErrInclusionProof, cp.rootHex, p.RootHash)
	}
	return cp.verifySignature(logKey)
}

// checkEntryUUID ties the body to the identifier the ledger recorded.
func (p InclusionProof) checkEntryUUID(leaf [32]byte) error {
	if !isHexUUID(p.EntryUUID) {
		return fmt.Errorf("%w: %q is not a rekor entry uuid", ErrInclusionProof, p.EntryUUID)
	}
	want := p.EntryUUID[len(p.EntryUUID)-64:]
	if got := hex.EncodeToString(leaf[:]); got != want {
		return fmt.Errorf("%w: the entry body hashes to %s, uuid %s names %s",
			ErrInclusionProof, got, p.EntryUUID, want)
	}
	return nil
}

// MerkleRoot returns the segment root the log entry attests.
//
// This is the join between the two records: the ledger's segment_sealed event
// says a segment has this root, and the log entry says somebody signed this
// root at this time. Neither is worth much without the other agreeing.
func (p InclusionProof) MerkleRoot() (string, error) {
	var entry hashedRekord
	dec := json.NewDecoder(bytes.NewReader(p.Body))
	if err := dec.Decode(&entry); err != nil {
		return "", fmt.Errorf("%w: the entry body is not a %s: %w",
			ErrInclusionProof, rekorHashedRekordKind, err)
	}
	if entry.Kind != rekorHashedRekordKind {
		return "", fmt.Errorf("%w: the entry is a %q, this system anchors %q",
			ErrInclusionProof, entry.Kind, rekorHashedRekordKind)
	}
	if entry.Spec.Data.Hash.Algorithm != hashAlgorithmSHA256 {
		return "", fmt.Errorf("%w: the entry hashes with %q, segment roots are %s",
			ErrInclusionProof, entry.Spec.Data.Hash.Algorithm, hashAlgorithmSHA256)
	}
	root := event.HashPrefix + entry.Spec.Data.Hash.Value
	if err := event.ValidateDigest(root); err != nil {
		return "", fmt.Errorf("%w: %w", ErrInclusionProof, err)
	}
	return root, nil
}

func decodeProofPath(hashes []string) ([][32]byte, error) {
	path := make([][32]byte, len(hashes))
	for i, h := range hashes {
		raw, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("%w: path step %d is not hex: %w", ErrInclusionProof, i, err)
		}
		if len(raw) != sha256.Size {
			return nil, fmt.Errorf("%w: path step %d is %d bytes, want %d",
				ErrInclusionProof, i, len(raw), sha256.Size)
		}
		path[i] = [32]byte(raw)
	}
	return path, nil
}

// rekorInclusionRoot walks an RFC 6962 inclusion path to a root.
//
// The number of steps is a function of index and size, not of the proof: the
// path is split into the inner steps (where the leaf's subtree is complete)
// and the border steps (the right-hand spine of a ragged tree), and a path of
// any other length is refused before a hash is computed. That is what makes
// "a step was dropped" a detected condition rather than a different root.
func rekorInclusionRoot(index, size uint64, leaf [32]byte, path [][32]byte) ([32]byte, error) {
	if size == 0 || index >= size {
		return [32]byte{}, fmt.Errorf("%w: leaf %d of a tree of %d", ErrInclusionProof, index, size)
	}
	inner := bits.Len64(index ^ (size - 1))
	border := bits.OnesCount64(index >> uint(inner))
	if want := inner + border; len(path) != want {
		return [32]byte{}, fmt.Errorf(
			"%w: the path has %d steps, leaf %d of a tree of %d takes %d",
			ErrInclusionProof, len(path), index, size, want)
	}

	running := leaf
	for i, sibling := range path[:inner] {
		if (index>>uint(i))&1 == 0 {
			running = hashNode(running, sibling)
		} else {
			running = hashNode(sibling, running)
		}
	}
	for _, sibling := range path[inner:] {
		running = hashNode(sibling, running)
	}
	return running, nil
}

// checkpoint is a parsed signed note: origin, tree size, root, signatures.
type checkpoint struct {
	origin  string
	size    int64
	rootHex string
	// signed is the exact text the signatures are over.
	signed string
	// signatures are the raw signature bytes of each signature line, with the
	// four-byte key hint already stripped.
	signatures [][]byte
}

// parseCheckpoint reads the signed-note checkpoint Rekor returns.
//
// The format is the note format: a body of origin, decimal size and
// base64 root, a blank line, then one or more "— name base64" signature lines.
// The signed text is the body up to and including its final newline.
func parseCheckpoint(raw string) (checkpoint, error) {
	body, signatures, found := strings.Cut(raw, "\n\n")
	if !found {
		return checkpoint{}, fmt.Errorf(
			"%w: the checkpoint has no signature block", ErrInclusionProof)
	}
	lines := strings.Split(body, "\n")
	if len(lines) < 3 {
		return checkpoint{}, fmt.Errorf(
			"%w: the checkpoint has %d body lines, want at least origin, size and root",
			ErrInclusionProof, len(lines))
	}

	size, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil {
		return checkpoint{}, fmt.Errorf("%w: the checkpoint's tree size %q is not a number: %w",
			ErrInclusionProof, lines[1], err)
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return checkpoint{}, fmt.Errorf("%w: the checkpoint's root is not base64: %w",
			ErrInclusionProof, err)
	}
	if len(root) != sha256.Size {
		return checkpoint{}, fmt.Errorf("%w: the checkpoint's root is %d bytes, want %d",
			ErrInclusionProof, len(root), sha256.Size)
	}

	cp := checkpoint{
		origin:  lines[0],
		size:    size,
		rootHex: hex.EncodeToString(root),
		signed:  body + "\n",
	}
	for _, line := range strings.Split(signatures, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		blob, derr := base64.StdEncoding.DecodeString(fields[len(fields)-1])
		// A note may carry signatures from several keys, and one this build
		// cannot read is not a reason to reject a checkpoint that also carries
		// one it can. The requirement is that *a* signature verifies.
		if derr != nil || len(blob) <= 4 {
			continue
		}
		cp.signatures = append(cp.signatures, blob[4:])
	}
	if len(cp.signatures) == 0 {
		return checkpoint{}, fmt.Errorf("%w: the checkpoint carries no readable signature",
			ErrInclusionProof)
	}
	return cp, nil
}

// verifySignature checks the note under the log's key.
func (c checkpoint) verifySignature(logKey *ecdsa.PublicKey) error {
	digest := sha256.Sum256([]byte(c.signed))
	for _, sig := range c.signatures {
		if ecdsa.VerifyASN1(logKey, digest[:], sig) {
			return nil
		}
	}
	return fmt.Errorf(
		"%w: no signature on the checkpoint from %q verifies under the log's key",
		ErrInclusionProof, c.origin)
}

// TransparencyLog is the third party a sealed root is anchored in.
type TransparencyLog interface {
	// AnchorRoot submits a `sha256:`-prefixed Merkle root and returns the
	// entry. Submitting a root already in the log returns that entry.
	AnchorRoot(ctx context.Context, merkleRoot string) (Anchor, error)
	// InclusionProof returns the log's proof that an entry is in it.
	InclusionProof(ctx context.Context, entryUUID string) (InclusionProof, error)
}

// RetryPolicy is the bounded retry one anchoring attempt runs under.
//
// Bounded, not endless: the point of retrying is to ride out a blip, and the
// point of stopping is that a log which has been down for the whole budget is
// an operator's problem and needs to become an alert rather than a busy loop.
type RetryPolicy struct {
	// Attempts is the total number of submissions, including the first.
	Attempts int
	// Base is the wait after the first failure.
	Base time.Duration
	// Max caps the wait.
	Max time.Duration
	// Multiplier grows the wait; below 1 it is treated as the default 2.
	Multiplier float64
}

const (
	defaultAnchorAttempts   = 5
	defaultAnchorBase       = time.Second
	defaultAnchorMax        = 5 * time.Minute
	defaultAnchorMultiplier = 2.0
	// defaultAnchorBound is the lag past which the heartbeat goes amber when
	// no bound is configured (FD §3.1).
	defaultAnchorBound = 15 * time.Minute
)

func (p RetryPolicy) withDefaults() RetryPolicy {
	if p.Attempts < 1 {
		p.Attempts = defaultAnchorAttempts
	}
	if p.Base <= 0 {
		p.Base = defaultAnchorBase
	}
	if p.Multiplier < 1 {
		p.Multiplier = defaultAnchorMultiplier
	}
	if p.Max <= 0 {
		p.Max = defaultAnchorMax
	}
	if p.Max < p.Base {
		p.Max = p.Base
	}
	return p
}

// Backoff returns the wait after a 1-based attempt number.
func (p RetryPolicy) Backoff(attempt int) time.Duration {
	p = p.withDefaults()
	if attempt < 1 {
		attempt = 1
	}
	wait := float64(p.Base)
	for range attempt - 1 {
		wait *= p.Multiplier
		if wait >= float64(p.Max) {
			return p.Max
		}
	}
	if wait >= float64(p.Max) {
		return p.Max
	}
	return time.Duration(wait)
}

// LagSnapshot is the anchoring heartbeat FD §3.1 renders.
//
// A value and the moment it was read, not a health boolean: the header says
// "Ledger segment N anchored M min ago" and turns amber past the bound, and
// neither the number nor the amber can be derived from a yes/no.
type LagSnapshot struct {
	// ObservedAt is when this reading was taken.
	ObservedAt time.Time `json:"observed_at"`
	// Anchored reports that every sealed segment submitted so far is in the
	// log. It is a summary of the numbers below, never a substitute for them.
	Anchored bool `json:"anchored"`
	// SegmentID, FirstPosition and LastPosition name the furthest-along
	// segment that is anchored — the "segment N" of the heartbeat. Segments
	// are identified to people by their position range, not by their
	// content-addressed id (ADR-0006).
	SegmentID     string `json:"segment_id,omitempty"`
	FirstPosition int64  `json:"first_position,omitempty"`
	LastPosition  int64  `json:"last_position,omitempty"`
	// AnchoredAt is when that segment was anchored.
	AnchoredAt time.Time `json:"anchored_at,omitzero"`
	// PendingSince is the seal time of the oldest segment still waiting.
	PendingSince time.Time `json:"pending_since,omitzero"`
	// PendingSegments is how many are waiting.
	PendingSegments int `json:"pending_segments"`
	// LagSeconds is how long public tamper-evidence has been behind: measured
	// from the oldest unanchored seal when anything is pending, and from the
	// last anchor when nothing is.
	LagSeconds float64 `json:"lag_seconds"`
	// BoundSeconds is the configured bound past which the header goes amber.
	BoundSeconds float64 `json:"bound_seconds"`
	// OverBound is LagSeconds past BoundSeconds.
	OverBound bool `json:"over_bound"`
	// Attempts is how many submissions the most recent anchoring made.
	Attempts int `json:"attempts"`
	// LastFailure is why the most recent anchoring failed, if it did.
	LastFailure string `json:"last_failure,omitempty"`
}

// Lag is LagSeconds as a duration.
func (s LagSnapshot) Lag() time.Duration {
	return time.Duration(s.LagSeconds * float64(time.Second))
}

// Bound is BoundSeconds as a duration.
func (s LagSnapshot) Bound() time.Duration {
	return time.Duration(s.BoundSeconds * float64(time.Second))
}

// pendingSegment is a sealed segment waiting for its anchor.
type pendingSegment struct {
	sealedAt time.Time
	first    int64
	last     int64
}

// anchoredSegmentState is the furthest-along segment known to be anchored.
type anchoredSegmentState struct {
	set        bool
	segmentID  string
	first      int64
	last       int64
	anchoredAt time.Time
}

// Anchorer anchors sealed segments and tracks how far behind the log is.
//
// Safe for concurrent use, and deliberately: the sealer submits an anchor and
// the dashboard reads the heartbeat, and neither may be made to wait for the
// other. Nothing here is on the append path.
type Anchorer struct {
	// Log is the transparency log. Required.
	Log TransparencyLog
	// Policy bounds the retry; the zero value is the documented default.
	Policy RetryPolicy
	// Bound is the lag past which the heartbeat goes amber.
	Bound time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Sleep waits out a backoff; nil means a context-aware sleep. Returning an
	// error abandons the retry.
	Sleep func(context.Context, time.Duration) error

	mu          sync.Mutex
	pending     map[string]pendingSegment
	anchored    anchoredSegmentState
	attempts    int
	lastFailure string
}

func (a *Anchorer) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now().UTC()
}

func (a *Anchorer) sleep(ctx context.Context, d time.Duration) error {
	if a.Sleep != nil {
		return a.Sleep(ctx, d)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (a *Anchorer) bound() time.Duration {
	if a.Bound > 0 {
		return a.Bound
	}
	return defaultAnchorBound
}

// segmentClaim is what a segment_sealed record says about its segment.
type segmentClaim struct {
	eventID    string
	segmentID  string
	merkleRoot string
	first      int64
	last       int64
	sealedAt   time.Time
}

// readSegmentClaim reads a segment_sealed record.
//
// claimString and claimInteger are object.go's readers, reused rather than
// rewritten: one definition of how a claim is read out of a record.
func readSegmentClaim(record event.Fields) (segmentClaim, error) {
	eventType, err := claimString(record, event.FieldEventType)
	if err != nil {
		return segmentClaim{}, err
	}
	if eventType != event.EventTypeSegmentSealed {
		return segmentClaim{}, fmt.Errorf("%w: anchoring a %s, not a %s",
			ErrAnchorMismatch, eventType, event.EventTypeSegmentSealed)
	}

	var claim segmentClaim
	if claim.eventID, err = claimString(record, event.FieldEventID); err != nil {
		return segmentClaim{}, err
	}
	if claim.segmentID, err = claimString(record, event.FieldSegmentID); err != nil {
		return segmentClaim{}, err
	}
	if claim.merkleRoot, err = claimString(record, event.FieldSegmentMerkleRoot); err != nil {
		return segmentClaim{}, err
	}
	if claim.first, err = claimInteger(record, event.FieldFirstPosition); err != nil {
		return segmentClaim{}, err
	}
	if claim.last, err = claimInteger(record, event.FieldLastPosition); err != nil {
		return segmentClaim{}, err
	}

	rawTS, err := claimString(record, event.FieldTS)
	if err != nil {
		return segmentClaim{}, err
	}
	ts, err := event.ParseTimestamp(rawTS)
	if err != nil {
		return segmentClaim{}, fmt.Errorf("%w: %s: %w", ErrAnchorMismatch, event.FieldTS, err)
	}
	claim.sealedAt = ts.Time()
	return claim, nil
}

// Anchor anchors one sealed segment, retrying with backoff.
//
// The segment is registered as pending the moment it is submitted and stays
// pending until an anchor comes back, so the lag keeps growing through an
// outage instead of freezing at the last attempt. A failure returns an error;
// it does not panic, it does not block, and it leaves nothing locked — the
// caller's next seal proceeds regardless, which is the whole of IP §6.4's
// "appends to the next segment continue".
func (a *Anchorer) Anchor(ctx context.Context, sealed event.Fields) (Anchor, error) {
	if a.Log == nil {
		return Anchor{}, fmt.Errorf("%w: no transparency log configured", ErrAnchorUnavailable)
	}
	claim, err := readSegmentClaim(sealed)
	if err != nil {
		return Anchor{}, err
	}

	a.beginAttempts(claim)

	policy := a.Policy.withDefaults()
	var last error
	for attempt := 1; attempt <= policy.Attempts; attempt++ {
		anchor, aerr := a.Log.AnchorRoot(ctx, claim.merkleRoot)
		a.countAttempt()

		switch {
		case aerr == nil:
			if anchor.MerkleRoot != claim.merkleRoot {
				failure := fmt.Errorf("%w: the log entry is for root %s, the segment's is %s",
					ErrAnchorMismatch, anchor.MerkleRoot, claim.merkleRoot)
				a.recordFailure(failure)
				return Anchor{}, failure
			}
			anchor.SegmentID = claim.segmentID
			a.recordSuccess(claim)
			return anchor, nil

		case errors.Is(aerr, context.Canceled), errors.Is(aerr, context.DeadlineExceeded):
			// The caller withdrew, or ran out of time. Not the log's condition
			// and not something a retry can fix.
			a.recordFailure(aerr)
			return Anchor{}, aerr

		case errors.Is(aerr, ErrAnchorRejected), errors.Is(aerr, ErrAnchorSigner):
			// A refusal on the merits, or a key we cannot use. Waiting does
			// not make either of them true later.
			a.recordFailure(aerr)
			return Anchor{}, aerr
		}

		last = aerr
		if attempt == policy.Attempts {
			break
		}
		if serr := a.sleep(ctx, policy.Backoff(attempt)); serr != nil {
			wrapped := fmt.Errorf("anchoring segment %s abandoned during backoff: %w",
				claim.segmentID, serr)
			a.recordFailure(wrapped)
			return Anchor{}, wrapped
		}
	}

	failure := fmt.Errorf("anchoring segment %s gave up after %d attempts: %w",
		claim.segmentID, policy.Attempts, last)
	a.recordFailure(failure)
	return Anchor{}, failure
}

func (a *Anchorer) beginAttempts(claim segmentClaim) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending == nil {
		a.pending = map[string]pendingSegment{}
	}
	if _, already := a.pending[claim.segmentID]; !already {
		a.pending[claim.segmentID] = pendingSegment{
			sealedAt: claim.sealedAt, first: claim.first, last: claim.last,
		}
	}
	a.attempts = 0
	a.lastFailure = ""
}

func (a *Anchorer) countAttempt() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.attempts++
}

func (a *Anchorer) recordFailure(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastFailure = err.Error()
}

func (a *Anchorer) recordSuccess(claim segmentClaim) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.pending, claim.segmentID)
	a.lastFailure = ""
	// The heartbeat names the furthest-along anchored segment. Re-anchoring an
	// older one — which a resumed sealer does — must not walk the header back.
	if !a.anchored.set || claim.last > a.anchored.last {
		a.anchored = anchoredSegmentState{
			set:        true,
			segmentID:  claim.segmentID,
			first:      claim.first,
			last:       claim.last,
			anchoredAt: a.now(),
		}
	}
}

// Lag returns the anchoring heartbeat.
//
// It always returns a reading. FD §3.1: the heartbeat "is never hidden" — a
// system that cannot say how far behind it is has to say that too, rather than
// render nothing.
func (a *Anchorer) Lag() LagSnapshot {
	now := a.now()
	bound := a.bound()

	a.mu.Lock()
	defer a.mu.Unlock()

	snap := LagSnapshot{
		ObservedAt:      now,
		BoundSeconds:    bound.Seconds(),
		PendingSegments: len(a.pending),
		Attempts:        a.attempts,
		LastFailure:     a.lastFailure,
	}
	if a.anchored.set {
		snap.SegmentID = a.anchored.segmentID
		snap.FirstPosition = a.anchored.first
		snap.LastPosition = a.anchored.last
		snap.AnchoredAt = a.anchored.anchoredAt
	}

	var since time.Time
	switch {
	case len(a.pending) > 0:
		for _, p := range a.pending {
			if since.IsZero() || p.sealedAt.Before(since) {
				since = p.sealedAt
			}
		}
		snap.PendingSince = since
	case a.anchored.set:
		snap.Anchored = true
		since = a.anchored.anchoredAt
	default:
		// Nothing sealed, nothing anchored: no lag to report, and saying so is
		// not the same as claiming the log is current.
		return snap
	}

	if lag := now.Sub(since); lag > 0 {
		snap.LagSeconds = lag.Seconds()
	}
	snap.OverBound = snap.LagSeconds > bound.Seconds()
	return snap
}

// AnchorEvent builds the superseding segment_sealed body that attaches an
// anchor to an already-sealed segment (doc 02 §3).
//
// original is the segment_sealed record the ledger already holds. It is read
// for the four members that describe the segment and for nothing else: it is
// not modified, not re-hashed and not replaced (I4). The body returned carries
// no `supersedes` — ledger.Correct sets that from the record it is given, and
// two places writing one member is one place too many.
func AnchorEvent(m EventMeta, original event.Fields, anchor Anchor) (event.Fields, error) {
	claim, err := readSegmentClaim(original)
	if err != nil {
		return nil, err
	}
	if anchor.MerkleRoot != claim.merkleRoot {
		return nil, fmt.Errorf(
			"%w: the anchor is for root %s, segment %s has root %s",
			ErrAnchorMismatch, anchor.MerkleRoot, claim.segmentID, claim.merkleRoot)
	}
	if anchor.SegmentID != "" && anchor.SegmentID != claim.segmentID {
		return nil, fmt.Errorf("%w: the anchor names segment %s, the event names %s",
			ErrAnchorMismatch, anchor.SegmentID, claim.segmentID)
	}
	if anchor.EntryUUID == "" {
		return nil, fmt.Errorf("%w: the anchor has no %s",
			ErrAnchorMismatch, event.FieldAnchorRekorEntryUUID)
	}
	// doc 02 §5 bounds a reference member. The ledger would refuse the append
	// anyway; refusing here says which value was wrong, at the point where the
	// anchor is still in hand.
	if len(anchor.EntryUUID) > event.MaxReferenceBytes {
		return nil, fmt.Errorf("%w: %s is %d bytes, the schema bounds it at %d",
			ErrAnchorMismatch, event.FieldAnchorRekorEntryUUID,
			len(anchor.EntryUUID), event.MaxReferenceBytes)
	}
	if anchor.LogIndex < 0 {
		return nil, fmt.Errorf("%w: %s is %d",
			ErrAnchorMismatch, event.FieldAnchorRekorLogIndex, anchor.LogIndex)
	}

	if err := event.ValidateEventID(m.EventID); err != nil {
		return nil, fmt.Errorf("%s: %w", event.FieldEventID, err)
	}
	if m.TS.IsZero() {
		return nil, fmt.Errorf("%s is required and is assigned by the server (doc 02 §2)", event.FieldTS)
	}
	source := m.Source
	if source == "" {
		source = event.SourceSystem
	}
	if err := event.ValidateSource(source); err != nil {
		return nil, err
	}

	body := event.Fields{
		event.FieldSchemaVersion:        event.SchemaVersion,
		event.FieldEventID:              m.EventID,
		event.FieldEventType:            event.EventTypeSegmentSealed,
		event.FieldTS:                   m.TS.String(),
		event.FieldSource:               source,
		event.FieldSegmentID:            claim.segmentID,
		event.FieldSegmentMerkleRoot:    claim.merkleRoot,
		event.FieldFirstPosition:        claim.first,
		event.FieldLastPosition:         claim.last,
		event.FieldAnchorRekorLogIndex:  anchor.LogIndex,
		event.FieldAnchorRekorEntryUUID: anchor.EntryUUID,
	}
	// The value domain, which is all a body can be checked against: doc 02 §2's
	// chain_position and prev_event_hash are the ledger's to assign, and
	// event.ValidateEvent runs against the finished record at append.
	if err := body.Validate(); err != nil {
		return nil, err
	}
	return body, nil
}

// AnchorAlert builds the alert a segment that could not be anchored raises.
//
// The schema is closed (doc 02 §1) and holds exactly one alert for this
// condition: `ledger_drift_detected`, "a ledger claim with no external proof".
// A sealed segment whose anchoring budget is spent is precisely that — the
// ledger says a segment was sealed and nothing outside the ledger can be shown
// to agree. It is raised when the retries are exhausted rather than on the
// first failure, because a segment anchored on the second attempt was never a
// claim without a proof, and an alert that fires on every blip is one nobody
// reads.
func AnchorAlert(m AlertMeta, original event.Fields, cause error) (event.Fields, error) {
	if cause == nil {
		return nil, errors.New("anchoring alert without a cause")
	}
	claim, err := readSegmentClaim(original)
	if err != nil {
		return nil, err
	}
	if m.SubjectEventID != "" && m.SubjectEventID != claim.eventID {
		return nil, fmt.Errorf(
			"%w: the alert names subject %s, the sealed event is %s",
			ErrAnchorMismatch, m.SubjectEventID, claim.eventID)
	}
	m.SubjectEventID = claim.eventID
	if m.Source == "" {
		// The sealer emits it, and doc 02 §3 marks segment_sealed `system`.
		m.Source = event.SourceSystem
	}

	return DriftEvent(m, fmt.Errorf(
		"segment %s (positions %d..%d) is sealed but has no transparency log entry: %w",
		claim.segmentID, claim.first, claim.last, cause))
}
