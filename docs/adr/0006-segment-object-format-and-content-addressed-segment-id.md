# ADR-0006: Address a sealed segment by the digest of its object, and make that digest its `segment_id`

- Status: accepted
- Date: 2026-08-28
- Deciders: Mike

## Context

Doc 02 fixes two things about a sealed segment and leaves a third open.

It fixes the Merkle construction (§4.6): leaves are the raw `event_hash` bytes
in position order, prefixed `SHA-256(0x00 ‖ leaf)`, interior nodes
`SHA-256(0x01 ‖ left ‖ right)`, an odd node promoted unchanged, root rendered as
`sha256:`-prefixed hex. It fixes the four members the ledger records about the
segment (§3): `segment_id`, `segment_merkle_root`, `first_position`,
`last_position`, plus two anchoring members that arrive later in a superseding
event.

It does not fix the bytes of the object those members describe. The only
statement about it anywhere is IP §1: segments are "content-addressed" and
"written to object storage with WORM/object-lock".

Two required tests presuppose a value the documents never name:

- **SEG-002** (IP §6.4): kill the sealer at every step boundary and re-run;
  "final segment hash identical to no-crash run".
- **SEG-006** (I4): tamper with a sealed segment object; "segment hash mismatch
  detected on read".

There is no "segment hash" in doc 02. It has to be defined somewhere, and the
choice determines whether SEG-006 is checkable from the ledger alone or only
against some other piece of state.

Three constraints narrow the options:

- **The schema is closed and protected.** Doc 02 §1 rejects unknown members at
  append; §7 makes any new member a major `schema_version` with a migration
  attestation. No member can be added to `segment_sealed` to carry an object
  digest.
- **I5: verification never trusts this system.** Whatever links the ledger's
  claim to the stored object must be usable by a third party with no access to
  our database.
- **I4: no record is deleted or mutated.** Once a `segment_sealed` event is
  appended, the id it names is permanent.

Golden fixture 11 carries `"segment_id":"seg-000001"`. That value is
illustrative — the schema constrains `segment_id` only as a bounded reference
(≤ 256 bytes, no grammar) — but it is committed, immutable, and shows the shape
the schema's author had in mind.

## Decision

**The segment object's content address is the segment hash, and that address is
the `segment_id` the ledger records.**

Concretely:

1. The segment object is a flat JSON object serialized with the *same* RFC 8785
   canonicalizer as events (`event.Canonicalize`), carrying
   `segment_format_version`, `event_hashes` (the leaves, in position order),
   `first_position`, `last_position` and `segment_merkle_root`.
2. The segment hash is `"sha256:" + hex(SHA-256(canonical object bytes))`,
   produced by the one digest construction in the system (doc 02 §4.3,
   `event.Digest`).
3. That segment hash is the object's storage key **and** the `segment_id` on the
   `segment_sealed` event. The object therefore does not carry its own id: a
   value cannot contain its own hash.
4. Sealing a segment with no events is refused. Doc 02 §4.6 defines no root for
   zero leaves, and this ADR does not invent one.

A reader with nothing but the ledger can therefore: take `segment_id`, fetch the
object under that name, hash it and see whether it is still the object the
ledger named (SEG-006); decode it, re-derive the root and compare with
`segment_merkle_root`; and prove any event's inclusion. No index, no second
source of truth, nothing of ours trusted (I5).

Sealing is idempotent because of this and not in addition to it: every step is a
pure function of the events, so a re-run after a crash recomputes the identical
bytes, finds them already at the identical address, and adopts them (SEG-002).

## Alternatives considered

**A. `segment_id` as a sequence number (`seg-000001`), object stored under that
name.** This is what golden fixture 11's value suggests. It loses because
nothing in the ledger then commits to the object's bytes: `first_position`,
`last_position` and `segment_format_version` are covered by no digest the ledger
holds, so editing them in storage is undetectable, and SEG-006's "segment hash
mismatch detected on read" has no recorded hash to compare against. Only the
leaves would be protected, and only indirectly through the root.

**B. `segment_id` as a sequence number, object stored under its content address,
with an id → address index.** The index is state outside the ledger that is
itself editable and unattested, and a third party without access to our database
cannot resolve an id through it — which is I5 exactly. It also reintroduces the
partial-failure window the content address removes: index and object can
disagree after a crash.

**C. Add a member to `segment_sealed` carrying the object digest.** The schema is
closed and protected; this is a major `schema_version` with new golden fixtures,
dual-version verifiers and a signed migration attestation (doc 02 §7) — for
something the existing `segment_id` already expresses.

**D. Leave `segment_merkle_root` out of the object and derive it on read.** The
root is derivable from the leaves, so carrying it is redundant against a
tampered object. It is not redundant against a *sealer bug*: an object whose
recorded root is not the root of its own leaves is caught on every read, and
without the recorded root there would be nothing to catch. The redundancy is the
check.

**E. Define a root for the empty segment.** Any value chosen (the digest of the
empty string, a fixed constant) would be a new protected constant that doc 02
does not contain, permanent from first use, and would make "a segment
containing no events" a representable and anchorable object. Refusing is the
only option that adds nothing to the protected surface.

## Consequences

**Easier.** SEG-006 is checkable from the ledger alone. Anchoring lands cleanly:
RM-012 attaches `anchor_rekor_log_index` and `anchor_rekor_entry_uuid` through a
*superseding* `segment_sealed` event carrying the same `segment_id` (doc 02 §3),
so anchoring never touches the object or its address, and the original event
stays byte-identical (I4). WORM is a natural fit: every name is a content
address, so the only legitimate second write of a name is a write of identical
bytes.

**Harder.** Segment ids are not human-legible and do not sort in seal order. The
dashboard identifies a segment by `first_position..last_position`, not by id.
Segments cannot be listed in order from the object store alone; the ledger's
`segment_sealed` events are the ordered index, which is where an append-only
system should keep one anyway.

**Now fixed.** The object format is a protected surface from the first sealed
segment: every id ever recorded is the digest of bytes in this exact form.
Changing the format changes every future id. It is therefore a bump of
`segment_format_version` with the old reader retained forever, never an edit —
old `segment_sealed` events are immutable (I4), so old objects can never be
re-sealed under a new format. Exit cost if this decision is reversed: readers
for both addressing schemes forever, plus a migration attestation, and every
already-anchored segment keeps its content-addressed id regardless.

**Divergence to note.** This implementation writes `segment_id` values of the
form `sha256:<64 hex>`, not `seg-000001`. Golden fixture 11 remains valid — the
schema permits both — and no fixture byte changes. A reader that assumed the
sequence-number shape would be assuming something the schema never guaranteed.

**Tests.** SEG-001, SEG-002 and SEG-006 in `internal/segment`. The Merkle roots
are pinned against a Python oracle written from doc 02 §4.6, together with the
roots of the two constructions §4.6 rules out, so a tree that duplicates the odd
node or drops the domain prefixes fails rather than producing a plausible root.
