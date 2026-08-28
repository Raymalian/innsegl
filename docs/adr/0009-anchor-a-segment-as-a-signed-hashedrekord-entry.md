# ADR-0009: Anchor a sealed segment as a signed `hashedrekord` entry, verify it from first principles, and accept at-least-once anchoring

- Status: accepted
- Date: 2026-08-28
- Deciders: Mike

## Context

Doc 02 §3 says what the ledger records about an anchor — `anchor_rekor_log_index`
and `anchor_rekor_entry_uuid`, arriving on a superseding `segment_sealed` event
— and doc 01 §6.4 says what happens when anchoring fails. Neither says what the
Rekor entry *is*. Rekor has eleven entry types; every one of them requires a
signature; and the choice of type fixes, permanently, what a reader ten years
from now has to fetch and parse to check an anchor recorded today.

Three constraints narrow it.

**I5: verification never trusts this system.** "Every attribution claim must be
checkable against Fulcio/Rekor by a third party with no access to our database."
An anchor is only worth something if somebody who distrusts us can check it, and
they must be able to do that with the ledger's two recorded members and a public
log endpoint.

**The event schema is closed and protected.** Doc 02 §1 rejects unknown members
at append and §7 makes any new member a major `schema_version` with a migration
attestation. There is no room for a member naming the entry kind, and no room
for a new event type to carry an anchoring alert.

**Anchoring must not be able to hurt the ledger.** Doc 01 §6.4: an anchoring
failure is "a monitored, bounded degradation — it delays public tamper-evidence,
it does not lose or weaken records". Whatever is built here has to be able to
fail without taking the append path with it.

There is also an infrastructure fact. SEG-003 is an integration case and doc 01
§2 forbids proving it against a mock, but RM-030 — the compose Sigstore stack —
lands in E5, after this work. A real Rekor had to be stood up here.

## Decision

**Three decisions, taken together.**

**1. One signed `hashedrekord` v0.0.1 entry per sealed segment.** Its
`spec.data.hash` is the segment's `segment_merkle_root` — `sha256`, the hex of
the same 32 bytes the ledger records — and its `spec.signature` is an ASN.1
ECDSA signature over those bytes under the ledger's anchoring key, with the
verifying key inline as PEM. The key is P-256 and only P-256: the digest is
always a SHA-256 root, and Rekor pairs each curve with a matching hash, so a
P-384 key would be checked against a SHA-384 digest this system never produces.

**2. An anchor is verified from first principles against a pinned log key.**
Nothing Rekor asserts *about* a proof is taken on trust. The entry body is
re-hashed and must be the leaf its uuid names; the inclusion path is walked to a
root under RFC 6962's rules, with the path length derived from index and tree
size rather than read from the proof; the checkpoint must be over the same size
and root; and the checkpoint's signature must verify under the log's key. Only
the last step trusts anything, and what it trusts is a key. The client is
hand-written over the documented REST shapes rather than Rekor's generated Go
client.

**3. Anchoring is at-least-once, not idempotent.** ECDSA nonces are random, so
two submissions of one root are two different entry bodies and Rekor stores
both. A submission that succeeds at the log but times out at the client
therefore leaves an entry the caller never learned the id of, and the retry adds
a second. This is accepted rather than engineered away.

Two consequences of the closed schema follow, and are recorded here because they
are decisions, not deductions:

- **The alert is `ledger_drift_detected`.** Doc 02 §3 defines it as "a ledger
  claim with no external proof", which is exactly a sealed segment whose
  anchoring budget is spent. It is raised on exhaustion of the retries, not on
  the first failure: a segment anchored on the second attempt was never a claim
  without a proof, and an alert that fires on every blip is one nobody reads.
- **The anchoring lag is a value with a timestamp, never a health boolean.**
  FD §3.1 renders "Ledger segment N anchored M min ago" and turns the header
  amber past a configured bound, and neither the number nor the amber can be
  derived from a yes/no. `Anchorer.Lag()` returns a reading whenever it is
  asked, including before anything has been sealed — FD §3.1 says the heartbeat
  "is never hidden", and a system that cannot say how far behind it is has to
  say that too.

## Alternatives considered

**A. An `intoto` or `dsse` entry.** Both carry an attestation envelope with a
predicate, and we would have to invent and version a predicate type for "this
Merkle root was sealed at this range". The claim is one digest; wrapping it in
an attestation format adds a schema of our own inside a log entry, which is one
more thing to keep compatible forever and one more thing a third-party verifier
must be taught to read.

**B. A `rekord` entry carrying the segment object inline.** Rekor would then
hold the leaves themselves, which reads as an attractive "the log has
everything". It loses on two counts. The public metadata exposure the threat
model §5.2 and ADR-0002 already flag as the cost of public Sigstore would go
from "SPIFFE IDs, repos and timing" to the ledger's entire event-hash stream.
And segment objects have no useful size bound, while log entries do.

**C. An anonymous anchor — the root with no signature.** Not available: every
Rekor entry type verifies a signature before acceptance. It also loses on the
merits. An unsigned digest in the log says somebody posted 32 bytes; a signed
one says *this key* asserted this root at this time, which is what makes an
anchor an attribution rather than a coincidence.

**D. Import `github.com/sigstore/rekor/pkg/client` and the generated
go-swagger client.** It would be less code here. It drags a large dependency
tree into a module whose entire dependency set is currently five entries, for
four HTTP requests. More importantly it works against I5's spirit: a verifier
that can only be built by importing our vendor tree is a verifier nobody outside
this project will build, and the point of the anchor is that outsiders check it.
What the client speaks is the documented wire format, which is what a stranger
would have to speak too.

**E. Trust Rekor's `rootHash` and `logIndex` fields and check nothing.** This is
the default behaviour of most Rekor clients and it is coherent for a caller who
already trusts the log operator. It is incoherent here: the anchor exists
because the ledger's operator is not trusted, and a proof checked only against
the responding server's own arithmetic is satisfied by any server that controls
the response.

**F. Deduplicate anchors by searching the log before each submission.** Rekor's
`searchIndex` can find an entry by data hash, so a pre-flight search would make
anchoring idempotent. It loses on cost and on durability: it is an extra
round trip on the happy path of every anchor, and it depends on the search-index
API that Sigstore has been signalling away from. What it buys is log tidiness —
the duplicate entries are equivalent, attest the same root under the same key
seconds apart, and the ledger records exactly one of them.

**G. Make submissions byte-identical with deterministic ECDSA (RFC 6979), so a
duplicate submission is a 409 the client can adopt.** Go's standard library
exposes no deterministic ECDSA signing API, and hand-writing deterministic
nonce derivation is precisely the category of cryptography this project must not
write itself. Reaching for a third-party signing library to fix log tidiness
inverts the cost of alternative D.

**H. Add an event type for "anchoring failed".** Doc 02 §7 makes a new
`event_type` a major `schema_version` with new golden fixtures, dual-version
verifiers and a signed migration attestation — for a condition the existing
`ledger_drift_detected` describes exactly.

**I. Alert on the first anchoring failure rather than on exhaustion.** It is
louder and it is worse. Transient unavailability is the expected case doc 01
§6.4 designs the retry for; an alert per blip is an alert channel nobody reads
by the time a real one arrives. The lag is visible continuously in the
heartbeat, so nothing is hidden between the first failure and the alert.

## Consequences

**Easier.** A third party checks an anchor with the two members the ledger
records and nothing else: fetch the entry by uuid, re-derive the leaf, walk the
proof, check the checkpoint signature against the log's published key, and
compare the entry's data hash with the `segment_merkle_root` in the
`segment_sealed` event. Combined with ADR-0006 — where the `segment_id` is the
object's content address — a reader can go from a ledger event to a verified
public anchor without asking this system for anything.

**Harder.** The ledger now has a signing key of its own, distinct from the
per-run Fulcio identities: it must be provisioned, rotated and protected like
any other (doc 04 §7, doc 05 §2). Rotation is survivable but not free — anchors
signed under an old key stay verifiable, so the set of keys a verifier must
accept grows with each rotation and has to be published.

**Now effectively protected.** The entry kind, its api version, and the meaning
of `spec.data.hash` are a wire format that every anchor ever written depends on.
They are not in doc 02's protected-strings list because doc 02 does not know
about them; they behave like protected strings all the same, and changing one
means writing a reader for both forms and keeping it forever.

**Accepted cost.** Duplicate log entries after an ambiguous retry. Bounded by
the retry budget, a few hundred bytes each, referenced by nothing.

**Test infrastructure, and a note for RM-030 (#38).** SEG-003 runs against a
real Rekor stood up in containers by
`internal/segment/rekorharness_test.go`: MySQL carrying Trillian's schema, the
Trillian log server, the Trillian log *signer* — without which leaves are
queued and never integrated, so no inclusion proof would ever exist — Redis for
Rekor's search index, and Rekor itself. That is upstream Rekor's own compose
topology, which is what doc 05 §1 anticipates: "Rekor's storage dependencies run
as sidecars per upstream's own compose reference; pin versions." Every image is
pinned by tag and overridable by environment variable. The harness is
self-contained so RM-030 can lift the topology into `deploy/compose/` rather
than rediscover it. It defines no `TestMain`: a package gets one, and this
package is shared with the WORM writer, so the single test that needs the log
owns it through `t.Cleanup` and its subtests share it. Without Docker, SEG-003
skips with a message naming what went unproven.

**Exit cost if reversed.** Changing the entry type means every anchor written
under this ADR keeps its `hashedrekord` form permanently — `segment_sealed`
events are immutable (I4) — so the verifier carries both readers forever. The
verification code is reusable across entry types; the anchoring key and its
published history are not disposable.

## Open item — for the human, not for an implementing agent

Doc 02 §3's "Emitted by" column gives `ledger_drift_detected` as `reconciler`.
The component that discovers an anchoring failure is the **sealer**
(`innsegl-sealer`, doc 05 §1), and doc 02 §3 marks `segment_sealed` — the
sealer's other output — as `system`. `AnchorAlert` therefore defaults `source`
to `system` and lets the caller override it, because labelling a sealer-observed
failure `reconciler` would name a component that did not observe it. Nothing in
doc 02 §2 or the validator restricts `source` by event type, so both are
appendable. Which value doc 02 intends is a question for the human.
