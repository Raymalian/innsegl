# ADR-0007: Enforce the protected surfaces with a self-verifying gate, and define what it does before the first tag exists

- Status: accepted
- Date: 2026-08-28
- Deciders: Mike

## Context

`VERSIONING.md` names five protected surfaces and one enforcement clause:

> MINOR/PATCH releases MUST NOT alter any protected surface. CI enforces this:
> the golden fixtures (`TC-SER`) and the contract schemas are diffed against the
> previous tag; any drift fails the release.

Doc 08 §3 is the source of that clause; test catalog **SER-005** is the required
test — *"serializer version bump attempt without new version tag → build/test
fails; silent format change is impossible."* RM-013 (#21) is the issue that
builds it.

Four facts complicate a literal reading.

**There is no previous tag.** `git tag` returns nothing in this repository and
will keep returning nothing until v0.1.0 ships. A gate whose entire mechanism is
"diff against the previous tag" therefore has nothing to do on every run between
now and the first release — which is precisely the window in which the golden
fixtures, the serializer and the schema constants are being written. A gate that
passes vacuously for its whole formative period is the third vacuous pass this
project would have shipped.

**Two of the five surfaces have no code yet.** The MCP tools (RM-022..025) and
the commit trailers do not exist. Seven of the eleven error classes in IP §4 are
returned by nothing. A gate that demands the full vocabulary today fails honestly
built branches; a gate that demands nothing notices no rename.

**"Diff against the previous tag" does not say what counts as drift.** An added
golden fixture, an added MCP tool and a renamed field are all "the manifest
changed". They are not the same event.

**A MAJOR release may change these surfaces, so the gate must know which kind of
release it is looking at** — and doc 08 §3 is explicit that this must not be a
question a human answers at release time, because the answer is exactly what a
rushed release gets wrong.

Invariants in play. **I4** (append-only history; no record's bytes ever change)
is what makes the golden fixtures immutable rather than merely stable. **I5**
(verification never trusts this system) is why the fixtures — not any document —
are the normative definition of surface 1: a verifier re-derives bytes, it does
not read prose.

## Decision

**The gate is three parts, two of which need no baseline at all, and the tag
diff is the third rather than the whole.** `scripts/protected-surfaces.sh`:

- **A. The fixtures verify themselves.** In shell, independent of Go and of
  `verify.py`: the genesis constant is re-derived from `"innsegl-genesis-v1"`;
  every `<name>.hash` is recomputed from its own `<name>.canonical.json`; and the
  serializer format fingerprint frozen in `internal/event/canonical.go` is
  checked against `format-probe.hash`, which freezes the same value a second
  time.
- **B. The shipped source still speaks the protected vocabulary.** Every member
  name and enum value that appears in a committed golden fixture must appear
  verbatim as a string literal in `internal/`; the trailer keys, MCP tool names,
  SPIFFE grammar and namespace must be spelled the way `VERSIONING.md` spells
  them; and the gate's own copy of that vocabulary is checked against
  `VERSIONING.md` so a reworded policy fails the build until the gate is updated
  in the same change.
- **C. The manifest is diffed against the previous tag**, exactly as the policy
  says, when there is one.

**No previous tag is a defined, announced, passing state.** Part C prints a
`FIRST RUN` block naming the missing baseline and the surfaces it *will* diff at
the next tag, emits a CI warning annotation, and passes. Parts A and B still run
as hard gates, so a rename of a protected string fails the build today, with no
tag in the repository. This is the substance of the decision: the first-run case
is not a hole, because the checks that do not need a baseline are the ones that
catch the failure the baseline diff was there to catch.

**The release kind is derived from the tags, never declared.** The candidate
version is the pushed tag (`GITHUB_REF_TYPE=tag`) or an explicit argument; the
baseline is the newest `v*.*.*` tag reachable from HEAD other than the candidate.
A release is MAJOR when the candidate's MAJOR component exceeds the baseline's,
and MINOR/PATCH otherwise. **A working tree with no candidate version is held to
the MINOR/PATCH rule**: an unreleased branch cannot license drift by saying
nothing.

Pre-1.0 follows the same rule and is not special-cased. `VERSIONING.md`'s Pre-1.0
section says a `0.x` minor bump "may never break a protected surface; that
requires the major-release procedure above, taken early" — so `v0.1.0 → v0.2.0`
is not a MAJOR release for this gate's purposes, and only a bump to `v1.0.0`
licenses a protected change.

**Change classification.** Removals and modifications fail a MINOR/PATCH
release. Additions do not: adding a fixture, a tool name or an error class
extends a surface without altering what was released, and a *rename* appears as a
removal plus an addition, so the removal half still fails. **Golden-fixture
modifications and deletions fail every release, MAJOR included** — doc 08 §3(b)
requires the old version's fixtures "retained and still asserted", and I4 forbids
changing bytes already written. A new schema version adds a fixture directory; it
never edits the existing one. A MAJOR release that does move a protected surface
must additionally add a file under `docs/adr/` in the same release (doc 08
§3(d)), which the gate checks.

**Only the vectors are immutable, not everything filed beside them.** The fixture
tree also holds a `README.md` and the `verify.py` oracle. `VERSIONING.md` protects
"the golden serialization fixtures" and "the contract schemas", not the prose next
to them, so those two are tracked separately: a change to them is reported in the
release log and never fatal. A patch release must be able to fix a typo or add a
check to the oracle.

**Vocabulary sets that land together are held together.** The trailer keys and
the MCP tool names are all-or-nothing: if any member is present in the shipped
source and another is not, that is a rename and it fails. The error classes are
not, because the tools that return most of them are not built; their presence is
recorded in the manifest so that a later present→absent transition fails the tag
diff.

## Alternatives considered

- **Skip the whole gate until a tag exists.** Rejected: the formative window is
  when the fixtures and the serializer constants are actually being written, and
  it is the window with no baseline. That is the interval in which a silent
  format change is most likely and least likely to be noticed.
- **Fail the build when there is no previous tag.** Rejected: it makes every
  pre-release commit red, which trains people to ignore the gate — and the gate's
  whole value is that a red run means something. A red gate that is always red is
  a disabled gate with extra steps.
- **Have a human declare the release kind (a `RELEASE_KIND` variable, a label, a
  file).** Rejected because doc 08 §3 puts the burden on CI precisely so that a
  release under time pressure cannot mislabel itself. A declaration is a field a
  tired releaser fills in wrongly; the tags are what actually ship.
- **Diff `docs/02-innsegl-event-schema.md` instead.** Not possible and not
  desirable: doc 02 is local-only and never reaches the repository CI reads, and
  `VERSIONING.md` already settles the precedence — *"Where a document and a
  fixture disagree, the fixture wins, because the fixture is what verifiers
  actually re-derive."*
- **Treat any manifest change, additions included, as drift.** Rejected: it
  blocks a new golden fixture for an existing schema version and a new MCP tool
  in a minor release, neither of which alters anything already released. Renames
  are still caught, through the removal half.
- **Let a MAJOR release change golden fixtures in place.** Rejected: it
  contradicts doc 08 §3(b) and I4 directly. "Verification of old records is
  supported forever, without exception" is unimplementable if the vectors those
  records were verified against can be edited.
- **Enforce the branch of the vocabulary in Go tests instead of a shell gate.**
  Go tests already pin the fixtures from inside the module (`TestSER001`,
  `VerifyFormat`), and they are necessary but not sufficient: they cannot see the
  previous tag, and they are written by the same change that would rename a
  constant. The gate re-derives the same facts from the committed bytes with a
  different tool, which is the I5 posture applied to the project's own CI.

## Consequences

- A protected-string rename fails CI today, before any release exists. That is
  new: until now the fixtures were pinned only from inside the Go module.
- Rewording `VERSIONING.md`'s list of protected strings fails the build until
  `scripts/protected-surfaces.sh` is updated in the same change. Deliberate: the
  policy and its enforcement move together or not at all.
- The error-class vocabulary is transcribed into the gate from IP §4, which is a
  local-only document. **The gate script is therefore the only shipped
  enumeration of that vocabulary.** `VERSIONING.md` protects "the `error_class`
  values they return" without listing them, so a public contributor cannot
  discover the list from the repository. This is a real gap and is left flagged
  rather than resolved: publishing the list belongs with the MCP tool work
  (RM-022..025), which is where the values acquire shipped definitions.
- The first release becomes the moment part C starts working, with no change to
  the script. Whoever cuts `v0.1.0` should confirm the next run's log shows a
  baseline rather than `FIRST RUN`.
- Reversing this costs one workflow file and two scripts; nothing outside
  `.github/workflows/protected-surfaces.yml` and `scripts/protected-surfaces*.sh`
  depends on it. The fixtures and constants it guards are untouched by it.
