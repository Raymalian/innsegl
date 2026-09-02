# ADR-0040: Close doc 04's open abuse cases against tests that exist, assign REL-001 to release signing, and pin the framework mappings to documents fetched on the review date

- Status: accepted
- Date: 2026-09-02
- Deciders: Mike

## Context

IP Phase 5 requires a threat-model review. The living threat model (doc 04) is
one of the eight numbered specifications, and those are local to the working
copy — `.gitignore` carries `docs/*` with `!docs/adr/`, so `docs/adr/` is the
only part of `docs/` that reaches the public repository. A review that lands
only in doc 04 is a review nobody outside the project can read. This ADR is
therefore the review artifact: the shipped record of what doc 04 claims, what
of it is actually true in this repository today, and what is not.

doc 04 §6 names the standing triggers for re-running the model. Two of them
have fired since it was written — MCP tools were added (E4), and the shipped
Sigstore default changed (ADR-0010) — and doc 04 itself carries three explicit
holes, marked in its own text:

- §2, SPIRE deployment, tampering row: "extends REC drift model to SPIRE —
  **open: add test ID**".
- §2, supply chain: "**Open: add release-signing test/CI check ID.**"
- §3, abuse cases AB-11 and AB-12: covering test cited as "**open — add TC**"
  and "**open — CI check**".

This ADR closes those, and it does not amend doc 04. Doc 04 is normative; a
review reports on a specification, it does not rewrite one. Everything below
that doc 04 should say is stated here as a recommendation, and the rows doc 04
must eventually carry are listed in §"What doc 04 and doc 07 must be given".

### The rule this review is held to

The failure mode of a threat-model review is a table of green cells that name
tests nobody ran. This project treats a confident wrong citation as worse than
an admitted gap, because a wrongly-green control is exactly the thing Innsegl
exists to make impossible elsewhere (A4, the verification claim itself).

So every ID in the table below was checked two ways: against doc 07, the
catalogue, and against the source tree, which is the only place a test actually
exists. Those two disagree. Sixty-six test IDs are written and running in this
repository that doc 07 does not list — the whole `FE-016`…`FE-107` range from
E6, plus `OPS-005`, `OPS-006` and `SPI-008` — and no ID in doc 07 is missing
from the source. Absence from the catalogue is therefore not evidence that a
test is absent, and presence in the catalogue is not evidence that one exists.
Each row below says which of the two it was verified against.

Framework IDs were fetched, not recalled, for the same reason. The MAESTRO
layer numbering and the OWASP threat identifiers are both things a model will
produce fluently and wrongly. §"Framework mapping, pinned" records the document,
the version, the publication date and the date it was read, and it records
plainly the one identifier this review could not reach a primary source for.

## Decision

1. **AB-11 closes against SPI-008**, which exists in code and not in doc 07.
2. **AB-12 closes partially against SER-005**, which exists and covers doc 04's
   "review gates on protected strings". Its other half, "signed instruction
   files", is recorded as **unimplementable in this repository as written**, and
   the checkable threat behind it is assigned proposed **REL-002**.
3. **Release signing takes REL-001**, in a proposed new catalogue family
   `TC-REL`. §"REL-001" states what the check must do to earn the ID. RM-056
   (#64) is implementing the workflow in parallel with this review and will name
   whatever it built independently; if the two names differ, the reconciliation
   is a rename, not a redesign, because the obligations below are the ID.
4. **AB-09 closes partially against SER-005** for the half that lives in this
   repository, with proposed **REL-003** for the registry half.
5. **No abuse case is left without a covering ID**, and every ID is marked
   *verified* or *proposed*. Nothing is marked verified on the strength of doc
   04 or doc 07 alone.

## The abuse-case table, and what each citation was verified against

`verified` means a test function or gate was found in the source tree and named
here. `in doc 07` means the catalogue also carries the row. `proposed` means the
test does not exist and this ADR is asking for it.

| AB | Attacker story | Control | Covering ID | Status | Where it is |
|---|---|---|---|---|---|
| AB-01 | Rogue process claims to be agent run-42 | Attestation selectors | SPI-002 | verified; in doc 07 | `internal/spire/attestation_test.go`, `internal/spire/spireharness_test.go` |
| AB-02 | Operator quietly deletes an embarrassing run | No delete surface; chain break; WORM; anchor mismatch | LED-003, LED-005, LED-006, SEG-005, SEG-006 | verified; in doc 07 | `internal/ledger/postgres_test.go`, `internal/ledger/property_test.go`, `internal/segment/worm_test.go`, `internal/segment/tamper_test.go` |
| AB-03 | Compromised MCP fabricates `commit_recorded` | No Rekor entry exists; drift detection | REC-004 | verified; in doc 07 | `internal/reconciler/drift_test.go`, `internal/reconciler/driftintegration_test.go` |
| AB-04 | Compromised agent signs outside its purpose | Audience allowlist; one-run identity; retirement | MCP-008, MCP-014, SPI-004 | verified; in doc 07 | `internal/mcp/get_credential_test.go` (`TestMCP014CredentialFromRunAUsedForRunB`), `internal/spire/ledgerharness_test.go` |
| AB-05 | Fake `Agent-Identity` trailer pasted by a human | Check 3, cert-vs-trailer match | VER-002 | verified; in doc 07 | `internal/verify/verifyintegration_test.go` |
| AB-06 | Rebase agent commits to detach attribution | Signature breaks; flagged unverified | VER-003 | verified; in doc 07 | `internal/verify/verifyintegration_test.go`, `TestVER003ASquashedCommitFailsAndTheOriginalIsStillResolvable` |
| AB-07 | Flood `register_agent` | Rate limit + alert | MCP-013 | verified; in doc 07 | `internal/mcp/ratelimit_test.go`, `internal/mcp/ratelimit.go` |
| AB-08 | Show a stale cached "verified" to an auditor | Tri-state honesty in UI and CLI | FE-003, FE-007 | verified; in doc 07 | `web/src/components/verification/rollup.test.ts`, `VerificationPanel.test.tsx`, `web/src/views/public-verify/` |
| AB-09 | Typosquat `innsegl` on npm/PyPI | Placeholder registrations; docs point at canonical names | SER-005 (in-repo half) | verified; in doc 07 | `scripts/protected-surfaces.sh` part B, VERSIONING.md surface 5 |
| | | Registry registrations themselves | **REL-003** | **proposed** | does not exist; RM-059 (#67) is open |
| AB-10 | Steal the MCP admin credential, mint outside the agent subtree | SPIRE authorization scope | SPI-005 | verified; in doc 07 | `internal/spire/authz_test.go` |
| | | Detection of the deletion half, which cannot be authorized (ADR-0012) | SPI-008 | verified; **not in doc 07** | `internal/spire/reconcile_test.go`, direction two |
| AB-11 | Tamper with SPIRE entries directly to widen a run's identity | Entry reconciliation + alert | **SPI-008** | verified; **not in doc 07** | `internal/spire/reconcile.go`, `internal/spire/reconcile_test.go`; ADR-0013 |
| AB-12 | Poison the coding agent building Innsegl | Review gates on protected strings | **SER-005** | verified; in doc 07 | `scripts/protected-surfaces.sh` parts A/B, `scripts/protected-surfaces-selftest.sh`, `.github/workflows/protected-surfaces.yml`; ADR-0007 |
| | | "Signed instruction files" | — | **unimplementable as written**; see below | nothing to sign is tracked |
| | | The toolchain half that *is* checkable | **REL-002** | **proposed** | does not exist |

### AB-11 — why SPI-008 is the right closure and not a rubber stamp

`internal/spire/reconcile.go` implements exactly the mechanism doc 04 §2 names:
expected entries derived from the ledger (`run_registered` open until
`run_retired` or `run_expired`), actual entries read from the SPIRE server's own
datastore, compared inside the `spiffe://{td}/agent/` subtree, with drift
recorded as `ledger_drift_detected` (ADR-0013).

Two properties make the citation load-bearing rather than decorative.

**It plants the attack the way the attacker would.** `SPI-008` creates its
unexplained entry on SPIRE's unauthenticated local admin socket — the socket
ADR-0011 records as contained by mount and network, never by authorization —
with `unix:uid:0`, the weak selector doc 04 names in the same paragraph. That is
AB-11's threat model executed, not simulated.

**It is shaped against the vacuous pass.** "An unexplained entry was detected"
is also what a reconciler that alerts on everything reports. Every integration
case in `reconcile_test.go` registers a legitimate run first, through the
ordinary admin path with its ledger event, and asserts that run raises nothing —
in the drift list and in the ledger both. That negative control was observed
failing against a deliberately over-alerting stub before the implementation
existed.

SPI-008 also carries the residual half of AB-10 that ADR-0012 could not close:
`BatchDeleteEntry` carries opaque entry IDs, rego cannot resolve one to a SPIFFE
ID, so a stolen admin credential can delete any entry in the trust domain and
detection is the only control there is. AB-10's row in doc 04 cites SPI-005
alone, which covers creation and not deletion; SPI-008 direction two is the rest
of it, and doc 04's AB-10 row should say so.

### AB-12 — the half that exists, the half that cannot, and the half that should

doc 04 gives AB-12 two controls. They are in very different states.

**"Review gates on protected strings" exists and is self-tested.**
`scripts/protected-surfaces.sh` part B requires every protected member name,
enum value, trailer key, tool name, SPIFFE grammar element and namespace string
to appear verbatim in the shipped source and, where VERSIONING.md is the source,
inside a code span in VERSIONING.md itself. Part A re-derives the genesis
constant and every committed fixture digest from the committed canonical bytes
in shell, independently of the Go that produced them. Both are hard gates on a
repository with no tags, which is this repository's state. `.github/workflows/
protected-surfaces.yml` runs the gate and, in a second job, runs
`scripts/protected-surfaces-selftest.sh`, which builds a throwaway repository,
injects one synthetic drift at a time and asserts red where the policy says red.
A gate that has never been observed failing proves nothing; this one has been.
The catalogue ID for it is SER-005, applied at repository level per ADR-0007.

That is a real control against a poisoned agent, and it is worth being precise
about *what* it controls: an agent that has been induced to rename a protected
string, alter a golden fixture, or quietly reword the policy that defines them
cannot land the change. It does nothing about an agent induced to write a
plausible bug in unprotected code.

**"Signed instruction files" has nothing to sign.** `.gitignore` line 1 is `.*`,
with an allowlist that admits `.github/`, `.golangci.yml`, `.editorconfig`,
`.dockerignore` and `.env.example` and nothing else; `opencode.json` is ignored
by name. The instruction surface that actually drives the coding agents —
`.claude/`, and the eight numbered specifications under `docs/` — is by design
not in the public repository. There is no artifact in the shipped tree that the
control could sign, and no reader outside the project can see the instructions
that produced this code. This review records that as a residual risk (R7) rather
than pretending the control is pending implementation. It is not pending; as
written it is incompatible with the repository's publishing rules, and doc 04
should either say so or change the control.

**The checkable threat behind AB-12 is the build toolchain, and it is
ungated.** The realistic route to poisoning an agent-built project is not the
prompt; it is the thing the prompt causes to execute. Three surfaces were
measured:

- *Go dependencies* — `go.mod` pins versions, `go.sum` is committed, and the
  default `GOSUMDB` applies. doc 04 §2's "pinned, checksummed" is true here. No
  `go mod verify` step exists in any workflow, and none is needed for the
  build-time guarantee; it would only add an explicit assertion of what the
  toolchain already enforces.
- *npm dependencies* — `web/package-lock.json` is committed and both CI jobs run
  `npm ci --no-audit --no-fund`, which installs the lockfile exactly with its
  integrity hashes. True as claimed.
- *GitHub Actions* — every `uses:` in all three workflows is pinned to a
  40-character commit SHA with the human-readable tag in a trailing comment, and
  `ci.yml` states the reason in its header: "a supply-chain attack on an action
  is an attack on the attestation chain this project exists to protect (doc
  04)". **That policy is a comment. Nothing enforces it.** A single `uses:
  some/action@v1` added in any future change passes every gate this repository
  has.

Proposed **REL-002** is that gate, and §"REL-002 and REL-003" states what it
must do.

## REL-001 — the release-signing check

doc 04 §2 leaves the release-signing check ID open. doc 08 §2 states the
obligation it has to discharge:

> Releases are signed with the project's own tooling; the release page documents
> the expected signing identity. An unsigned or mismatched release artifact is
> itself a security event — report it.

**The ID is `REL-001`**, in a proposed new catalogue family **`TC-REL` — release
and supply chain of Innsegl itself**, layer E.

A new family rather than an existing one, because none of the eleven existing
families is about the artifacts this project ships. `TC-SIG` is commit signing
under I2 and its eight cases are all the two-phase path; `TC-OPS` is chaos and
load. Filing a release gate in either would make the family name a lie, and
family names are how the Definition of Done audit walks the catalogue. `TC-REL`
also gives AB-09 and AB-12's supply-chain halves a home, which they currently do
not have anywhere in doc 07.

### What REL-001 must do to earn the ID

RM-056 (#64) owns `.github/workflows/release.yml` and is building it in parallel
with this review; these are the obligations, not an implementation.

1. **Sign with the project's own tooling.** doc 04 §2 stakes the credibility of
   the whole product on this — "Innsegl attributes Innsegl — dogfooding is the
   credibility test". A generic `cosign sign-blob` unconnected to the signing
   path this repository ships would satisfy the words and empty the claim. The
   release must go through the same Sigstore identity path the product uses
   (`internal/signing`, gitsign, ADR-0031), against the same Fulcio and Rekor a
   user would verify against.
2. **Verify what it just signed, in the same run, from first principles.** I5
   says verification trusts nothing. The check must re-derive: fetch the Rekor
   entry for the release artifact, validate its inclusion proof, and evaluate
   the certificate at the log's signed integration time (ADR-0034) — not read
   the signer's exit code. `innsegl verify` is the natural instrument.
3. **Assert the identity, not merely the presence of a signature.** The expected
   signing identity must be a committed value in the repository, and the check
   must fail when the certificate's identity does not equal it. doc 08 §2 calls
   a mismatched artifact a security event; a check that accepts any valid
   signature cannot see one. A change to that committed value should be as
   visible as a protected-surface change.
4. **Have been observed failing, for the right reason, at both negative
   controls.** An unsigned artifact must be rejected, and a validly-signed
   artifact carrying the *wrong* identity must be rejected. Every gate in this
   repository ships with a self-test that proves it goes red —
   `protected-surfaces-selftest.sh`, `coverage-floors-selftest.sh` — and REL-001
   without one is a gate whose green means nothing. IP §2 applies: the red is
   observed before the workflow exists.
5. **Fail the release, not warn.** A warning on a release artifact is the
   cached-green anti-pattern (FE-003) relocated to CI.
6. **Publish the material a third party needs to repeat it.** The release page
   must carry the expected identity and the Rekor entry reference, so that the
   verification is reproducible by someone who does not trust this project's CI
   — which is the entire point of I5.

Obligations 3 and 4 are the ones that decide whether REL-001 is worth having. A
release workflow that signs and does not check the identity, or that has never
been observed refusing a bad artifact, is a green badge on an unproven claim,
and doc 04's A4 is precisely the asset that destroys.

## REL-002 and REL-003

**REL-002 (proposed, layer U/C) — the build toolchain is pinned, and the gate
that says so has been seen to fail.** Every `uses:` in `.github/workflows/`
resolves to a 40-character hexadecimal commit SHA; a tag or branch reference
fails the build. It must carry its own negative control — a synthetic workflow
with `some/action@v4` that the gate is asserted to reject — for the same reason
REL-001 does. It closes the checkable half of AB-12, and it is the only control
this repository would have against OWASP ASI04 / T17. It needs no Go, no Docker
and no network.

**REL-003 (proposed, layer E/operational) — the canonical names the project
claims are registered and resolve.** Partly operational by nature: no test can
make PyPI refuse a squatter. What it can assert is that the canonical names are
enumerated in exactly one place, that the shipped module path, MCP server name
and CLI binary name equal the enumerated ones (SER-005 already covers this half,
and REL-003 should defer to it rather than duplicate it), and that each claimed
registration resolves to an artifact the project controls. RM-059 (#67) is the
open issue; AB-09's row in doc 04 currently reads "operational (no test)", which
is honest but leaves the abuse case uncovered, and this review is required to
leave none uncovered.

## Framework mapping, pinned

Both frameworks were fetched on **2026-09-02**. Nothing in this section is from
memory, and the one identifier that could not be reached from a primary source
is marked as such rather than filled in.

### MAESTRO

**Document read:** "Agentic AI Threat Modeling Framework: MAESTRO", Cloud
Security Alliance blog, author Ken Huang, published **2025-02-06**, read
2026-09-02. **The document states no version number.** The
`CloudSecurityAlliance/MAESTRO` repository (read 2026-09-02) points at the same
February 2025 publication as the framework document and adds no version. A later
CSA article, "Applying MAESTRO to Real-World Agentic AI Threat Models" (Leath
and Huang, 2026-02-11, read 2026-09-02) uses the same layer numbers and cites no
revision, so the February 2025 numbering is the current numbering.

The seven layers, verbatim from the source:

| Layer | Name |
|---|---|
| Layer 1 | Foundation Models |
| Layer 2 | Data Operations |
| Layer 3 | Agent Frameworks |
| Layer 4 | Deployment and Infrastructure |
| Layer 5 | Evaluation and Observability |
| Layer 6 | Security and Compliance (Vertical Layer) |
| Layer 7 | Agent Ecosystem |

doc 04 §4's placement checks out against those names. Pinned:

- **Innsegl sits at Layer 4 (Deployment and Infrastructure) and Layer 6
  (Security and Compliance).** The source names "compromised container images,
  orchestration attacks, infrastructure-as-code manipulation, lateral movement"
  at Layer 4 — AB-11 is the Layer 4 threat in this system, and SPI-008 is its
  control. Layer 6's named threats include "compromised security agents" and
  "evasion of security AI agents"; AB-03 (a compromised MCP fabricating records)
  is exactly that, covered by REC-004.
- **Innsegl's product function is a Layer 5 (Evaluation and Observability)
  control for other layers.** The source names "manipulation of evaluation
  metrics", "poisoning observability data" and "evasion of detection" at Layer 5
  — AB-03 and AB-08 respectively, covered by REC-004 and FE-003/FE-007.
- **Cross-layer, Layer 3 → Layer 5:** an agent framework feeding false
  `task_ref` values into truthful ledger records. Unmitigated by construction
  and recorded as residual risk R6; `task_ref` is a claim, not a fact.
- **Cross-layer, Layer 7 (Agent Ecosystem):** ecosystem trust in the public
  verification page. The source names "agent impersonation", "agent identity
  attacks" and "repudiation" at Layer 7 — which is where Innsegl's whole product
  claim lives. Mitigated by raw-material re-derivability (VER-001, FE-007) and by
  AB-09's namespace controls.

### OWASP

doc 04 §4 instructs that the exact OWASP identifiers be pinned at review time
rather than taken from doc 04, "because the taxonomy is versioned and IDs shift
between releases". That instruction was correct and the shift has happened.

**Primary document read:** *OWASP Top 10 for Agentic Applications 2026*, OWASP
Gen AI Security Project, **Version 2026, December 2025**, PDF fetched and read
in full 2026-09-02. Its Appendix A, "OWASP Agentic AI Security Mapping Matrix"
(pp. 38–40), cross-maps the ASI Top 10 against the LLM Top 10, the *Agentic AI
Threats & Mitigations* guide's T-numbers, and AIVSS. Every T-identifier below is
transcribed from that appendix, which is an OWASP publication citing its own
sibling document — not from a secondary summary.

**The ten risks, verbatim:** ASI01 Agent Goal Hijack · ASI02 Tool Misuse and
Exploitation · ASI03 Identity and Privilege Abuse · ASI04 Agentic Supply Chain
Vulnerabilities · ASI05 Unexpected Code Execution (RCE) · ASI06 Memory & Context
Poisoning · ASI07 Insecure Inter-Agent Communication · ASI08 Cascading Failures ·
ASI09 Human-Agent Trust Exploitation · ASI10 Rogue Agents.

**On the T-series.** *Agentic AI – Threats and Mitigations* v1.0 (2025-02-17) is
what doc 04 was written against; the Top 10 2026 body text cites **v1.1**
explicitly ("Agentic AI – Threats and Mitigations v1.1"), and the 2025-12-09
OWASP announcement describes v1.1 as "a minor update … synchronised with our Top
10". The v1.1 PDF itself is behind a download form that returned an HTML landing
page rather than the document when fetched on 2026-09-02, so **this review did
not read the T&M guide directly**; the T-identifiers are taken from the Top 10
2026 appendix instead. The range is T1–T17.

Innsegl's position, pinned:

| doc 04 §4 claim | Pinned identifiers | Innsegl's role | Covering ID |
|---|---|---|---|
| "a mitigation for … repudiation/untraceability" | **T8 Repudiation & Untraceability** (appendix, under ASI08 and ASI09) | Mitigation — this is the product | SIG-001, VER-001, LED-001/002 |
| "a mitigation for … identity-spoofing/impersonation" | **ASI03 Identity and Privilege Abuse** | Mitigation | SPI-001, SPI-002, VER-002 |
| "partial mitigation for rogue-agent detection" | **ASI10 Rogue Agents** → **T13 Rogue Agents in Multi-Agent Systems** | Partial mitigation — unattributed signatures surface in drift detection | REC-003 |
| Threat *to* Innsegl: tool misuse (AB-04) | **ASI02** → **T2 Tool Misuse** | Threat | MCP-008, MCP-014 |
| Threat *to* Innsegl: privilege compromise (AB-10) | **ASI03** → **T3 Privilege Compromise** ("maps one-to-one", per the Top 10 body text) | Threat | SPI-005, SPI-008 |
| Threat *to* Innsegl: resource exhaustion (AB-07) | **ASI02** → **T4 Resource Overload** | Threat | MCP-013 |
| *Not in doc 04:* the supply chain of Innsegl itself | **ASI04 Agentic Supply Chain Vulnerabilities** → **T17 Supply Chain Compromise** | Threat | REL-001, REL-002 — **neither exists yet** |

Three honest notes on this mapping.

**doc 04's "identity-spoofing/impersonation" could not be pinned to a T-number.**
Secondary sources consistently report T9 as "Identity Spoofing & Impersonation",
and that is probably right, but **T9 appears nowhere in the Top 10 2026 appendix
or body**, and the v1.1 guide could not be retrieved. It is pinned to ASI03,
which is primary-sourced, and the T-number is deliberately left blank. A guess
here would be the exact failure mode this review exists to avoid.

**The published appendix is internally inconsistent about T4, T6 and T12.** The
same table gives "T4 Resource Overload" under ASI02 and "T4 Memory Overload"
under ASI06; "T6 Goal Manipulation" under ASI01 and "T6 Broken Goals" under
ASI06; "T12 Agent Communication Poisoning" under ASI04 and ASI07 and "T12 Shared
Memory Poisoning" under ASI06. This is a defect in the source document, not in
the transcription. AB-07's mapping uses the ASI02 row, which is the row about
resource exhaustion and therefore the right one for AB-07 regardless of how the
conflict resolves upstream.

**ASI04 is the gap this mapping exposes.** doc 04 §4 lists three threats to
Innsegl from the taxonomy and omits the supply chain of Innsegl itself, even
though §2 has a supply-chain paragraph. It is the one ASI category where this
project has a documented control intention and no gate at all. Both proposed IDs
that close it — REL-001 and REL-002 — are unimplemented at the time of writing.

## Residual risks

doc 04 §5 lists six. This review re-states them with their status as measured
today, and adds five it found. Nothing here is hidden behind a mitigation that
does not exist.

**R1 — Trust domain root compromise (A1). Unchanged, recovery story still
unwritten at review time.** Detection exists (SPI-008, REC-003); prevention is
deployment discipline. doc 04 asks for a re-rooting runbook. RM-057 (#65) is
writing `runbooks/` in parallel with this review, so this ADR cannot verify it;
whoever reconciles the wave should check that the re-rooting event is among
them.

**R2 — Public Sigstore metadata exposure. Smaller than doc 04 states.** doc 04
§5.2 and the ADR-0002 tradeoff it cites were written when public Sigstore was
the default. ADR-0010 made self-hosted Fulcio/Rekor the shipped default and
demoted public Sigstore, and ADR-0029 composes the self-hosted stack. The
default deployment no longer publishes SPIFFE IDs, repositories and timing to a
public log. The residual is now the reverse: an operator who *chooses* public
Sigstore accepts the exposure. doc 04 §5.2 should be re-pointed at ADR-0010.

**R3 — GitHub contributor-logic change. Worse than doc 04 states: the snapshot
has never been taken.** doc 04 treats GH-001 as a dated snapshot that is re-run
on a schedule. Per ADR-0037, GH-001 has never run against real GitHub —
`test/e2e/testdata/gh-001-run.json` reads status `never-run`, the scheduled job
in `author-gate.yml` fails until a human provisions a throwaway repository and
credential, and I6's outward half is unimplemented under IP §8. The monthly
schedule that doc 04 §5.3 relies on exists and is red by design. GH-002 proves
I6 over this repository's own commits and nothing about GitHub's behaviour.

**R4 — Canonicalization bug. Unchanged, controls in place.** TC-SER golden
fixtures are committed and immutable, SER-005 re-derives them in shell
independently of the Go, and part C of the gate fails any fixture modification
on *any* release including MAJOR. There is still exactly one implementation, so
the cross-implementation check doc 04 anticipates has nothing to run against.

**R5 — Attribution ≠ authorization (E1). Unchanged.**

**R6 — `task_ref` honesty. Unchanged, and now also a named MAESTRO cross-layer
threat** (Layer 3 → Layer 5, above).

**R7 — The agent instruction surface is outside the repository, and AB-12's
first control has nothing to sign.** `.gitignore` excludes `.*` and all of
`docs/` except `docs/adr/`. The eight normative specifications and the agent
instruction files are local-only by policy. Consequences: "signed instruction
files" cannot be implemented as written; a reader of the public repository
cannot audit the instructions that produced the code; and every ADR — this one
included — cites specification sections and test IDs that an outside reader
cannot look up. Accepted, because the publishing rule is deliberate, but it
should be accepted explicitly rather than left as an open control.

**R8 — Action pinning is a convention with no gate.** Measured: all `uses:`
references in `ci.yml`, `author-gate.yml` and `protected-surfaces.yml` are
40-character SHAs today. Nothing prevents the next one from being a tag.
ASI04/T17. Closes with REL-002.

**R9 — SPIRE entry deletion can be detected but not authorized.** ADR-0012's
unclosable hole, restated here because it is a residual and belongs in this list
rather than only in an ADR about a policy: a stolen admin credential can delete
any entry in the trust domain, rego cannot scope `BatchDeleteEntry`, and
SPI-008 direction two is the entire control.

**R10 — Release signing does not exist at review time.** REL-001 is assigned by
this ADR and implemented by nobody yet. Until it lands and has been observed
failing on both negative controls, doc 04 §2's "releases signed with the
project's own tooling" is an intention. The dogfooding claim is the project's
loudest credibility claim, and it is currently unbacked.

**R11 — doc 07 and the implemented test set have diverged by 66 IDs.** Measured
on 2026-09-02: every ID in doc 07 exists in the source, but sixty-six IDs exist
in the source that doc 07 does not carry — `FE-016`…`FE-107`, `OPS-005`,
`OPS-006`, `SPI-008`. doc 07 is normative and the Definition of Done audit walks
it. An audit that walks doc 07 today under-reports the test suite; a reader of
this ADR who tries to look up SPI-008 in the catalogue will not find it. This is
a documentation-integrity risk to the review artifact itself, which is why it is
listed as a residual and not as a chore.

## Alternatives considered

**Amend doc 04 in place instead of writing an ADR.** Lost on two counts. doc 04
is normative and this issue reviews it; a review that edits its subject cannot
be checked against it afterwards. And doc 04 never ships, so the review would be
invisible to exactly the audience — an adopter deciding whether to trust the
attribution claim — that a threat-model review is written for.

**Leave AB-11 citing "open — add TC" until doc 07 carries SPI-008.** Lost
because it inverts the evidence. The test exists, runs against a real SPIRE, and
has an observed red; the catalogue row is the thing that is missing. Citing the
catalogue's silence as the state of the control would report the system as less
safe than it is, which is the mirror image of the fabricated-citation failure and
just as wrong.

**Leave the release-signing ID to RM-056 (#64) on the grounds that it owns the
workflow.** Lost because assigning it is this issue's scope and because the two
agents cannot talk. Leaving it unassigned guarantees the artifact ships with
doc 04's third hole still open; assigning it guarantees at worst a rename. The
obligations in §"REL-001" are the substance and they do not depend on the name.

**File release signing as `SIG-009` inside `TC-SIG` rather than opening
`TC-REL`.** Lost because `TC-SIG` is "commit signing (two-phase)" and its eight
cases are all the I2 path; a release-artifact gate filed there makes the family
name inaccurate, and the family names are the audit's index. It is the cheapest
reversal in this ADR if the reconciliation prefers it — one rename, no change to
the obligations.

**Map the OWASP threats from the widely-reported T1–T15 list.** Lost because it
is wrong: the current taxonomy runs to T17, and the numbering reported by
secondary sources conflicts with itself (T4 and T5 are both reported as
"Resource Overload" across different summaries). Reading the primary appendix
cost one fetch and produced a mapping that cites its own page range.

**Assert T9 for identity spoofing because the secondary sources agree.** Lost on
the project's own standard. Three blogs agreeing is not a primary source, the
identifier is absent from the one OWASP document this review could read, and a
threat-model artifact that guesses an identifier has forfeited the property that
makes it worth reading.

## Consequences

**Easier.** doc 04's three self-declared holes are closed or explicitly assigned,
and every abuse case has a covering ID with its status marked. An outside reader
can, for the first time, see what the project claims about its own threat surface
without access to `docs/`. RM-056 (#64) has a named ID and six stated obligations
to build against rather than a blank.

**Harder.** This ADR cites SPI-008, OPS-005, OPS-006 and the FE-016…FE-107 range
against a catalogue that does not list them, and cites specification sections a
public reader cannot open. Both are recorded as R11 and R7. The artifact is
honest about it, but it is less useful than it would be if doc 07 were current.

**Irreversible.** Nothing in this ADR changes running code or a protected
surface. The ADR itself is immutable per `docs/adr/README.md`; a later review
supersedes it rather than editing it. The threat-model review is dated, and doc
04 §6's triggers apply to it: the next MCP tool, the next trailer or grammar
change, the next SPIRE or Sigstore advisory, a GH-001 failure, or federation (E5)
re-opens it.

**Exit cost.** Low. If `TC-REL` is rejected in favour of existing families, three
proposed IDs are renamed and the obligations move with them.

### What doc 04 and doc 07 must be given

These are recommendations to the human who owns the normative documents. This
ADR does not make them.

**doc 04:**
- §2 SPIRE deployment, tampering row: replace "**open: add test ID**" with
  `SPI-008`.
- §2 supply chain: replace "**Open: add release-signing test/CI check ID.**"
  with `REL-001`, and add `REL-002` for action pinning.
- §3, AB-11: replace "**open — add TC**" with `SPI-008`.
- §3, AB-10: add `SPI-008` beside `SPI-005`; SPI-005 covers creation, not the
  deletion hole ADR-0012 leaves open.
- §3, AB-12: replace "**open — CI check**" with `SER-005` for the protected-
  strings half, `REL-002` for the toolchain half, and either strike "signed
  instruction files" or state why it cannot be implemented under the repository's
  publishing rules (R7).
- §3, AB-09: replace "operational (no test)" with `SER-005` plus `REL-003`.
- §4: add ASI04 / T17 to the list of threats *to* Innsegl; re-point the OWASP
  paragraph at the Top 10 2026 / T&M v1.1 identifiers pinned above; note that
  MAESTRO carries no version number, so the "IDs shift between releases" caution
  applies to OWASP only.
- §5.2: re-point at ADR-0010 — self-hosted is the default and the exposure is
  now opt-in.
- §5.3: record that GH-001 has never run (ADR-0037), so the residual is an
  un-taken snapshot rather than a stale one.
- §5: add R7–R11.

**doc 07:**
- `TC-SPI`: add the `SPI-008` row. ADR-0013 already carries its proposed text.
- New family `TC-REL`, with `REL-001` (E), `REL-002` (U/C) and `REL-003`
  (E/operational).
- The sixty-six implemented-but-uncatalogued IDs, per R11.
