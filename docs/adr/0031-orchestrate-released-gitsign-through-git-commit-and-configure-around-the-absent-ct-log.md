# ADR-0031: Orchestrate released gitsign through `git commit`, build its environment from nothing, and configure around the absent CT log

- Status: accepted
- Date: 2026-08-30
- Deciders: Mike
- Implements: IP §1 component 3, IP §6.2, RM-032 (#40); test IDs SIG-001, SIG-005, SIG-008
- Builds on: [ADR-0010](0010-self-hosted-sigstore-is-the-shipped-default.md),
  [ADR-0019](0019-scope-mintjwtsvid-to-the-agent-subtree-and-issue-one-audience-per-credential.md),
  [ADR-0024](0024-readiness-probes-sigstore-by-fetching-its-trust-material.md),
  [ADR-0028](0028-place-commit-trailers-in-process-and-refuse-the-messages-git-places-ambiguously.md),
  [ADR-0029](0029-compose-self-hosted-sigstore-as-its-own-project-joined-to-spires-oidc-network.md)

## Context

IP §1 names the pipeline this issue builds in one line:

> gitsign wraps signing. JWT-SVID (audience-bound to Sigstore) →
> `SIGSTORE_ID_TOKEN` → Fulcio short-lived cert → signed commit → Rekor
> transparency entry.

and IP §7 fixes what "wraps" is allowed to mean:

> SPIRE and Sigstore (gitsign/Fulcio/Rekor) are used as released upstream
> components — do not fork, do not reimplement their crypto. Configuration and
> orchestration only.

Five forces meet here, and four of them are facts about released software
rather than choices this project gets to make.

**1. `gitsign` is a `gpg` replacement, not a library.** It is invoked by git as
`gpg.x509.program` with `--sign`, reads the object to be signed on stdin and
writes a CMS signature on stdout. There is no supported in-process API for
signing a commit; `pkg/gitsign` exports a `crypto.Signer`-shaped thing, but
assembling the CMS, computing the object hash and uploading the Rekor entry are
`internal/`. Using gitsign as released therefore means running the binary.

**2. gitsign's defaults point at public-good Sigstore, and ADR-0010 says ours
must not.** Unconfigured, gitsign signs against `fulcio.sigstore.dev`, logs to
`rekor.sigstore.dev`, and verifies against the public TUF root. ADR-0010
measured that public Fulcio accepts no issuer of type `spiffe` at all, so
self-hosted Fulcio and Rekor are the shipped default. Every one of those three
anchors has to be moved, and the third — the Rekor **log key** — is the one
whose absence is silent: verification against the wrong log key fails in a way
that looks like a bad signature.

**3. THERE IS NO CT LOG, AND COSIGN WILL NOT ACCEPT AN EMPTY SET OF CT KEYS.**
ADR-0029 decision 5 runs Fulcio with `--ct-log-url=` empty and predicted the
consequence: "a verifier configured to require an SCT will refuse these
certificates. RM-032 (gitsign wrapper) and RM-037 (`innsegl verify`) must be
built against a trust root that lists no CT log." Half of that is a flag —
`--insecure-ignore-sct`. The other half is not, and it cost the most time to
find. `gitsign verify` constructs a cosign certificate verifier before it looks
at the ignore-SCT flag, and that constructor calls `cosign.GetCTLogPubs`, which
**errors on an empty key set** and, when `SIGSTORE_CT_LOG_PUBLIC_KEY_FILE` is
unset, falls back to fetching the keys from the public TUF mirror. MEASURED,
with the network blocked and every other anchor supplied locally:

```
Error: error getting CT log public key: updating local metadata and targets:
  error updating to TUF remote mirror: tuf: failed to download 13.root.json:
  Get "https://tuf-repo-cdn.sigstore.dev/13.root.json": ...connection refused
```

A verifier that reaches the public internet to load keys it will not use is the
opposite of IP §7's "integration tests must run against local containerized
instances so CI needs no external dependencies".

**4. gitsign has a credential cache, and E8 forbids it.**
`GITSIGN_CREDENTIAL_CACHE` points gitsign at a daemon (`gitsign-credential-cache`)
that keeps the ephemeral **private key** and its certificate alive across
signatures. E8 is explicit: "The MCP never holds, caches, or proxies agent
private keys. Keys are generated agent-side/gitsign-side and discarded." An
operator who exports that variable for their own interactive use would
otherwise turn key custody on for the MCP without anyone deciding to.

**5. ADR-0028 already refused to let ambient configuration into the signed
bytes**, for the trailer keys. The same argument applies with more force to
`gpg.x509.program`, `commit.gpgsign`, `user.email` and `commit.template`: the
rendered message is the preimage of the signature, and so is the author line.

Invariants in play: I2 throughout (no signing without a valid, unexpired,
audience-correct credential for the current run); I5 in decisions 2 and 5; I6
via ADR-0028's gate; E8 in decision 3.

## Decision

**Seven decisions, all in `internal/signing/gitsign.go` and
`internal/signing/sigstore.go`.**

### 1. The wrapper runs `git commit`, and `git` runs `gitsign`

`Signer.Sign` invokes

```
git -c gpg.format=x509 -c gpg.x509.program=<gitsign> -c commit.gpgsign=true \
    commit --file <message> --cleanup=verbatim --no-edit
```

in the caller's repository. Three things about that line are load bearing.

`-c` rather than `git config`: command-line configuration outranks repository
configuration, so a repository that sets `gpg.x509.program` cannot substitute
another signer, and nothing is written into the caller's `.git/config`.

`--cleanup=verbatim`: the message has already been normalised by RM-031's
writer and IS the preimage of the signature. Git's default cleanup would strip
and re-wrap bytes we are about to sign, which would make ADR-0028's
"rendering is a pure function of (normalised message, claim)" false at the last
moment.

`--file`: the message never passes through a shell or an editor.

The staged index is the caller's. `Sign` stages nothing and resets nothing:
what is committed is what `sign_commit`'s caller staged.

### 2. Every trust anchor is fetched from this deployment and handed to gitsign as a file

Before any signature, the wrapper fetches Fulcio's `/api/v1/rootCert` and
Rekor's `/api/v1/log/publicKey` and requires them to PARSE — a PEM **CA**
certificate and a PKIX public key respectively, which is ADR-0024's definition
of "Sigstore is reachable", used here so that the wrapper's readiness question
and the MCP's health check mean the same thing. They are written to the
Signer's work directory and named in `GITSIGN_FULCIO_ROOT` and
`SIGSTORE_REKOR_PUBLIC_KEY`.

That fetch is also the **reachability probe, and it runs before `git` does**.
It is the one place that can distinguish `SIGNING_UNAVAILABLE` (Fulcio) from
`TRANSPARENCY_UNAVAILABLE` (Rekor) without pattern-matching a subprocess's
prose, and because it precedes the commit, neither failure can leave a commit
object behind — IP §6.3's "the repo has no new commit object at all", obtained
by ordering rather than by cleanup.

### 3. The child's environment is built from nothing, and `GITSIGN_CREDENTIAL_CACHE` is not in it

`cmd.Env` is a whitelist. No variable of this process reaches gitsign or git.
That is one decision serving three purposes:

- **E8.** `GITSIGN_CREDENTIAL_CACHE` cannot be inherited, so the wrapper cannot
  be made to hold a signing key by an environment it did not choose.
- **I2.** `GITSIGN_TOKEN_PROVIDER` is pinned to `envvar`. Left unset, cosign's
  provider auto-detection is free to find a GitHub Actions token, a workload
  SPIFFE socket or a file at `/var/run/sigstore/cosign/oidc-token` — any of
  which would sign a commit as somebody other than this run, silently, and only
  on the machines where that provider happens to be enabled.
- **ADR-0028's argument, generalised.** `GIT_CONFIG_NOSYSTEM=1` and a
  `GIT_CONFIG_GLOBAL` pointing at a file that does not exist keep a
  `~/.gitconfig` out of the bytes that get signed, and `GIT_AUTHOR_*` /
  `GIT_COMMITTER_*` are set explicitly from the request, so the author line is
  the one `CheckAuthor` admitted rather than whatever the machine is configured
  with.

`TestE8TheWrapperHoldsNoKeyMaterial` asserts all of this from the outside: it
exports `GITSIGN_CREDENTIAL_CACHE`, `SIGSTORE_ID_TOKEN` and
`GITSIGN_FULCIO_URL` in the test process and requires the first to be absent
from the child and the other two to carry this run's values. It also reflects
over `Signer`, `Result`, `Credential` and `Certificate` and fails on any field
whose type could hold a private key.

### 4. `Result` carries the identity of the credential used, never the token

`sign_commit` has to record what signed a commit. What it needs is the SPIFFE
ID and the expiry, so that is what `Result` carries. The bearer token stays in
the environment of one child process and in the `Signer`'s cache; a struct that
returned it would be one copy of a credential too many, and E8's spirit is that
custody is measured in copies.

### 5. The CT log key set is made non-empty with a key that was generated and thrown away

`SIGSTORE_CT_LOG_PUBLIC_KEY_FILE` names a PEM public key generated by
`placeholderCTLogKey`, whose private half never leaves the function.

This is the honest encoding of "there is no CT log". cosign requires a
non-empty set; this deployment has no CT log operator and therefore no CT log
key; so the set contains exactly one key that **cannot have signed anything**.
If `--insecure-ignore-sct` were ever dropped, SCT verification fails closed
rather than succeeding against whatever key a TUF fetch happened to return.
A fresh key per Signer also makes the property checkable: two calls that
produced the same bytes would mean something had stored one.

The alternative considered and rejected is below; the short version is that
naming Rekor's key or Fulcio's would be one line shorter and would assert
something untrue about who operates a CT log.

### 6. The Rekor entry is FOUND by artifact hash, not read out of gitsign's output

gitsign's default "online" mode logs a `hashedrekord` whose artifact is the
**commit SHA**. The wrapper searches `/api/v1/index/retrieve` for
`sha256:<sha256 of the commit SHA>`, fetches each candidate, and accepts the one
whose artifact hash matches AND whose public key is byte-identical to the
certificate the commit is actually signed under.

The search is not a lookup mechanism that happens to work; it is the **proof**.
gitsign prints `tlog entry created with index: N`, and scraping that would name
an entry without establishing anything about it. Matching on (artifact hash,
certificate) establishes that the entry is this commit's and no other's, which
is exactly the assertion SIG-001 would otherwise be able to fake.

Online mode is kept — it is gitsign's default, and IP §7 says configuration
only — and it has a second consequence worth stating: because the logged
artifact IS the commit SHA, RM-035's reconciler can read a commit SHA straight
out of a Rekor entry when repairing a crash between Phase B and Phase C
(IP §6.5). Offline mode logs the commit *content*, from which the SHA is not
recoverable without the signature.

### 7. Skew widens a certificate's window and NEVER a credential's

IP §6.8 asks for "verification-time logic tolerant of NTP-scale skew but
reject anything beyond a small bound"; the bound this project documents is
**60 seconds**, `DefaultSkew`, and `checkCertificate` applies it symmetrically —
a certificate that is not yet valid is refused past the bound exactly as an
expired one is.

`Credential.usableAt` applies **no skew at all**, and the asymmetry is the
decision. A verifier reading somebody else's certificate must forgive clock
disagreement. A signer has no such licence: widening a credential's window by a
minute so it can still be used is indistinguishable from extending its TTL by a
minute, which IP §6.2 forbids in terms — "never extend TTLs to 'help'". The
only adjustment made on the credential side is `MinValidity` (default 30s),
which **narrows** the window, because a token that expires between our check and
Fulcio's produces a failure attributed to the wrong component. Both rules push
the same way: toward re-fetching.

The re-fetch itself is ordered so that IP §6.2's second sentence is true by
construction: the cached credential is **dropped before** the source is called,
so a failed re-fetch has nothing to fall back to and signing blocks.

## Alternatives considered

**Import gitsign as a library and sign in process.** Would remove a subprocess
and let the Rekor entry come back as a typed value. Rejected because the
signing path — CMS assembly, the commit object hash, the Rekor upload — is
under `internal/` in gitsign, so "as a library" would mean vendoring or forking
it, which IP §7 forbids in as many words. The subprocess is also what makes the
E8 boundary physical: the private key exists in another process's address space
and dies with it.

**Read the Rekor log index from gitsign's stderr.** One line, no HTTP client,
and it is what the output is there for. Rejected because it names an entry
without establishing that the entry is this commit's — precisely the shape of
vacuous evidence this project has already been caught producing eleven times.
The hash search costs about eighty lines and turns SIG-001's Rekor assertion
from "gitsign said so" into a comparison.

**Use `internal/segment`'s Rekor client instead of a second one.** The right
instinct, and it does not fit: that client is an anchor **writer** (ADR-0007)
with no search method, and adding one would mean editing another issue's file.
The reader here is deliberately small — search, fetch, compare — and reuses
`internal/segment`'s `InclusionProof.Verify` in the test rather than
reimplementing a Merkle check. Consolidating the two into one read/write client
is a job for RM-037, which needs the read half anyway; flagged in Consequences.

**Switch gitsign to `GITSIGN_REKOR_MODE=offline`,** which embeds the log entry
in the signature and makes verification offline. Attractive for I5 and it is
the direction upstream says it is going. Rejected for v0.1 on two grounds: it
is not the released default, and IP §7 constrains this issue to configuration
that has a reason; and the offline entry's artifact is the commit *content*,
which leaves IP §6.5's reconciler unable to recover a commit SHA from Rekor
alone. Revisit when RM-035 exists and can say what it needs.

**Point `SIGSTORE_CT_LOG_PUBLIC_KEY_FILE` at Rekor's log key or Fulcio's root
public key.** Zero new key material, one line shorter, and both keys are
already on disk. Rejected because the file's meaning is "these are the CT logs
this verifier trusts", and putting the transparency log's own key there says
something false about the deployment to the next person who reads it — in a
file whose whole purpose is to encode trust. The generated-and-discarded key
says exactly what is true: there is no CT log, and the set is non-empty only
because cosign requires it to be.

**Add a CT log to the compose stack** (ADR-0029 offered this as the bounded
change to revisit "on evidence"). The evidence came back negative: the flag and
one environment variable were enough, and a CT log would be two more containers
and a second log to operate for a property no v0.1 verifier consumes. ADR-0029
decision 5 stands.

**Let cosign fetch CT keys from the public TUF mirror and simply ignore them.**
Works today on a developer's laptop and fails in a hermetic CI runner, which is
the environment IP §7 names. Worse, it fails *at verification*, long after the
signature exists.

**Inherit `os.Environ()` and delete the dangerous variables.** A denylist
against an open set — the same argument ADR-0028 used to refuse
`git interpret-trailers`, and it is stronger here because the set includes
every variable cosign, sigstore-go and git will add in future releases.

**Check the certificate before creating the commit.** Impossible without
reimplementing the Fulcio exchange: the certificate does not exist until
gitsign has run, and gitsign runs only as part of `git commit`. The wrapper
therefore checks everything cheap BEFORE the commit and reads the certificate
back AFTER it, and the errors returned from the second half are
INVARIANT_VIOLATION-shaped rather than retryable, because a commit that exists
and cannot be attributed is not a transient condition.

**Verify with `git verify-commit` rather than `gitsign verify`.** `git
verify-commit` invokes gitsign with `--verify`, which has no access to issuer
or identity, so gitsign reports `Validated Certificate claims: false` and warns.
A verification that cannot say WHICH identity signed is not the verification
IP §1's check 3 describes, so `Signer.Verify` requires an identity argument and
has no "any identity" mode.

## Consequences

**`gitsign` becomes a runtime dependency of the MCP, pinned only by the
harness.** `internal/signing` resolves it with `exec.LookPath` at construction,
so a deployment must install it; the test harness pins **v0.17.1** and skips
loudly when it is absent. There is no `go.mod` entry, deliberately — adding one
would pull cosign, sigstore-go and their transitive trees into a module whose
dependency set is currently fourteen direct entries, to obtain a binary we
invoke rather than call. The cost is that a version bump is not visible in
`go.mod`; the mitigation is `harnessGitsignVersion`, which is the one place the
version is written and the message an absent binary prints.

**`internal/signing/testdata/sigstore-testscope.yml` is a compose overlay
living under `internal/`.** ADR-0029's "what the project should do next" asked
for exactly this file and put it in `deploy/compose/`; RM-032 does not own
`deploy/`, so it lives beside its only caller. **Moving it to
`deploy/compose/sigstore-testscope.yml` is a rename and should happen the
moment a second suite needs it** — RM-034's failure injection is the likely
first.

**The OIDC discovery provider needs a registration entry, and a Go harness has
to create one.** `deploy/compose/spire/register.sh` does this for the shared
stack and cannot be reused per-process: it hardcodes the container name
`innsegl-spire-oidc` and addresses `-f spire.yml` with no project. The harness
therefore reimplements its five selectors. MEASURED, and worth recording
because the error names nothing: without that entry the provider holds no SVID,
`GET /keys` answers `HTTP 500 document not available`, and **Fulcio refuses
every JWT-SVID with "There was an error processing the identity token"** — the
same message an expired token produces. Two issues will hit this again;
parameterising `register.sh` by project and container name is the fix, and it
is `deploy/`'s to make.

**A second CMS reader now exists in this repository, and it is a structure
walk.** `certificatesFromSignature` parses as far as SignedData's
`certificates [0]` and hands the DER to `crypto/x509`. It verifies nothing —
the signature is gitsign's business — but it is still ASN.1 this project now
maintains, of the kind threat model §5.4 warns about. The mitigation is that
its positive case is pinned against a **real** signature captured from the
compose stack (`testdata/signed-commit.sig.pem`) rather than against a blob we
encoded ourselves.

**`Signer.Verify` is not the verifier that proves I5.** It shares this
wrapper's configuration, including its trust root, so it trusts things RM-037's
`innsegl verify` must not. It exists because SIG-001 needs the released
verifier's verdict and because the CT-log configuration should live in one
place. RM-037 must build its own trust material from the endpoints an outsider
can reach, and should treat decision 5 as the thing to copy and decision 2 as
the thing to redo.

**The wrapper caches one credential and is single-run.** `Signer` holds a mutex
and one `Credential`, keyed by the claim's identity; a credential for a
different run replaces it rather than being kept alongside. RM-033 should
create one Signer per run, or the cache degrades into a re-fetch per commit —
correct, but it spends a `get_credential` call each time.

**SIG-005's middle case spends about 32 seconds of wall clock.** It waits for a
real 30-second JWT-SVID to really expire, because its assertion — that the
second certificate's `NotBefore` is after the first credential's expiry — is
only a fact if the credential really died. A fake clock would let the case pass
while gitsign quietly reused a live token. The other two cases use an injected
clock and are fast.

**doc 07 has no test ID for the wrapper's own certificate check.** SIG-001
covers the happy path and SIG-005 the validity window, but "the wrapper refuses
to report a success when the certificate's SAN is not the claim's" — the
INVARIANT_VIOLATION arriving from our own side, IP §6.9's trailer spoofing seen
from the inside — is unnumbered. Proposed: **SIG-010** (U) `Sign` refuses a
commit whose certificate does not attest the claimed run.

**Exit cost.** Moderate and mostly on decision 1. The signed artifact is
ordinary gitsign output — a CMS signature in a `gpgsig` header and a
`hashedrekord` in Rekor — so nothing already signed depends on this wrapper
existing, and a later in-process signer would produce the same bytes. What
would be expensive to reverse is decision 6's choice of online mode, because
every commit already signed has its Rekor entry keyed on the commit SHA and a
verifier written against that keying is a verifier this project ships.
