# ADR-0008: Prove the WORM configuration by attempting a real deletion, and fail closed on anything short of a refusal

- Status: accepted
- Date: 2026-08-28
- Deciders: Mike

## Context

IP §1 requires sealed segments to be "written to object storage with
WORM/object-lock", and I4 says no record is ever deleted or mutated. IP §6.4
turns that into an executable obligation:

> WORM misconfiguration: a deploy-time check that attempts to delete a canary
> object and must be *refused* by the storage layer; deployment fails if
> deletion succeeds.

Doc 05 §1 names the store (MinIO with object lock, "buckets created with lock
on; SEG-005 canary runs against it"). Doc 05 §2 adds two things the deploy-time
reading alone would miss: the mode is **compliance**, and the canary "runs as a
scheduled job in production, not only at deploy".

Three properties of the problem shape everything below.

**The assertion is inverted.** Every other test in this project asserts that
something happened. SEG-005 asserts that something did *not*. "The deletion was
refused" is also true when the request was malformed, when the key was wrong,
when the object was never written, and — most dangerously — when the
credentials could not have deleted anything in that bucket in the first place.
A check of this shape passes by accident more easily than it passes on merit.
This project has already been bitten twice by that class of pass: RM-008's
property test went green against a stub, and RM-009's absence-assertion passed
trivially until it temporarily added the methods it was asserting the absence
of, to prove the test could fail.

**A configuration is not a behaviour.** `GetObjectLockConfig` returns what the
bucket was asked to be. It does not say what the store will do when this
principal, holding these credentials, asks to destroy this version today. IP
§6.4 asks for the second thing.

**Object lock is narrower than "immutable".** In particular it expires, and in
governance mode it yields to any caller holding
`s3:BypassGovernanceRetention` — so a bucket can report a retention mode,
refuse an ordinary delete, and still be deletable by the account the canary is
running as.

## Decision

**The canary establishes refusal by attempting a real, permanent deletion of a
real retained object written through the production writer, and it is only
allowed to attribute a refusal to object lock after it has permanently deleted
something else in the same bucket with the same credentials.** Its verdict is
the exit status of `innsegl canary`, and there is no outcome short of a refusal
that exits zero.

Concretely:

1. **The writer sets retention itself.** `segment.WORM` applies mode and
   retain-until on every `PutObject`, defaulting to compliance (doc 05 §2). A
   bucket-level default rule is checked but not depended on, because a default
   rule protects only what is written through paths that do not override it.
2. **This code never creates the bucket.** Object lock can only be enabled at
   bucket creation, so a writer that created buckets on demand would, on the
   day a flag was dropped, silently create an unlocked one and keep working.
3. **The probe travels the production write path.** `RunCanary` writes its
   probe through the same `WORM.write` a sealed segment goes through. A probe
   written some other way would prove something about that other way.
4. **The gate is a live deletion, twice.** `DeleteObject` on the probe's
   version must be refused; then the same call asking to bypass governance
   retention must also be refused. The second attempt is what distinguishes a
   compliance bucket from a governance bucket whose retention the canary's own
   credentials can lift — a distinction the reported mode string cannot make.
5. **The anti-vacuity control is an assertion, not a comment.** Before a
   refusal counts, the canary permanently deletes a version it is entitled to
   delete — the delete marker it writes on the probe's own key, which carries
   no retention — using the identical API call, permission and bucket. If that
   fails the run is inconclusive, and an inconclusive run fails.
6. **The probe is read back and byte-compared** after both attempts. A refusal
   that left the object gone or altered is not a refusal.
7. **Unreached checks are reported as failures.** A report always carries every
   check in `CanaryCheckNames()`; `OK()` is false if any is missing. "No check
   failed" must not be reachable by running fewer checks.
8. **`innsegl canary` is a subcommand, and its exit status is the verdict.**
   `0` every check held; `2` bad command line; `3` a check failed — fail the
   deploy; `4` the canary could not run, so nothing was proved. A deploy step
   and a cron job read the same number. There is no warn mode: IP §6.4 says the
   deployment fails.

### What object lock does not protect against

Recorded here because overclaiming is worse than a narrower true claim, and
because RM-009 set the precedent by recording that a Postgres superuser can
disable the ledger's append-only triggers.

- **It expires.** After retain-until, the version is ordinary. A retention
  window shorter than the audit horizon is a deletion scheduled in advance.
  `CanaryOptions.MinBucketRetention` checks the bucket's window against a
  number the operator supplies; this project does not invent one, because doc
  05 §2 pins it to "the organization's audit horizon" and names no value.
- **Governance mode is bypassable** by a caller holding
  `s3:BypassGovernanceRetention`. Compliance mode is the requirement, and the
  bypass attempt in step 4 is how the canary tells them apart in practice.
- **Versions are protected; keys are not.** An ordinary `DELETE` on a locked
  key succeeds — it writes a delete marker — and the segment stops being
  visible to a reader that does not ask for a version. Nothing is destroyed and
  the marker can be removed, but a segment can be *hidden*. The ledger's
  `segment_sealed` events remain the ordered index that makes such a gap
  detectable (ADR-0006). Detection is the claim; prevention is not. The canary
  relies on this permissiveness for its own control in step 5.
- **It is an API-level control.** It says nothing about wiping the volume,
  deleting the tenancy, or a provider acting on the account. It addresses an
  operator with API credentials (doc 04 AB-02), not durability.
- **A run is evidence about one moment**, for one bucket, with one credential.
  A later reconfiguration, a different key, or an object written by a path that
  sets no retention are all outside what it saw. That is precisely why doc 05
  §2 makes it a scheduled job rather than a deploy-time ritual.

## Alternatives considered

**A. Read the bucket's object-lock configuration and trust it.** Cheap, needs
no probe and leaves no residue. It loses because it answers a different
question: a configuration is a record of an intention, and IP §6.4 asks what
the storage layer *does*. It is also silent on the case that motivated step 4 —
a governance bucket whose retention the deploying credential can bypass reports
a perfectly healthy configuration.

**B. Attempt the delete but skip the credential control.** This is the vacuous
version, and it is the one that would have shipped without the two prior
incidents. A read-only key produces `AccessDenied` on the delete, which is
indistinguishable at the call site from a retention refusal, and the canary
would certify a bucket it never tested. The control costs one extra delete of
an object nothing protects.

**C. Use a plain unretained control object instead of a delete marker.** It
reads more obviously. It loses on exactly the buckets that matter: in a bucket
with a default retention rule there is no way to write an object that carries
no retention, so the control object would be locked and the control would fail
spuriously on every correctly configured production bucket. Delete markers
carry no retention by construction.

**D. Run the canary as a Go test in CI.** The test binary is not a deployable
artefact, CI's credentials are not production's, and doc 05 §2 requires a
scheduled job in production. SEG-005 exists in `internal/segment` as well — it
is what proves the canary can fail — but the *gate* has to be something an
operator can schedule.

**E. Report a warning and exit zero when deletion succeeds.** IP §6.4:
"deployment fails if deletion succeeds". A warning in a deploy log is a
deletion nobody noticed.

**F. Let the writer create the bucket with object lock enabled.** It would make
first boot easier. It loses because object lock is settable only at creation,
so the failure mode is a silently unlocked bucket that works perfectly until
the day someone tries to delete a record — and it would require bucket-creation
privilege in production for a process that only needs to write objects.

**G. Default to governance mode.** It is operationally friendlier: a mistake
can be undone. That is the same sentence as "a record can be deleted", which is
I4. Doc 05 §2 says compliance, and this ADR does not soften it.

## Consequences

**Easier.** WORM misconfiguration becomes a red deploy rather than a discovery
during an audit. The same binary and the same flags serve the deploy gate and
the scheduled job, so the thing that runs weekly in production is the thing CI
proved. Because segment names are content addresses (ADR-0006), the writer's
write-once rule needs no coordination: the only legitimate second write of a
name is a write of identical bytes, which is how a crashed sealer resumes
(SEG-002).

**Harder.** Every canary run leaves a probe object that cannot be deleted until
its retention expires. `CanaryOptions.ProbeRetention` exists for that: a
scheduled job can retain probes for an hour while segments are retained for
years, without weakening the check, because compliance mode refuses a deletion
the same way whatever the window. Tests now need a containerised MinIO, and it
is pinned to a release tag rather than a major version — the subject of the test
is one server's enforcement behaviour, so the version it was observed in is
part of the evidence. `github.com/minio/minio-go/v7` becomes a dependency of
the module.

**Operator-visible surface.** `documentedSubcommands` in `cmd/innsegl` grows
from the five of doc 05 §1 to six. The subcommand set is asserted by test
precisely so this shows up as a deliberate change; it is not a protected string
under doc 08, but it is a contract scripts will come to depend on.

**Now fixed.** The exit statuses above are the interface a deploy step and a
cron job consume. Changing what `3` means, or adding a status that a permitted
deletion can produce, changes the meaning of every green deploy since.

**Exit cost if reversed.** Low for the mechanism — the canary is additive and
nothing depends on its output but the gate. High for the posture: reverting to
a configuration check means every claim that this deployment refuses deletion
rests on a bucket setting nobody exercised, and the two known ways a
configuration check passes while deletion is permitted (an expired window, a
bypass-privileged credential) become invisible again.
