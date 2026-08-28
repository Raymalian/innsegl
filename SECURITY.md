# Security policy

Innsegl is an attribution and non-repudiation system; we expect and welcome
adversarial attention. If you can make a false attribution verify, silently
alter history, or obtain an identity without attestation, we want to know
more than you want to tell us.

## Reporting

- Report privately via **GitHub Security Advisories** on this repository:
  the **Security** tab → **Report a vulnerability**. This is the supported
  private reporting channel.
- Do not open public issues for suspected vulnerabilities.
- Include: version/commit, deployment shape (compose reference or custom),
  reproduction steps, and impact against the invariants below if known.

## What counts as a vulnerability here

Anything that breaks a core invariant, in descending severity:

- **I5**: a verification verdict that cannot be independently re-derived,
  or a "verified" state for a forged attribution
- **I1/I2**: identity issuance without attestation; signing with a credential
  outside its run or audience
- **I4**: any path that deletes or mutates a ledger event or sealed segment
  without detection
- **I3**: an attributable action that produces no ledger record
- **I6**: agent activity that adds a contributor on GitHub

Hardening gaps that don't break an invariant (rate-limit tuning, verbose
errors) are welcome as ordinary issues.

### The invariants, in full

| | |
|---|---|
| **I1** | No identity without attestation. No SVID is ever issued to a workload SPIRE did not attest. |
| **I2** | No signing without identity. A commit is never produced unsigned, and never signed with anything but a valid, unexpired, audience-correct credential for the current run. |
| **I3** | No action without a record. Every identity issuance, credential fetch, commit, and retirement produces a ledger event. |
| **I4** | No record is ever deleted or mutated. Corrections are new events referencing old ones (`supersedes`). Retirement deletes the SPIRE entry, never ledger content. |
| **I5** | Verification never trusts this system. Every attribution claim must be checkable against Fulcio/Rekor by a third party with no access to our database. |
| **I6** | No GitHub contributor is ever added. Commit author is the human operator or a deliberately unlinked address; agent identity lives only in trailers and signature. |

## Our commitments

- Acknowledgment within 72 hours; triage verdict within 7 days.
- Coordinated disclosure: we ask for a reasonable embargo while a fix ships;
  we will credit reporters (or honor anonymity) in release notes.
- Fixes to invariant-breaking issues ship with a regression test carrying a
  test-catalog ID, per the project's TDD policy — the advisory links the test.
- No legal action for good-faith research within scope. Out of scope:
  attacks on the public Sigstore infrastructure (report to Sigstore),
  volumetric DoS against demo deployments, social engineering.

## Supported versions

Innsegl is pre-1.0 and has no tagged release yet. Until the first tag,
security fixes land on the default branch. From the first tag onward, fixes
ship in the next release on the current minor line; this section is updated
with the supported lines at that point.

## Verifying releases

Releases are signed with the project's own tooling; the release page
documents the expected signing identity. An unsigned or mismatched release
artifact is itself a security event — report it.
