# ADR-0073: Trust roots are kept as an append-only history

- Status: accepted
- Date: 2026-10-07
- Deciders: the operator

## Context

On 2026-09-16 a deployment's trust volumes were recreated. That replaced its
Fulcio CA and started a new transparency log. A third CA existed for a few
hours in between. Nothing kept the old CA certificate or the old log, and they
cannot be recovered.

Every commit signed before then now fails two checks:

- the chain check: "x509: certificate signed by unknown authority";
- the inclusion check: the log "holds no entry".

Nothing in those commits is wrong. The signature is intact, and the trailer
still matches the certificate. What is gone is the evidence.

The verifier (ADR-0034) trusts exactly one root, the one Fulcio publishes now,
and one log key, the one Rekor publishes now. So any rotation, planned or not,
breaks every older commit. Three things were missing:

1. a record of which roots and log keys the deployment had used;
2. a check that old commits still verify, so the loss went unnoticed for three
   weeks;
3. a warning before a CA expires, which forces the same rotation.

I5 still applies: verification must not trust this system's database. A
history of public certificates and public keys is not the ledger. A stranger
can be handed the same file and check it against the same Fulcio and Rekor.

## Decision

1. **The trust history.** `trust-history.json` lists every Fulcio root and
   every transparency-log key the deployment has used. It also lists the SPIRE
   upstream CA and the gateway CA, so their expiry is watched from the same
   place. Each entry is `{kind, key_id, public_pem, first_used, retired_at,
   retired_reason, revoked_at, tree_id}`:
   - `key_id` is sha256 of the SubjectPublicKeyInfo;
   - entries hold public material only, and a private key is refused on read.

   It lives on its own trust volume, `innsegl-trust-history`, which
   `trust-volumes.sh` creates and `down -v` cannot remove. It does not sit in
   the Fulcio CA's volume: no core service mounts that volume, and none
   should. The core writes the history; the query API reads it, read-only.

2. **Append-only.** One function writes the file. It refuses any history that
   drops, reorders or changes an entry. It allows one change to an existing
   entry: setting `retired_at` or `revoked_at` where it was unset.

3. **Seeded on the first start, with no step for the operator.** The reconcile
   companion runs a trust pass on its first cycle and daily after. The pass
   records the material in use now, if the history does not already hold it.
   The first pass on an existing deployment is that deployment's seed:
   - a certificate's `first_used` is its own NotBefore;
   - a log key recorded right after the first root takes that root's date.

   So an existing deployment's history begins when its current root did, not
   on the day this shipped.

4. **The verifier accepts any root and any log key in the history.**
   - Chain check: a certificate passes if it chains to the published root or
     to any Fulcio root in the history.
   - End dates: a root with `retired_at` accepts only entries the log
     integrated before then, within the skew bound. A root with `revoked_at`
     accepts only entries integrated before then, with no skew.
   - Inclusion check: a proof passes under the published log key or any log
     key in the history, with the same end-date rules.
   - The log's signed integration time decides, never the certificate's own
     claim. An end-dated root or key with no signed time is `unavailable`.

   Nothing else changes, and every other check is still required.

5. **Lost roots are named, not trusted.** A `lost_root` entry records a root
   the deployment used and no longer has: the key id its certificates carry as
   their Authority Key Identifier, `lost_at` and a reason, and no public
   material, because that is what was lost. They come from a seed file the
   operator supplies, `trust-lost-roots.json` on the trust volume, which the
   daily pass imports. The ids belong to one deployment and are never in the
   product's code. A fresh deployment has no seed and no lost roots.

6. **A distinct verdict, `pre-history`, for commits whose evidence is gone.**
   All of these must hold:
   - the certificate chains to no root, current or historical, because the
     authority is unknown;
   - the log answered and holds no entry at all for the commit;
   - the trailer matches the certificate;
   - the certificate's Authority Key Identifier names a `lost_root` entry;
   - the certificate's NotBefore is before the history's first verifiable
     entry.

   **The Authority Key Identifier is not cryptographic.** Whoever mints a
   certificate writes its own. A match narrows the label to an era the
   operator named; it does not prove where the certificate came from. A
   certificate from any other unknown CA stays `failed`.

   Then the verdict is "signed before this deployment's trust history began
   (date); cannot be verified". The chain and inclusion checks become
   `unavailable`, and their original findings are kept as evidence.

   The verdict is never a pass:
   - the pass rate counts it as could-not-be-checked;
   - `innsegl verify` exits 7;
   - the dashboard draws it in the unavailable tone with its own label.

   Any other combination stays `failed`.

7. **Sentinel commits, selected by the pass.** For each Fulcio root in the
   history with no sentinel yet, the daily pass verifies the newest commits in
   the core's mirror and keeps the first one that verifies under that root as
   the era's sentinel (`trust-sentinels-auto.json`, append-only). The
   operator's `trust-sentinels.json` is an optional addition, and may pin any
   verdict a sentinel must keep (`verified`, `content-verified` or
   `pre-history`). Every sentinel is verified daily against the history. A
   mismatch is an ALERT line. An era with no sentinel yet is information, not
   an alert. The alert is a log line, not a ledger event:
   `ledger_drift_detected` needs a subject event on the chain, and a sentinel
   from an era the ledger also lost has none. This follows the rule ADR-0013
   set: no honest subject, no append. A new alert event type would be a
   protected schema change and is not made here.

8. **Expiry warnings, and where problems show.** The same pass warns one year
   and 90 days before the current Fulcio root, SPIRE upstream CA or gateway CA
   expires. It writes its problems, each with the time it was first seen, to
   `trust-status.json` beside the history. `GET /_core/status` and
   `GET /api/v1/health` serve the expiry dates and those problems. `innsegl
   status` shows each as a `trust WARN` line and the dashboard overview shows
   them too. Neither changes an exit status, and there is no schema change.

## Alternatives considered

**Keep trusting the published root alone, and rotate rarely.** That is what
broke. A rotation is sometimes forced (a lost key, a compromise, an expiry),
and the cost then is every commit ever signed.

**Write the history into the Fulcio CA's volume, next to `ca.crt`.** That
volume holds the CA's encrypted private key. Writing to it would make the CA
key writable by the core. Reading from it would mount the key into the query
API. Both widen what can reach the key, which is the opposite of what
key custody is for.

**Seed the history from a shell step in the Sigstore bootstrap.** It holds the
CA file itself, but it cannot see the SPIRE or gateway CAs. Under key custody
it does not mint the root. Producing JSON and RFC 3339 dates from portable
shell is also fragile across the shells it runs in. The core already fetches
the published root and key over the same endpoints a stranger uses.

**Report pre-history commits as `failed`.** That accuses commits nothing was
found wrong with. It also trains the reader to ignore `failed`, the same reason
ADR-0034 refuses to judge validity against the wall clock.

**Report them as `unavailable`.** In this system, `unavailable` means "an
upstream could not be reached; retry". These commits will never verify, and
saying "retry" would be untrue.

**Verify the CMS signature in process, so a pre-history commit can be proven
signed by its certificate.** ADR-0034 rejected this under IP §7. It would also
prove only that the commit was signed under a certificate whose CA nobody can
check. See the consequences below for what that limit means.

**Record rotations in the ledger now.** A new event type is a protected schema
change and needs the major-release procedure. It is deferred, not refused.

## Consequences

- A planned rotation no longer breaks old commits, as long as the outgoing root
  and log key are in the history before the switch. A compromise is handled
  with `revoked_at`.
- The history is now irreplaceable. Losing it brings back 2026-09-16 for every
  rotated-away root. It is a trust volume for that reason, and it is in the
  migration's volume table. Off-host backup of it is follow-up work.
- `pre-history` can still be reached by a forgery that copies a lost root's
  Authority Key Identifier into a self-made CA, backdates the certificate and
  matches the trailer. Naming lost roots shrinks the label from "any unknown
  CA" to "an era the operator named"; it does not close this. That is
  deliberate, and it is safe only because the verdict is never a pass. It
  says the evidence is gone, never that the commit is good. The same holds for
  a pre-history commit whose object was rewritten. Without the log entry and
  without in-process CMS verification, a rewrite is indistinguishable from the
  original. Neither case can reach `verified`.
- A deployment created after this ships has a history from its first start.
  For it, `pre-history` cannot occur for commits signed by the deployment.
- Each era gets a sentinel without the operator writing one, once a commit
  under its root reaches the mirror. A lost era cannot be selected for, since
  nothing verifies under it; the operator may pin one with `pre-history`.
- The verdict set grows by one. It is not a protected surface in
  VERSIONING.md. Every consumer that maps verdicts treats an unknown one as
  not verified, and the ones in this repository now name it.
- Exit cost: delete the file and the volume, and the verifier is the one it
  was before. Nothing else reads them.
