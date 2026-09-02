# Runbook — trust-domain re-rooting after an A1 compromise

**Doc 04 §5.1 deliverable**: *"Trust domain root compromise (A1). … Document the
recovery runbook: new trust domain is a re-rooting event; historical Rekor
entries remain valid under the old root."*

A1 is the top of the blast-radius list for a reason: *"Compromise = mint any
agent identity. Everything downstream inherits this trust."* This is the one
incident where the fastest-looking action — rotate the key, carry on — is the
one that destroys the evidence you will need.

---

## 0. What is and is not true the moment you suspect A1

**The ledger is unaffected and stays unaffected.** I4 admits no deletion and no
mutation, the database refuses both, and a compromise of the signing root does
not reach backwards into records already written. Everything the ledger says
about what happened remains exactly as true — and exactly as limited — as it
was yesterday.

**The identities are the casualty.** Every SVID minted under the compromised
root is indistinguishable from every other. That is not a gap in our tooling;
it is what a root *is*. A holder of the root can mint
`spiffe://innsegl.dev/agent/…/run-42` that is cryptographically identical to
the one the MCP would have minted.

So the recoverable/unrecoverable split, stated before any action:

| | |
|---|---|
| **Recoverable** | the ledger, in full — untouched |
| | the sealed segments and their Rekor anchors |
| | every historical commit's *signature validity* — **provided the old Fulcio root stays published** (§5) |
| | a *bound* on the compromise window, from Rekor's signed integration times |
| **Not recoverable, ever** | within the window: which identities were legitimate. Both kinds chain to the same root. Nothing minted later can settle a question the root was the answer to. |
| | therefore: the *authenticity* of any attribution whose signing certificate was issued inside the window. The signature stays valid; what it proves is now "someone with the root", not "this agent". |

Nothing in this runbook narrows the second row. Do not let a status update
imply otherwise.

---

## 1. Contain (minutes)

Fail closed. Every design decision in this system converts an integrity attack
into an availability problem; this is the moment you cash that in.

1. **Stop issuing.** Stop `innsegl-mcp`. With no MCP there is no
   `register_agent` and no `get_credential`; IP §6 makes that a clean refusal,
   not a corruption.
2. **Stop signing.** Stop anything holding a workload identity in the trust
   domain. A signature produced now lands in Rekor inside the window and widens
   the range of commits you will later have to caveat.
3. **Do not stop Rekor, and do not stop Fulcio.** They are the record of the
   attack. Losing them is the only way to turn a recoverable incident into an
   unrecoverable one.
4. **Do not delete SPIRE entries yet.** The live entry set is evidence. Capture
   it first:

   ```bash
   docker compose -f deploy/compose/spire.yml exec -T spire-server \
     /opt/spire/bin/spire-server entry show \
     -socketPath /run/spire/admin/api.sock > entries-at-containment.txt

   docker compose -f deploy/compose/spire.yml exec -T spire-server \
     /opt/spire/bin/spire-server bundle show \
     -socketPath /run/spire/admin/api.sock > old-bundle.pem
   ```

   (The admin socket is deliberately reachable only from inside the server
   container — ADR-0011. `docker compose exec` is the shipped way in.)

5. **Archive the old Fulcio root and the old Rekor key now**, before anything
   is redeployed. §5 explains why these two files decide whether history stays
   verifiable:

   ```bash
   curl -sS "$INNSEGL_FULCIO_URL/api/v1/rootCert"     > fulcio-root-OLD.pem
   curl -sS -H 'Accept: application/x-pem-file' \
        "$INNSEGL_REKOR_URL/api/v1/log/publicKey"     > rekor-key-OLD.pem
   ```

---

## 2. Bound the window

You cannot say what is trustworthy until you can say *when*. Use timestamps
somebody else signed.

- **Our clock is not evidence.** An event's `ts` is written by our own
  processes. If the MCP host was in scope, it is an input, not a fact.
- **Rekor's `integratedTime` is signed by the log.** It is the best third-party
  bound available in this system.
- **The trust domain root's own certificate** gives you a hard outer edge: no
  identity predates its `NotBefore`.

Enumerate every signature under the old trust domain and set it against what
the ledger says it intended. That is exactly the reconciler's drift job, so
run it over a wide window and read, do not schedule:

```bash
innsegl reconcile -once -json \
  -dsn "$INNSEGL_LEDGER_DSN" \
  -rekor-url "$INNSEGL_REKOR_URL" \
  -workspace "$INNSEGL_WORKSPACE" \
  -trust-domain "$INNSEGL_TRUST_DOMAIN" \
  -drift-window 100000 \
  > drift-investigation.json
```

`-drift-window` is how many of the log's most recent entries a cycle
cross-checks against the chain; widen it until it covers the whole suspected
window. Two finding kinds matter here:

- `unattributed_signature_detected` — a signature under the trust domain with
  **no intent in the ledger**. In ordinary operation this is a reconciliation
  bug. Today it is the attacker's footprint.
- `ledger_drift_detected` — a ledger claim with no external proof.

> Note the direction of trust. The reconciler treats a signature with no ledger
> intent as suspicious *because the ledger is the record of what we asked for*.
> After A1, the ledger's own `run_registered` events are no longer proof that
> **we** asked: an attacker with the root did not need to go through the MCP.
> A signature with a matching intent is therefore weaker evidence than usual,
> not stronger. Say so in the report.

Record: the earliest and latest `integratedTime` you are treating as the window,
and the reasoning. Everything below inherits those two timestamps.

---

## 3. Re-root: a new trust domain, not a new key

Doc 04 §5.1 is explicit that this is a re-rooting event. Two reasons it cannot
be a key rotation:

1. **Rotation does not un-mint.** SPIRE's upstream authority can be rotated and
   the bundle can carry both roots through a transition — which is exactly the
   wrong property here, because it keeps the attacker's identities valid.
2. **A trust domain cannot be renamed in place.** The name is in
   `deploy/compose/spire/server.conf` (`trust_domain = "innsegl.dev"`), in every
   SVID, in every SPIFFE ID in the ledger, and in the URI SAN of every
   certificate Fulcio ever issued. There is no rename; there is a new
   deployment.

And a third reason that is about honesty rather than mechanism: **reusing the
name makes old and new identities indistinguishable by inspection.** After a
re-rooting, a reader must be able to tell from the SPIFFE ID alone which side of
the incident an identity came from. Pick a genuinely new trust domain name.

The SPIFFE ID grammar is a protected string
(`spiffe://{trust-domain}/agent/{agent-type}/{task-id}/{run-id}` —
`internal/spire/entries.go`). **Only the trust-domain component changes.** The
`/agent/` prefix and the three path segments after it do not; changing them
would be a major release with a migration attestation (doc 08).

Steps:

1. Stand up a **new** SPIRE deployment with the new trust domain, its root in a
   KMS or HSM (doc 05 §2, and the reason A1 is survivable at all in the
   production topology; the compose stack keeps it on disk under
   `UpstreamAuthority "disk"`, which is a test posture).
2. Re-attest nodes and workloads against it. Node attestation material from the
   old deployment is in scope of the compromise; regenerate it.
3. Re-create the infrastructure entries:

   ```bash
   INNSEGL_SPIRE_JWT_ISSUER='<new issuer>' deploy/compose/spire/register.sh
   ```

   This creates only the fixed infrastructure entries (today, `spire-oidc`'s
   own identity). Per-run agent entries are the MCP's and are created on
   `register_agent` — never by hand.
4. Point Fulcio at the new OIDC issuer. Fulcio believes **exactly one** issuer;
   `INNSEGL_SPIRE_JWT_ISSUER` is threaded through both compose files for that
   reason (see the `Makefile`'s `sigstore-up`). A stack booted with the two
   halves disagreeing fails in a way that looks like an outage.
5. Bring the MCP up against the new trust domain, and require the append-only
   database role while you are re-deploying anyway:

   ```bash
   innsegl serve -trust-domain '<new>' -require-append-only-role
   ```

6. Run the WORM canary before declaring the new deployment fit. A re-root
   touches credentials, and credentials are what the canary's last check
   depends on:

   ```bash
   innsegl canary -min-bucket-retention 720h
   ```

---

## 4. The ledger crosses the boundary untouched

Do not create a second ledger, and do not start a new chain.

- The event envelope has **no trust-domain member** and no `chain_id` member
  (doc 02 §2; ADR-0005 puts one chain per database). The trust domain appears
  only inside `spiffe_id` values, which are ordinary strings in event bodies.
- So the chain simply continues. Events before the cutover name the old trust
  domain; events after it name the new one. That is the correct record, and it
  is self-describing: the boundary is visible in the data without anyone
  annotating it.
- **Do not delete or supersede historical events.** I4, and the database will
  refuse you anyway (SQLSTATE `IN001`). A `supersedes` correction is for a
  record that was *wrong*; these records are right. What changed is what they
  are evidence *of*, and that is not a property of the record.

> **NOT SHIPPED — and it is a spec gap, not an oversight to route around.**
> There is no event type for a re-rooting. `event_type` values are a protected
> string set (doc 02 §3): `run_registered`, `credential_issued`, `tool_call`,
> `commit_intent`, `commit_recorded`, `commit_intent_expired`, `run_retired`,
> `run_expired`, `unattributed_signature_detected`, `ledger_drift_detected`,
> `segment_sealed`. Adding `trust_domain_rerooted` is a major release with a
> migration attestation (doc 08), which is not an incident action.
>
> Record the re-rooting **outside** the ledger: an ADR under `docs/adr/`, the
> archived bundles from §1, and the window from §2. Do not improvise an
> in-band record by misusing an existing event type — a `ledger_drift_detected`
> whose `reason` describes a re-rooting is a lie about what the reconciler
> found.

---

## 5. Keep history verifiable — the part that is easy to get catastrophically wrong

**`innsegl verify` fetches its trust root live.** It has no root-file flag and
no pinned bundle; it GETs `/api/v1/rootCert` from whatever `-fulcio-url` names
(`internal/verify/sigstore.go`). The consequence:

> Point `innsegl verify` at the **new** Fulcio and every historical commit
> returns **exit 3, FAILED** — *"the certificate does not chain to the root this
> deployment's Fulcio publishes"*. That is a confident, wrong verdict about the
> past, produced by a correct implementation being given the wrong root.

It is `failed`, not `unavailable`, because the check ran and the path genuinely
does not exist under the new root. The tool is behaving correctly. The
deployment is lying to it.

Therefore, as a permanent obligation of the re-rooting:

1. **Keep the old Fulcio's root served, read-only, at a stable URL**, forever
   or for as long as the attribution claims matter. It needs to answer exactly
   one path: `GET /api/v1/rootCert`, returning the PEM you archived in §1.
2. **Keep the old Rekor running, read-only, forever.** The entries *are* the
   evidence. Under ADR-0010 the shipped default is self-hosted Sigstore, so the
   old Rekor is yours to keep and yours to lose. Decommissioning it is the one
   action in this runbook that would actually destroy proof.
3. Verify historical commits against the old pair, explicitly:

   ```bash
   innsegl verify <commit-sha> \
     -repo /path/to/repo \
     -fulcio-url https://fulcio-archive.<your-domain> \
     -rekor-url  https://rekor-archive.<your-domain>
   ```

4. Publish which URL pair covers which date range, next to the window from §2.
   A verifier who does not know which root to use cannot get a right answer.

> **NOT SHIPPED.** There is no `innsegl verify -fulcio-root-file` and no
> pinning of trust material. `internal/verify/sigstore.go` records the boundary
> deliberately: pinning from a file we ship would make verification depend on
> trusting us, which is what I5 forbids. The consequence for A1 is the archival
> obligation above. If pinning is later added, this section changes; until then,
> a re-rooting is an operational commitment to keep two HTTP endpoints alive.

---

## 6. What an operator must not pretend

Say each of these out loud before writing the incident report.

1. **Not: "we rotated the key, so we are clean."** Rotation does not un-mint.
   Every identity minted under the old root remains valid under the old root,
   which is exactly where all the historical evidence lives.
2. **Not: re-sign history under the new root.** A fresh signature over an old
   commit is a *new* attestation, made today, by a *different* identity, about
   an act that happened before that identity existed. It is a false record.
   The system already refuses to help: rewriting a commit changes its SHA, the
   log holds nothing for the new object, and check 2 fails (VER-003).
3. **Not: re-anchor or re-seal historical segments.** A segment is addressed by
   its content; a re-seal of a changed range is a second object claiming
   positions an existing object already claims, which is drift, not repair.
4. **Not: delete the old Rekor entries, the old bundle, or any ledger event.**
   You cannot, you must not try, and the attempt is itself evidence of
   something.
5. **Not: reuse the old trust domain name.** See §3.
6. **Not: "verified under the new root."** Nothing under the new root says
   anything about the past. A green check obtained from the new Fulcio for a
   post-cutover commit is a statement about post-cutover commits only.
7. **Not: a per-commit "probably fine" for the window.** Either a commit's
   certificate was issued inside the window or it was not. Inside, the honest
   statement is: *the signature is valid; the identity it names was mintable by
   the attacker; this attribution is not evidence of authorship.* Publish the
   window and let readers apply it, rather than adjudicating commit by commit
   on intuition.

---

## 7. After the cutover

- Reap orphans left behind on the old deployment before shutting its admin API,
  so the ledger records their expiry rather than losing them silently:

  ```bash
  innsegl reap -dsn "$INNSEGL_LEDGER_DSN" -trust-domain '<old>' -json
  ```

  Exit 0 swept clean · 5 an orphan could not be reaped · 6 could not sweep.

- Re-run the drift sweep against the **new** trust domain on the ordinary
  schedule. Expect noise in the first cycles: entries under the old trust
  domain fall outside the new deployment's scope, and the sweep window is
  bounded, so widen deliberately rather than leaving it wide.
- Re-run the threat model. Doc 04 §6 lists a standing review trigger for
  exactly this, and A1 having fired is the strongest possible one.
- Write the ADR (§4). The re-rooting is a decision with consequences that
  outlive the incident: two archival endpoints, a permanent date boundary in
  attribution, and a trust domain name that can never be reused.

---

## 8. Gaps this runbook had to work around

| Wanted | Status |
|---|---|
| an event type recording the re-rooting | **absent, and protected.** See §4. |
| `innsegl verify -fulcio-root-file` / pinned trust material | absent by design (I5). Creates the archival obligation in §5. |
| a re-rooting mode in the shipped stack | absent. `deploy/compose/` ships one trust domain, `innsegl.dev`, in `spire/server.conf`. A second deployment is a second stack. |
| production key custody | the compose stack uses `UpstreamAuthority "disk"`. Doc 05 §2 requires KMS/HSM in production; that is a deployment property, not something this repository ships. |
| a tool that lists every certificate issued in a window | absent. §2's reconciler sweep is the closest shipped thing, and it is scoped to signatures the log holds. |
| this runbook, exercised | **written, not run.** Unlike `index-rebuild.md`, nothing here was executed: a re-rooting drill needs two full SPIRE + Sigstore stacks. Every command and every path is taken from the shipped configuration and source, but none of them was run end to end for this document. |
