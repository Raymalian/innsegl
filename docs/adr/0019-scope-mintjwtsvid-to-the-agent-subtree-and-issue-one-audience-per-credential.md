# ADR-0019: Allow `MintJWTSVID` to the admin credential only inside the agent subtree, and issue exactly one audience per credential

- Status: accepted
- Date: 2026-08-29
- Deciders: Mike

## Context

IP §4 gives `get_credential` in one line:

> `get_credential(run_id, audience)` → `{jwt_svid, expires_at}`. Fails closed if
> run retired, entry missing, or audience not in the allowlist (`sigstore`
> initially).

IP §6.2 gives the substance:

> - SVID expires mid-run → `get_credential` re-fetches transparently; if
>   re-fetch fails, signing blocks. Never sign with an expired credential;
>   never extend TTLs to "help."
> - Audience misuse: a credential minted for `sigstore` presented anywhere else
>   must fail server-side allowlisting (`AUDIENCE_MISMATCH`) and be useless at
>   the wrong relying party. Test both directions.
> - Replay: … a credential from run A used in a `sign_commit` for run B →
>   `INVARIANT_VIOLATION`, alert-level event recorded.
> - Retired run requests anything → `RUN_ALREADY_RETIRED`. Test that retirement
>   is effective immediately (no cached-credential grace path through the MCP).

**The blocker ADR-0012 left, deliberately.** That ADR narrowed the admin
credential to an allowlist of seven entry- and agent-API methods, and wrote
down what it was not doing:

> `MintJWTSVID` *could* be scoped — its request carries the ID in
> `input.req.id` — and is nonetheless denied today, because nothing in this
> repository calls it yet. `get_credential` (E4) will need it; adding it is one
> allowlist line plus one scope rule plus its own denial test.

That denial was **measured before this change**, against the shipped stack, by
the shipped minter:

```
MintJWTSVID(spiffe://innsegl.dev/agent/demo/rm-023/run-21000, sigstore):
  INVARIANT_VIOLATION (not retryable): authorization denied for method
  /spire.api.server.svid.v1.SVID/MintJWTSVID
```

Three further forces shape the decision.

- **Minting is not entry-gated.** `MintJWTSVID` issues an SVID for any SPIFFE
  ID in the trust domain whether or not a registration entry exists for it. So
  an unscoped `MintJWTSVID` on the admin credential does not merely widen the
  entry surface ADR-0012 narrowed — it routes around it completely. AB-10
  ("steal MCP admin credential, mint identities outside agent subtree") would
  be reopened by exactly one allowlist line.
- **Invariant I2** is what a credential's binding is for: "never signed with
  anything but a valid, unexpired, audience-correct credential for the current
  run." Three properties, and all three are properties the *user* of a
  credential has to check, not only its issuer.
- **Invariant I3** is why the ledger is a gate rather than a side effect:
  "Every identity issuance, credential fetch, commit, and retirement produces a
  ledger event."

ADR-0004 has already settled one question this tool would otherwise have to
answer: `get_credential` takes no `idempotency_key` and `credential_issued`
must carry none, because a repeat call is a legitimate re-fetch and each
issuance is a distinct auditable fact.

## Decision

**Allowlist `MintJWTSVID` for the admin credential and scope it with the same
`agent_subtree` rule that scopes an entry batch; and make `get_credential` four
gates, a mint, a check and a record, in that order, caching nothing.**

Seven parts, each of which could reasonably have gone another way.

1. **The policy change is an allowlist line *and* a scope rule, and the
   read-only arm excludes both scoped sets.** `deploy/compose/spire/authz-policy.rego`
   gains `"/spire.api.server.svid.v1.SVID/MintJWTSVID"` in `mcp_admin_methods`,
   a `mint_id_methods` set naming it, `not mint_id_methods[input.full_method]`
   added to the arm that lets an unscoped read-only method through, and a new
   arm `mint_id_methods[input.full_method]; agent_subtree(input.req.id)`. The
   third of those is the one a reviewer should look hardest at: without it the
   new method would match the "names no SPIFFE ID to scope" arm and be allowed
   for every identity in the trust domain. It is written as an exclusion of
   *both* scoped sets so that adding a future method to either set cannot leave
   it unscoped by omission.

2. **Four gates before SPIRE is asked for anything**, in this order: the
   `run_id` must be a run id; the audience must be on the allowlist; the ledger
   must say the run exists and is not retired; and the SPIRE **server** must
   still hold a registration entry for it. The audience gate is second, before
   the run is resolved, because it is a property of the request alone — its
   answer cannot depend on state, so it cannot leak state either.

3. **The run directory's answer is checked, not trusted.** Before an identity
   reaches SPIRE the MCP requires it to satisfy doc 02 §5's grammar (which
   already pins the `/agent/` subtree), to name the run that was asked for, and
   to carry that run's own `{agent_type}/{task_id}/{run_id}`. This is the same
   containment the rego enforces, one layer up, against a component the rego
   cannot see. Neither alone is load-bearing.

4. **Mint, then record, then release.** The action `credential_issued` names is
   the *release* of a credential to a run (doc 02 §3). So a mint whose issuance
   cannot be appended is dropped rather than returned: the caller gets
   `LEDGER_UNAVAILABLE` and no token, and the unreleased SVID expires unused.

5. **Exactly one audience, and no TTL in the request.** A multi-audience token
   is accepted at more than one relying party, which is the misuse IP §6.2
   exists to prevent. A `ttl` field would be this code's opportunity to extend
   one, which IP §6.2 forbids; with the field absent, the server's own
   `default_jwt_svid_ttl` governs — five minutes on the shipped stack.

6. **Retirement immediacy is discharged by caching nothing.** RM-015 measured
   SPIRE's own convergence at 3–7 seconds; IP §6.2 allows no grace path
   "through the MCP". So every call re-reads authoritative state — the ledger
   for retirement, the SPIRE server (not an agent cache) for the entry — and
   there is no credential cache, no run cache, and, by ADR-0004, no
   idempotency store entry either. That last one matters more than it looks: a
   stored reply *is* a cached credential, and a tool that replayed one would
   hand out a credential for a run retired since.

7. **`RequireCredentialFor` is published as the check the user of a credential
   makes**, and `get_credential` runs it on every mint before releasing one.
   Wrong run → `INVARIANT_VIOLATION`; wrong relying party → `AUDIENCE_MISMATCH`;
   outside the validity window → `CREDENTIAL_EXPIRED`. It is a check on the
   credential's metadata; verifying the token's signature is the verifier's job
   (RM-037) and Fulcio's.

Dependencies are installed with `ConfigureGetCredential` rather than through
`Config`, because ADR-0016's registration seam hands a binder nothing but the
server and `server.go` is the one file all five tool authors would otherwise
share.

## Alternatives considered

- **Have the agent fetch its own JWT-SVID from the Workload API, and let
  `get_credential` return nothing but metadata.** It is the option that keeps
  I1 cleanest, because the Workload API attests the caller. Rejected because
  IP §4 makes the tool return `jwt_svid`, and because the MCP could then
  neither bind the audience per call nor record the issuance — I3 requires a
  ledger event for every credential fetch, and an issuance the MCP never saw is
  one it cannot record. The I1 tension this creates is real and is recorded as
  a residual below rather than argued away.

- **Add the allowlist line without a scope rule.** Rejected, and *measured*
  rather than reasoned about: with the method allowlisted and the scope rule
  removed, the same admin credential minted JWT-SVIDs for
  `spiffe://innsegl.dev/innsegl/rogue`, for `spiffe://innsegl.dev/innsegl/mcp`
  — its own admin identity — for `spiffe://innsegl.dev/agent`, for
  `spiffe://innsegl.dev/agent/demo/rm-023`, for
  `spiffe://innsegl.dev/agent/demo/rm-023/run-1/extra` and for
  `spiffe://innsegl.dev/agentx/demo/rm-023/run-1`. That is AB-10 by another
  road, in one line of rego.

- **Scope the mint by trust domain rather than by subtree.** Rejected for the
  same measurement: `spiffe://innsegl.dev/innsegl/mcp` is in the trust domain,
  and a JWT-SVID for the admin identity itself is the worst of the eight.

- **Enforce the subtree only in the Go client.** Rejected on ADR-0012's
  reasoning, which has not changed: a stolen credential does not run our
  client, it runs `grpcurl`. The client check is kept as well (decision 3), as
  defence in depth against a compromised run directory — which is a component
  the rego cannot see.

- **Append `credential_issued` before minting.** Rejected: it records a release
  that may never happen, in an append-only ledger, and a false entry is worse
  than an absent one. The failure this ordering leaves is a minted SVID that
  was never returned to anybody and expires unused.

- **Return the token even when the append fails, and repair later.** Rejected:
  I3 admits no action without a record, and unlike IP §6.5's commit there is
  nothing to reconcile against afterwards — a JWT-SVID leaves no external trace
  the way a Rekor entry does, so a repair pass would have nothing to find.

- **Dedupe repeat calls with an idempotency key so a replay is cheap.**
  Rejected by ADR-0004, and independently by decision 6: a stored reply is a
  cached credential, and IP §6.2 forbids exactly that grace path.

- **Mint one token carrying every allowlisted audience, so one fetch serves
  every relying party.** Rejected: IP §6.2 requires a credential to be
  "useless at the wrong relying party", and a token whose `aud` names two
  parties is useful at both.

- **Pass an explicit `ttl` so the expiry is predictable and testable.**
  Rejected: it is the field through which a TTL gets extended "to help", and
  the test that wanted predictability can read `expires_at` off the reply.

- **Check the audience after resolving the run, so a bad audience on an unknown
  run reports `RUN_NOT_FOUND`.** Seriously considered, because it orders the
  errors from most specific to least. Rejected because it makes the answer to a
  malformed request depend on whether a run exists, which is a state oracle for
  an unauthenticated-by-this-layer caller; and because MCP-008 then needs a
  known-good run to mean anything, which the positive control supplies anyway.

- **Implement `CredentialRuns` here by scanning the chain for
  `run_registered`.** Rejected twice over: it is a full-chain scan on every
  credential fetch, and it would be a second definition of "what is a run"
  alongside the one `register_agent` (RM-022, #30) must already own. Two
  definitions is two things that can disagree about retirement, which is the
  one thing IP §6.2 requires to be immediate.

## Consequences

- **The MCP admin surface grows by one method, and asset A2's blast radius
  grows with it.** A stolen admin credential can now mint a JWT-SVID for any
  identity of the shape `spiffe://innsegl.dev/agent/{a}/{b}/{c}` — including
  one for which no registration entry has ever existed, because `MintJWTSVID`
  is not entry-gated. The MCP itself refuses that (gate 4), but SPIRE alone
  does not. Bounding it to the agent subtree is the containment this ADR buys;
  bounding it further would need a mechanism rego does not have, since the
  policy cannot query the datastore. **Recorded as residual risk, not closed.**

- **An I1 tension, stated rather than implied.** I1 is "no identity without
  attestation". A JWT-SVID minted through the admin API is issued without the
  run's workload being attested *at that moment*; what was attested is the
  workload that matched the entry's selectors when `register_agent` created it,
  and the entry's continued existence is what gate 4 checks. Whether the caller
  of `get_credential` is the run it claims to be is a question about MCP caller
  authentication, which E1 exempts from this project as an authorization
  concern and which no issue in E4 currently owns. **Flagged for the human.**

- **Two seams ship with no production implementation behind them.**
  `CredentialRuns` is `register_agent`'s to satisfy (RM-022, #30), and nothing
  calls `ConfigureGetCredential` because the MCP entry point in `cmd/` does not
  exist yet. Until both land, a served `get_credential` answers
  `INVARIANT_VIOLATION` naming the missing wiring rather than improvising — the
  same "loud and wrong rather than quiet and wrong" posture ADR-0016 took for
  RM-021's error carrier. **Supervisor merge action, not a state to ship.**

- **`credentialLedgerError` is a duplicate of a mapping that belongs one layer
  down.** `*ledger.StoreError` carries IP §4's class strings but does not
  implement `mcp.Classified`, so this file maps it by string identity — which
  is the gap ADR-0016 already flagged for RM-021's carrier. When
  `internal/ledger` implements `mcp.Classified`, this function collapses to
  `Classify`.

- **Doc 07 MCP-014 cannot be finished here, and the reason is a schema gap.**
  The case asks for `INVARIANT_VIOLATION` *and* "alert-level ledger event
  recorded". The refusing tool is `sign_commit`, which is RM-033 (#41) and does
  not exist; and the event has no type. Doc 02 §3's two alert rows are
  `unattributed_signature_detected` (a trust-domain signature with no intent)
  and `ledger_drift_detected` (a ledger claim with no external proof), and a
  cross-run credential presented *before* any signature is neither. Inventing
  an enum value in a protected schema is not an implementing agent's to do.
  **Flagged for the human**: either MCP-014's alert maps onto an existing type
  by a reading this ADR cannot see, or doc 02 §3 needs a twelfth event type in
  a new `schema_version`. What ships instead is the half that is provable —
  the binding is server-side, it is checkable, and a caller that checks cannot
  reach Phase A — following the precedent RM-018 set for SPI-007.

- **Verified, not assumed** (2026-08-29, SPIRE 1.15.3, Docker 29.6.2,
  `deploy/compose/spire.yml`). Four measurements, in order:
  1. Before the policy change, the shipped minter's in-subtree mint was refused
     with `authorization denied for method
     /spire.api.server.svid.v1.SVID/MintJWTSVID`. That run is the red.
  2. After it, the same call on the same connection succeeds and returns a real
     JWT-SVID; the tool end to end returns one whose decoded claims are
     `sub=spiffe://innsegl.dev/agent/demo/rm-023/run-40000` and
     `aud=[sigstore]` — one audience, the run's own identity.
  3. With the method allowlisted but the scope rule removed, six of nine
     out-of-subtree identities were **minted**, including the admin identity
     itself. So the denial is attributable to the scope rule and not to the
     method's presence on the allowlist. (The remaining three —
     `/spire/agent/...`, `/spire/server`, and another trust domain — SPIRE
     refuses on its own account even unscoped.)
  4. With both in place, all nine are refused with `PermissionDenied` naming
     `MintJWTSVID`, and the in-subtree positive control on the same connection
     still succeeds.

- **The SPIRE-upgrade cost ADR-0012 recorded is unchanged**, with one addition:
  `authz-policy-data.json` must continue to mark `MintJWTSVID` `allow_admin`,
  or the method is denied to admin whatever this policy says, and
  `get_credential` stops working with a `PermissionDenied` that names an
  authorization decision no one changed.

- **Exit cost.** Removing the method from the allowlist disables
  `get_credential` entirely and is a one-line, loudly-failing change. Removing
  the *scope rule* while keeping the allowlist line silently reopens AB-10 by
  the mint route, which is why
  `TestGetCredentialAgainstRealSPIRE` asserts nine refusals against the shipped
  compose stack rather than against a fixture. Reversing decision 5 (one
  audience, no TTL) after the first tag changes what a credential is accepted
  for and is a behavioural break for every relying party in the field.
