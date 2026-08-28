# ADR-0012: Scope the MCP admin credential with an OPA authorization policy, and name the two things it still cannot scope

- Status: accepted
- Date: 2026-08-28
- Deciders: Mike

## Context

IP §6.10 states the requirement in one sentence:

> MCP admin credential for SPIRE is least-privilege (entry create/delete only,
> scoped to the agent subtree of the trust domain). Test that the credential
> cannot mint entries outside `spiffe://{td}/agent/...`.

Threat model AB-10 is the attacker story — "steal MCP admin credential, mint
identities outside agent subtree" — against asset **A2**, the admin credential
itself. Test catalog SPI-005 is the test, and doc 07 is explicit about who has
to do the refusing: *"Refused by SPIRE authorization."*

ADR-0011 left the gap open, deliberately and in writing:

> **Also recorded:** `admin_ids` grants *full* admin. It does not scope entry
> creation to the `/agent/` subtree, which is what SPI-005 and AB-10 require.

That was measured, not assumed. Before this ADR, on the shipped stack, an
X509-SVID bearing `spiffe://innsegl.dev/innsegl/mcp` called `BatchCreateEntry`
over the admin API and SPIRE created every one of these:

```
spiffe://innsegl.dev/innsegl/rogue                  status:{message:"OK"}
spiffe://innsegl.dev/innsegl/mcp                    status:{message:"OK"}   <- the admin identity itself
spiffe://innsegl.dev/spire/agent/x509pop/deadbeef   status:{message:"OK"}
spiffe://innsegl.dev/agent                          status:{message:"OK"}
spiffe://innsegl.dev/agentx/demo/rm-015/run-1       status:{message:"OK"}
```

A client-side check does not close that. A stolen credential does not run our
client; it runs `grpcurl`. The refusal has to be inside SPIRE.

SPIRE's only mechanism for it is the experimental OPA authorization policy
engine (`server.experimental.auth_opa_policy_engine`). Its shape constrains the
decision: a configured policy **replaces** SPIRE's built-in default wholesale,
the policy is evaluated per RPC with the request body available as `input.req`,
and the result is five booleans — `allow`, `allow_if_admin`, `allow_if_local`,
`allow_if_downstream`, `allow_if_agent` — reconciled against the caller's class
by SPIRE's own middleware.

## Decision

Ship `deploy/compose/spire/authz-policy.rego`: upstream SPIRE 1.15.3's default
policy, unchanged, with `allow_if_admin` narrowed by two conditions.

1. **An allowlist of methods.** An admin SPIFFE ID is authorized only for
   `BatchCreateEntry`, `BatchUpdateEntry`, `BatchDeleteEntry`, `ListEntries`,
   `GetEntry`, `CountEntries` and `ListAgents` — the surface IP §4's tools and
   E3's reaper and reconciler need, and nothing else. Everything else upstream
   marks `allow_admin` (`CreateJoinToken`, `BanAgent`, the bundle, federation
   and local-authority APIs, and all three SVID mint APIs) is denied to admin by
   omission. `r.allow_admin` from upstream's table is still required, so the
   policy can only ever subtract from upstream's default, never add.

2. **A subtree condition on the two methods that name a SPIFFE ID.** For
   `BatchCreateEntry` and `BatchUpdateEntry`, *every* entry in the batch must
   have a `spiffe_id` of exactly `spiffe://innsegl.dev/agent/{a}/{b}/{c}` —
   trust domain pinned, four non-empty path segments under `/agent`, no more and
   no fewer. `BatchUpdateEntry` is included because without it an attacker could
   create an in-subtree entry and then move it out.

`data.apis` is upstream's own `policy_data.json`, shipped verbatim as
`authz-policy-data.json`, so every non-admin caller class behaves exactly as it
does with no policy configured.

**The local socket is not scoped and will not be.** It is unauthenticated by
construction, it is what `register.sh` uses to create the infrastructure entries
the stack needs before any MCP exists, and ADR-0011 contains it with a private
tmpfs rather than with authorization. Narrowing `allow_if_local` would break
bootstrap and would not contain a caller that already has full admin on an
unauthenticated socket.

## Two things this cannot scope, recorded rather than implied

- **`BatchDeleteEntry` is not scoped, and cannot be.** Its request carries
  opaque entry IDs, not SPIFFE IDs, and rego cannot resolve one to the other. A
  stolen admin credential can therefore delete *any* entry in the trust domain,
  including `spire-oidc`'s. That is denial of service and orphaning, not forged
  attribution: AB-10 is about minting, and A5 (availability) already accepts that
  fail-closed design converts many attacks into DoS. Detection is entry
  reconciliation — RM-019 (#27), and abuse case AB-11, which doc 04 still marks
  **open — add TC**.

- **`MintX509SVID` and `MintWITSVID` could not be scoped even if we wanted
  them.** The SPIFFE ID lives inside a DER-encoded CSR, which rego cannot parse.
  They are denied to admin outright. `MintJWTSVID` *could* be scoped — its
  request carries the ID in `input.req.id` — and is nonetheless denied today,
  because nothing in this repository calls it yet. `get_credential` (E4) will
  need it; adding it is one allowlist line plus one scope rule plus its own
  denial test.

## Alternatives considered

- **A client-side check in `internal/spire` and nothing else.** Rejected: it
  refuses nothing an attacker does. `RegisterRun` does validate the ID before
  asking — defence in depth, and it has its own test — but SPI-005 deliberately
  bypasses it via an unexported seam so the assertion is about SPIRE.

- **Leave `admin_ids` full-admin and rely on reconciliation to notice.**
  Rejected: detection after the fact is the control for AB-11 (entries tampered
  with out of band), not for AB-10. IP §6.10 asks for least privilege, and doc 07
  asks for a refusal.

- **Write a policy from scratch rather than editing upstream's.** Rejected: a
  configured policy replaces the default entirely, so a from-scratch policy would
  have to re-derive authorization for every RPC in SPIRE, including the agent and
  downstream paths that keep the stack alive. Every omission would be a silent
  behaviour change. Starting from upstream's file makes the diff the decision.

- **Inline upstream's API table into the rego instead of shipping
  `policy_data.json`.** Rejected: keeping it as a separate verbatim copy makes a
  SPIRE version bump a file copy with a reviewable diff, rather than a merge into
  prose.

- **A stricter `agent_subtree` that also enforces the character grammar of
  doc 02 §5** (lowercase, no leading dash, length bound). Rejected for the policy
  and kept in the client and the event schema. What this rule owns is
  containment; a malformed-but-in-subtree ID is a validation failure, and putting
  a character-class regex in an authorization policy adds a way for a legitimate
  registration to be denied by something no operator can debug from a
  `PermissionDenied`.

## Consequences

- **Easier:** AB-10 is closed by the deployment rather than by convention, and
  SPI-005 asserts a real refusal. Adding to the admin surface now requires
  editing an allowlist that reads like a list of tools, which makes the review
  question obvious.

- **Harder — and this is the real cost:** a SPIRE upgrade now has a second
  moving part. `authz-policy-data.json` is pinned to 1.15.3's table; an upgrade
  that adds an RPC leaves that RPC absent from the table and therefore **denied
  to every caller class**. That is fail-closed and loud, not silent, but it means
  a version bump in `spire.yml` must re-copy the data file from the matching tag
  and re-run TC-SPI. The rego carries that instruction in its header.

- **Also harder:** the feature is upstream-experimental. SPIRE logs a warning at
  every start saying so, and the config key may move in a future release. The
  alternative was shipping a documented AB-10 hole.

- **Verified, not assumed** (2026-08-28, SPIRE 1.15.3, Docker 29.6.2). Three
  measurements, in order:
  1. Without the policy, the admin SVID created all eight out-of-subtree entries
     SPI-005 attempts. That run is the red.
  2. With the policy, all eight are refused with
     `PermissionDenied: authorization denied for method
     /spire.api.server.entry.v1.Entry/BatchCreateEntry`, the server holds no
     entry for any of them, and the in-subtree positive control on the same
     connection still succeeds.
  3. Mutating `agent_subtree` to hold for every path — leaving the policy engine,
     the allowlist and everything else in place — makes the same entries be
     created again. So the denial is attributable to that rule, not merely to a
     policy being configured.
  Plus the control that keeps the reading honest: the identical out-of-subtree
  entry is accepted over the unauthenticated local socket on the same server,
  so SPIRE has no objection to the ID — only to who asked for it.

- **Exit cost if reversed:** low, and dangerous. Deleting the `experimental`
  block from `server.conf` restores SPIRE's default policy in one restart — and
  silently reopens AB-10. SPI-005 is what makes that loud, which is why it runs
  against the shipped compose stack rather than against a fixture.
