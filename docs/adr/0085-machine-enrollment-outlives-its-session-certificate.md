# ADR-0085: Machine enrollment outlives its session certificate

- Status: accepted
- Date: 2026-11-12
- Deciders: the operator (approved 2026-11-12)
- Supersedes: ADR-0063 decision 3's certificate-only renewal
  requirement and its consequence requiring re-enrollment after a day offline;
  decision 5's identical refusal only as it applies to authenticated recovery
  diagnostics. The remaining decisions stand.

## Context

ADR-0063 gives each installation a certificate valid for at most 24 hours,
renewed at half-life, and requires re-enrollment after extended offline time.
The implementation adds a further 24-hour renewal grace period. A renewal
refusal stops automatic renewal even when connectivity later returns.

A machine can be asleep or disconnected beyond either period while its
installation remains authorized. Certificate expiry is neither installation
revocation nor provider-session expiry. Requiring a new enrollment token
because of elapsed offline time makes routine connectivity an administrative
recovery operation.

## Decision

Machine enrollment persists independently of its traffic certificate.
Keep the 24-hour maximum certificate lifetime and proactive renewal, but
recover an authorized installation automatically after reconnect using
separately enrolled device proof and a current authorization check. Elapsed
offline time alone does not require another enrollment token.

Recovery preserves installation identity, scope and pending data. It does
not allow expired certificates on ordinary routes, bypass suspension or
revocation, or use a provider login as machine authorization. Lost device
proof or trust requires account-owner authentication. A generic refusal is
not proof of revocation; diagnostics distinguish known facts from unknown
causes and provide a complete recovery or pause action.

## Alternatives considered

- **Only improve refusal messages.** Leaves ordinary offline use dependent
  on repeated manual enrollment.
- **Lengthen certificate validity or the grace period.** Moves the same
  failure to a later outage without separating enrollment from validity.
- **Accept expired certificates indefinitely as the only recovery proof.**
  Extends their authentication role without a separate recovery lifecycle.
- **Use the provider session as device proof.** Does not establish
  authorization for an innsegl installation.

## Consequences

Authorized machines can resume after extended offline periods without new
installation identities. Recovery introduces a device-credential lifecycle
and migration for existing installations. A stolen recovery credential may
obtain certificates until revoked; short traffic-certificate lifetimes do
not bound that capability. Reversal requires withdrawing recovery credentials
and migrating clients, not merely shortening certificate lifetimes.

Acceptance establishes policy; runtime support must be verified. Before implementation, specify
the recovery protocol and migration, reconcile docs 04, 05 and 07, and assign
test-catalog IDs. The local recovery plan carries protocol, diagnostics and
verification requirements. Agent credentials, run lifecycles, provider
logins and protected public vocabulary remain unchanged.
