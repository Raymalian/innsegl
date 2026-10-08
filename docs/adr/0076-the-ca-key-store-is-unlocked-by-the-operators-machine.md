# ADR-0076: The CA key store is unlocked by the operator's machine

- Status: accepted
- Date: 2026-10-07
- Deciders: the operator
- Amends: the key-custody overlay of #238 (how the store is unsealed, how the
  CA gets its token, and who is on the store's network)

## Context

Under the file CA, anything that can read Fulcio's trust volume has the CA key
and its password, which sit side by side (ADR-0075). The key-custody overlay
(#238) keeps the key in a store instead: Fulcio holds a token that can ask for
signatures, and no key. Two things kept it off:

- The store starts sealed, and the overlay's only answer was an operator
  typing an unseal key after every restart.
- Fulcio's token had to be minted by hand from a root token and passed in the
  environment, where `docker inspect` shows it.

Measured on the pinned Fulcio: its KMS client reads `VAULT_TOKEN`, then
`BAO_TOKEN`, then `~/.vault-token`, once at start, and never renews the token.
It passes no login options to the client, so Fulcio cannot log in to the store
with a SPIRE JWT.

## Decision

1. **Off by default, on per deployment.** `INNSEGL_CA_CUSTODY=on` in the
   compose `.env` adds the two overlays. Without it the stack is the file CA,
   as OPS-051 requires.

2. **A custodian, beside the store.** `innsegl ca-custodian serve` runs as a
   service of the Sigstore project. On a new store it:
   - initialises it with one unseal share;
   - creates the CA key as a non-exportable P-256 transit key;
   - creates a signer policy that allows signing with that key and reading its
     public half, and nothing else;
   - creates an AppRole whose tokens carry that policy alone, with a 24-hour
     period, and a snapshot role (decision 8).

   It then seals the unseal key and the AppRoles' secret ids to the operator's
   recipients (age, the same recipients as ADR-0074's backup), and revokes the
   root token.

3. **Nothing at rest unlocks the store.** The sealed material is ciphertext on
   a trust volume. The store's own storage is encrypted under its unseal key.
   No root token survives provisioning. Measured: a root token can make a key
   exportable later, so revoking it is what keeps the key in.

4. **The CA's token is a file in memory.** The custodian logs the CA in and
   writes the token, 0600, to a memory-backed volume that Fulcio and the
   bootstrap mount as their home. It renews the token every 8 hours. A login
   revokes the token it replaces. No token is in any environment or compose
   file.

5. **The operator's machine unlocks it.** After a restart the store is sealed,
   and Fulcio refuses to start. The client service asks the core once a
   minute; only when the store is sealed does it:
   - fetch the sealed material;
   - open it with the operator's Secure Enclave key (one Touch ID);
   - send it back over the machine's enrolled certificate.

   The custodian unseals the store and logs the CA in. `innsegl ca-custody
   unlock` does the same from a terminal. A declined prompt is not asked again
   for 15 minutes. The routes admit the same machines as the backup:
   - an active workstation of the operator organisation,
   - enrolled by its owner or an admin.

6. **The store's network admits the custodian.** Its members are the store,
   the bootstrap, Fulcio, the custodian, and the one-shot import of #238. A
   second, internal network, the unlock network, has two members: the
   custodian and the core. The core reaches custody only through the
   custodian's three routes (status, sealed material, unlock), and it reads
   and logs none of what they carry.

7. **Turning it on is a rotation.** `make innsegl-ca-rotate TO=custody`
   mints a new root from the store's key and switches Fulcio. It proves a
   real certificate, ends the file CA's era in the trust history (ADR-0073),
   and records the new root. The old key is not imported. The file CA is left
   untouched as the way back. Until the rotation runs, bring-up starts the
   store and the custodian and leaves Fulcio on the file CA.

8. **The backup carries custody, as the store's own snapshot.** The store
   uses integrated storage, one node, so it can snapshot itself. A copy of
   its files taken while it writes is not a backup. The custodian takes the
   snapshot hourly, and at every init and unlock. It uses a third AppRole,
   whose tokens may take snapshots and nothing else; its secret is in the
   sealed material, and its token lives in memory only.

   The trust-key backup (ADR-0074) carries the newest snapshot and the sealed
   material, and marks the bundle as a custody bundle. The drill fails a
   custody bundle that lacks either.

   Measured on the pinned store:
   - the snapshot, restored into a new store, leaves it sealed;
   - only the original unseal key opens it;
   - it holds the same CA key (OPS-155, from a real bundle).

## Consequences

- A reader of Fulcio's container or volumes gets a token that can sign while
  it lives, at most a day without the custodian. It does not get the key. The
  token is revocable, and the store keeps an audit trail.
- A reader of the core's disks gets ciphertext. A reader of the core's memory
  during an unlock gets the material. That is no more than a reader of the
  file CA's volume gets today.
- While the store is sealed, signing behaves as in any Fulcio outage: it fails
  closed, and the rest of the recording goes on. Fulcio's log reads `ecdsa
  public keys are not equal` while sealed; `innsegl ca-custody status` says it
  plainly.
- Losing the operator's Secure Enclave key loses the ability to unlock. The
  store's data is then unreadable, as with the backups (ADR-0074). Recovery is
  a new store and a rotation.
- The `ca-import` path of #238 is kept for a deployment that wants the same
  root (OPS-050). Turning custody on through this ADR does not use it.
- Exit cost: `make ca-custody-back`, remove the `.env` line, and rotate to a
  file CA with `make innsegl-ca-rotate`.
