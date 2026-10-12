# ADR-0082: A second unlock device: a hardware security key through the dashboard

- Status: accepted
- Date: 2026-10-11
- Deciders: the operator
- Amends: ADR-0074 decision 2 (who the backup is encrypted to), ADR-0076
  decisions 2, 5 and 6 (who the material is sealed to, who unlocks it, and who
  is on the unlock network)

## Context

ADR-0076 seals the CA store's unlock material to the operator's recipients,
and ADR-0074 encrypts every trust-key bundle to the same kind of list. In
practice that list is one hardware-held key on one operator machine. Both
ADRs name the consequence: lose that key and the store cannot be unlocked and
no bundle can be opened. A machine that is away, lost or broken also leaves
signing down after any restart of the store, because nothing else can unlock
it.

Two more facts shape the answer:

- The material is sealed once, when the store is initialised. There is no way
  to add a recipient later without a new store and a rotation.
- The core encrypts only to recipients it can use without a plugin (ADR-0074
  decision 2). A plain age X25519 recipient is one of them, so a new device
  that yields one needs no change to how the core encrypts.

A FIDO2 security key with the `hmac-secret` extension, reached from a browser
through the WebAuthn PRF extension, returns a secret that never leaves the key
without a touch, and only for one credential on one relying-party ID. From
that secret the browser can derive an age X25519 identity. Its public
recipient can join both lists. The core keeps public recipients and
ciphertext, as today.

The cost is the trust model. The code that sees the PRF output is JavaScript
the core serves. A command-line path runs the operator's own binary instead,
but it needs an installed and enrolled machine, which is exactly what the
operator lacks when the usual machine is away.

## Decision

1. **The dashboard path first, and the machine path unchanged.** An owner or
   admin of the operator organisation enrols a security key from the account
   page. The browser derives the key's identity from its PRF output and sends
   only the public recipients. The operator machine's hardware key stays a
   recipient and stays the daily, automatic unlocker of ADR-0076 decision 5.

2. **A PIN and a touch on every use.** Enrolment and every later use require
   user verification (`userVerification: required`) and user presence. A
   ceremony whose assertion lacks the UV flag is refused. The key alone,
   without its PIN, opens nothing.

3. **Hardware keys only, never synced passkeys.** An unlock credential is a
   separate, non-discoverable, cross-platform credential, not the user's
   sign-in passkey. A credential whose backup-eligible (BE) flag is set is
   refused at enrolment. A synced passkey would copy the unlock secret to
   every device and account it syncs to.

4. **The dashboard API joins the unlock network.** `innsegl-api` reaches the
   custodian, through routes allowlisted for it, only to forward an unlock or
   a reseal. It forwards only after it has verified a fresh assertion from an
   active unlock key of an owner or admin of the operator organisation. It
   checks the assertion before it reads the material, and it never logs or
   stores the material.

5. **A strict content security policy before the unlock page.** The dashboard
   sends a content security policy that allows script only from its own
   origin, with a nonce for its one inline script and no `unsafe-inline`. No
   page that derives an identity or handles material ships before that policy
   is in force. This is a hard gate, not a follow-up.

6. **The browser also derives the backup identity.** At enrolment the browser
   derives two identities from two server-chosen salts: one for custody, one
   for backups. Both recipients are recorded. A trust-key bundle is encrypted
   to the recipients set on the host plus every active device's backup
   recipient, so the security key can open backups as well as unlock the
   store. Both derivations are a versioned format, fixed by golden vectors in
   Go and TypeScript, and treated as a protected string once used.

7. **A two-step reseal.** `innsegl ca-custody reseal`, and an Apply action on
   the dashboard, re-seal the same material to the current set of recipients:
   - the operator opens the current material with a working device and
     confirms the new set, each recipient shown with a label and fingerprint;
   - the custodian proves the material against the store before sealing, and
     refuses an empty set, a set without the device that opened it, and a set
     other than the one confirmed;
   - it keeps the previous sealed copy until the new one has been opened again
     with the same device, and restores the previous copy if that is not
     confirmed in time.

   The CA key, the store, the unseal key and the secret ids do not change. A
   newly enrolled key is pending until a reseal applies it.

8. **Revocation is forward-only for now.** Revoking a key removes it from the
   set, and the next reseal stops new copies being sealed to it. It does not
   make older copies unreadable: sealed material inside older bundles, and
   older bundles themselves, still open with it. Rotating the material itself
   is a separate, optional change.

9. **A command-line route later.** A path that uses the security key from a
   terminal, through an age plugin rather than the browser, is left for a
   later change. It is the stronger trust model and serves headless use. It
   does not block this one.

10. **Still no paper recipient.** The recipient sets gain hardware keys only.
    No recipient is kept on paper or as an exportable file.

## Amendments to earlier ADRs

- **ADR-0074 decision 2.** The bundle is encrypted to
  `INNSEGL_TRUST_BACKUP_RECIPIENTS` **and** the backup recipients of the
  active unlock devices, which the custodian publishes beside the sealed
  material. With no such list, the bundle goes to the host's recipients only,
  as before. The core still holds public keys only and still runs no plugin.
- **ADR-0076 decision 2.** The material is sealed to the host's recipients
  **and** the custody recipients of the active unlock devices, and can be
  re-sealed to a new set (decision 7 above) instead of only once at
  initialisation.
- **ADR-0076 decision 5.** The operator's machine is no longer the only
  unlocker. An owner or admin of the operator organisation can unlock from
  the dashboard with an active security key, from any browser that supports
  PRF for security keys. The machine path, its prompt and its admission rule
  are unchanged.
- **ADR-0076 decision 6.** The unlock network has three members: the
  custodian, the core, and `innsegl-api`. The API reaches custody only through
  the routes allowlisted for it, and, like the core, reads and logs none of
  what they carry beyond the forwarding.

## Alternatives considered

**Unwrap on the server.** The browser would send the PRF output, and the API
would derive the identity and open the material. Then the core holds a lasting
identity, in memory and potentially in logs or crash dumps, on every unlock.
Unwrapping in the browser gives the core the material only, which ADR-0076
already accepts it sees at an unlock.

**Synced passkeys as unlock devices.** They work on more browsers and phones.
But their secret is copied to every device and account they sync to, and is
recoverable through that account. An unlock secret must stay on one piece of
hardware (decision 3).

**The command-line path first.** It runs the operator's own code, so a
compromised core cannot harvest a lasting identity through it. But it needs an
installed binary, a plugin, a USB stack and an enrolled machine certificate.
When the usual machine is away, there is no such machine. It remains the
later route (decision 9).

**A paper recipient.** A printed identity survives the loss of every device.
It is also an exportable secret, readable by anyone who finds it, with no PIN
and no touch. The operator declined it on 2026-10-07 and declines it again.

**Encrypt to the symmetric WebAuthn age stanza.** Each encryption would need
the authenticator present. The core writes a bundle every day with nobody
present, so it needs a public recipient.

## Consequences

- Losing the operator's machine no longer locks the operator out. Any enrolled
  security key, with its PIN, unlocks the store and opens new bundles.
- Malicious JavaScript on the dashboard origin, from a compromised core, an
  injected script or a browser extension, can request the PRF output during a
  real touch and keep a lasting identity. The policy of decision 5 closes
  injection, not a compromised core. That identity stays valid until the key
  is revoked and the old ciphertexts age out. This is the main cost against
  the command-line path.
- A compromised API sees the material at the moments the operator unlocks
  through it. That is the same class of exposure the core has today.
- Each recipient is one more key that opens the material. Keep the set small.
- An unlock credential is bound to the dashboard's relying-party ID. Changing
  the dashboard's domain makes every unlock key useless: enrol on the new
  domain and reseal before switching.
- Browsers differ in support for PRF on security keys. Where it is missing,
  the page says so; the operator's machine and any enrolled workstation still
  unlock.
- Enrolment, revocation, unlocks, refusals and reseals are written as
  authentication audit rows, with no secret in any row. The ledger schema does
  not change.
- Exit cost: revoke every unlock key and reseal to the host's recipients; take
  `innsegl-api` off the unlock network. Bundles already encrypted to a key
  still open with it until they are deleted.
