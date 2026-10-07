# ADR-0075: Each host has its own CA password, and the CA rotates by script

- Status: accepted
- Date: 2026-10-07
- Deciders: the operator
- Amends: ADR-0073 (how a rotation writes the trust history)

## Context

The Fulcio CA key is stored encrypted. Until now its password came from
`INNSEGL_FULCIO_CA_PASSWORD`, and the compose files gave that variable a
default. A default in a public repository is a password everyone has. A
deployment's CA key was found locked with it.

The password also reached Fulcio as a command-line argument. `docker inspect`
showed it.

ADR-0073 made old roots verifiable after a rotation, but nothing performed a
rotation. The bootstrap never replaces a CA, by design. A rotation done by
hand is the kind of step that lost a CA on 2026-09-16.

## Decision

1. **A password per host, generated at install.** The Sigstore bootstrap
   draws 32 bytes from openssl's CSPRNG into `ca.pass`, as hex, when there is
   none. No shipped file gives a key password a default. OPS-130 fails the
   build if one does.

2. **It lives in the Fulcio CA's own trust volume, beside the key.** Not in a
   volume of its own. The password must go everywhere the key goes: backups,
   migrations, cutovers, archives. A separate volume is one more list to keep
   in step, and a backup that carried the key without its password would
   restore a CA nobody can open.

   The cost is plain: whoever can read that volume gets both. That was
   already true of the old default, and the password never was the control
   against such a reader. The mount table is (one writer, one reader,
   read-only), and key custody (rung 3) is the answer for a reader. What the
   password does protect: a copy of `ca.key` that travels on its own.

3. **Fulcio reads it from its own config file.** The bootstrap writes
   `serve.yaml` with `fileca-key-passwd` from `ca.pass`, and Fulcio starts
   with `--config=/etc/fulcio/serve.yaml`. The value is in no compose file,
   no command line and no `docker inspect`. Measured on the pinned Fulcio
   release: it starts with the right password in that file, and refuses to
   start with a wrong one. The Fulcio image is distroless, so a shell wrapper
   is not possible.

4. **Existing hosts move with no manual step,** on the next run of the
   bootstrap, which every `make update` runs:
   - `ca.pass` exists: it is the password; the variable is no longer read.
   - the variable is set: it must open the key, then it is written to
     `ca.pass` once.
   - neither, and the key opens with the old public default: the key is
     re-locked under a generated password. Open with the old, write the new,
     open with the new, check the old no longer opens and the public key is
     the same, then rename. A run stopped between the two renames is
     finished by the next one.
   - neither, and it does not: refused, naming the variable to set once.

   The old public default is never adopted, even when the variable holds it.
   `make update` now recreates a file-CA Fulcio, so it starts reading
   `serve.yaml`. A Fulcio under key custody is left alone.

5. **Rotation is `make innsegl-ca-rotate`** (`scripts/ca-rotate.sh`,
   `runbooks/trust-rotation.md`):
   - pre-flight refuses unless `CONFIRM=rotate`, a `MODE` (`retire` or
     `revoke`) and a `REASON` are given; the stack is up; Fulcio is the file
     CA on `serve.yaml`; the root it serves is the root on its volume; and
     the trust history holds that root. Optionally, a trust-key backup newer
     than N hours.
   - then: archive the CA in its own volume, still locked with its own
     password, never deleted; make the new CA the way the bootstrap makes the
     first; switch and restart Fulcio; prove a real certificate chains to the
     new root; end the old root in the history; record the new root.
   - a failure before the switch leaves everything as it was. A failure after
     it puts the archived CA back and restarts Fulcio.

6. **The history is written last, at the time of the switch.** This amends
   the order ADR-0073's rotation implies. The history is append-only, so an
   end date written before the switch could never be taken back if the
   switch then failed: the root in use would be marked revoked. So the end
   date is the switch time, written once the new root is proven. Under
   `revoke`, the old root vouches only for entries the log integrated before
   that time, with no skew, whenever the date was written down.

7. **`retired_reason` is kept like the dates.** It may be set where it was
   empty, never changed. Before this, a Save could rewrite it.

## Alternatives considered

**The variable, with no default.** Every install would need a manual step to
pick a password, and the value would still be on Fulcio's command line.

**A small static helper that reads the file and execs Fulcio.** It would need
building and shipping into a third-party image's container, and the value
would then sit in the Fulcio process's arguments. Fulcio's own config file
needs neither.

**A separate trust volume for the password.** See decision 2: recoverability
over a separation the password never provided.

**Write the end date before the switch, as a first step.** A failed switch
could then not be rolled back cleanly. See decision 6.

## Consequences

- No shipped file holds a CA password. A fresh host's password exists only
  on that host and in its trust-key backups.
- `INNSEGL_FULCIO_CA_PASSWORD` is read once, by the first bootstrap of this
  release, and can then be removed from `.env`.
- Each rotation adds an archive of a few kilobytes to the CA volume.
- `revoke` also refuses good commits the old CA signed in the minute of the
  switch. The runbook says to pause agents first.
- Not covered: a CA under key custody, a lost CA key (restore it from backup
  first), and the transparency log's key. A rotation is not a ledger event;
  that stays deferred, as ADR-0073 says.
- Exit cost: put `--fileca-key-passwd` back with a value. The password file
  and archives stay where they are, harmless.
