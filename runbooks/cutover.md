# Cutover: move a deployment to a new host

Move a running deployment from `<old-host>` to `<new-host>`, keep every
commit signed before the move verifiable, and turn `<old-host>` into a client
of the new core with a development stack of its own. RM-294 (#470), epic #453.

Every step names the machine it runs on, the check that proves it worked, and
how to undo it. Do not start a step until the check before it passed.

`<core-name>` is the DNS name clients and the dashboard reach the core by.
Keep it: point `<core-name>` at `<new-host>` in step 5, and no client needs
re-pointing. `<repo>` is the innsegl checkout on each host, at the same
commit on both.

## What moves, and what does not

| moves (`scripts/innsegl-migrate.sh`) | does not move |
|---|---|
| the five trust volumes: ledger, transparency log, its signing key, the Fulcio CA, the pseudonymisation secret | `~/.innsegl/ca`: the gateway's public certificate, rewritten on every start from a key that does move |
| SPIRE's server and agent state | `~/innsegl-backups`: a copy of the backups volume, which does move |
| sealed segments, credential keys, the gateway CA key, the mirror, the backups volume | `~/.innsegl/client`: the client on `<old-host>`, replaced in step 7 |
| the log folder (`INNSEGL_LOG_DIR`): every tool-call body, snapshot and telemetry record | containers and images: built or loaded again on `<new-host>` |
| the Rekor tree pin | `deploy/compose/.env`: copied by hand in step 0 |

`scripts/innsegl-migrate.sh volumes` prints exactly what a host would carry,
under the names that host resolves.

## 0. Before you start

**On `<old-host>`**, stack up:

```sh
scripts/innsegl-migrate.sh check
```

Write down the ledger event count, the tree id and the log folder's file
count. Then:

- **Hold a recovery code.** Sign in to the dashboard and confirm you have an
  unused one, or regenerate them on the account page. If the dashboard's
  origin changes (step 9), a recovery code is the only way back in: an
  enrolment code works only while no account exists.
- **Copy the operator settings.** `deploy/compose/.env` on `<old-host>` holds
  anything set there by hand (the ledger role passwords, `INNSEGL_BIND`,
  `INNSEGL_GATEWAY_CLIENT_AUTH`, `INNSEGL_GATEWAY_CERT_NAMES`,
  `INNSEGL_API_RP_ID`, `INNSEGL_API_RP_ORIGIN`). Copy it to
  `<new-host>:<repo>/deploy/compose/.env` without the
  `INNSEGL_SPIRE_PARENT_ID` line, which bring-up writes. **The ledger role
  passwords must match**: they live inside the carried Postgres data.
- **`<new-host>` has never run the stack**, or you will pass `--replace` in
  step 4. Check there: `docker volume ls -q | grep innsegl` prints nothing.

## 1. Freeze the old core — `<old-host>`

```sh
make innsegl-down
docker compose -f deploy/compose/sigstore.yml stop
docker compose -f deploy/compose/spire.yml stop
```

Never `make spire-down` or `make sigstore-down` here: both pass `down -v`,
and SPIRE's state is not a trust volume.

While the core is down, agents keep working. Each client forwards model
traffic to the provider directly and journals what the core did not record
into its outbox, signed with the installation's key; the new core imports it
when it answers (ADR-0068). **Commits signed through the gateway fail until
step 5**: signing is the one thing that never falls back. Keep the window
short.

**Check:** `docker ps --format '{{.Names}}' | grep innsegl` prints nothing.

**Rollback:** `make start` on `<old-host>`.

## 2. Export — `<old-host>`

```sh
scripts/innsegl-migrate.sh export --event-count <count> innsegl.migration.tar
```

It refuses while any container is still running against a volume. The
archive is mode 0600: it holds CA private keys.

**Check:** the last line reads `wrote innsegl.migration.tar (N volume(s), ...)`,
and the line before it names the log folder's file count, matching step 0.
`shasum -a 256 innsegl.migration.tar` (or `sha256sum`); note the digest.

**Rollback:** nothing was changed. Delete the archive and `make start`.

## 3. Copy — `<old-host>` to `<new-host>`

Copy `innsegl.migration.tar` into `<new-host>:<repo>/` by whatever means you
trust. Keep it mode 0600 on the way.

**Check:** on `<new-host>`, the sha256 of the copy equals step 2's.

**Rollback:** delete the copy.

## 4. Import — `<new-host>`

```sh
scripts/innsegl-migrate.sh volumes
scripts/innsegl-migrate.sh import innsegl.migration.tar
```

`volumes` shows the names and the log folder this host will fill. `import`
verifies the manifest, every volume's checksum and every log-folder file's
sha256, and refuses a non-empty target, all before it writes anything. It
refuses on a dev-marked host (ADR-0072). It writes the Rekor pin.

**Check:** `import complete (N volume(s))`, the same N as step 2, and
`loaded the log folder into ... (M file(s))`, the same M as step 0.

**Rollback:** nothing is running on `<new-host>` yet. To retry, run the same
import with `--replace`. To abandon, remove the volumes `volumes` listed and
empty the log folder; `<old-host>` still has everything.

## 5. Bring up — `<new-host>`

```sh
make start
```

Then point `<core-name>` at `<new-host>`.

**Check:**

```sh
scripts/innsegl-migrate.sh check innsegl.migration.tar
```

prints `MATCH`: the ledger event count, the tree id, and a log folder holding
at least the files the archive carried. `trust-volumes:` during `make start`
names the same deployment id `<old-host>` printed. Clients reach the core
again, and their outboxes drain: `curl -s http://127.0.0.1:28195/_client/status`
on a client shows the outbox emptying.

**Rollback:** stop `<new-host>` (as step 1), point `<core-name>` back, and
`make start` on `<old-host>`. Whatever the new core recorded in between stays
on `<new-host>` only.

## 6. Verify a commit signed before the move — `<new-host>`

Pick a commit signed before step 1, in a clone of its repository on
`<new-host>`:

```sh
INNSEGL_FULCIO_URL=http://127.0.0.1:5555 INNSEGL_REKOR_URL=http://127.0.0.1:$(scripts/rekor-port.sh) INNSEGL_OIDC_ISSUER=http://spire-oidc:8080 innsegl verify <sha> --repo <clone>
```

or paste it into the dashboard's **Verify a commit** page.

**Check:** `VERDICT: VERIFIED`, all three checks `verified`. A fresh CA or a
fresh log would fail check 1 or 2. That is the whole point of the move.

**Rollback:** if it fails, go back to step 5's rollback. Do not continue.

## 7. Enrol the old machine as a client — `<old-host>`

On the new core's dashboard, mint an enrolment token (account page,
organisation, connect a machine). Then:

```sh
innsegl connect https://<core-name>:28095 --token <ie_…> --ca-fingerprint sha256:<hex>
```

**Check:** `curl -s http://127.0.0.1:28195/_client/status` names
`<core-name>`, and the machine appears on the account page.

**Rollback:** `innsegl connect --disconnect`.

## 8. Mark the old machine's own stack dev — `<old-host>`

```sh
make dev-stack
```

From now on `make start` here brings up `innsegl-dev-*`: its own names, a
trust root of its own, host folders under `~/.innsegl/dev`, loopback only
(ADR-0072). The old live volumes and `~/.innsegl/log` are left exactly where
they are.

**Check:** `scripts/stack-mode.sh mode` prints `dev`.
`scripts/innsegl-migrate.sh volumes` names `innsegl-dev-*` only.

**Rollback:** delete `.innsegl/stack-mode` in `<repo>`.

Keep the old live volumes and `~/.innsegl/log` until step 6 has passed and
the new host has taken a verified backup. Then remove them deliberately, by
name; `scripts/teardown-guard.sh` stands in front of the trust volumes.

## 9. Passkeys, if the dashboard's origin changed — browser

A passkey is bound to the origin it was made at (ADR-0062, ADR-0066). If
`INNSEGL_API_RP_ID` or `INNSEGL_API_RP_ORIGIN` differ on `<new-host>`, every
passkey made on `<old-host>` stops working there. Accounts and recovery codes
moved with the ledger.

1. Open the new dashboard. Choose **Use a recovery code** and sign in with
   one of the codes from step 0.
2. On the account page, add a passkey.
3. Regenerate the recovery codes. This voids the rest, including any used
   on the old origin.

**Check:** sign out, then sign in with the new passkey.

**Rollback:** none needed: the recovery code is spent, the old passkeys stay
listed and work again if the origin goes back.

## Gaps

| gap | what to do instead |
|---|---|
| No recovery code and a changed origin: an enrolment code is refused once an account exists | Hold a code before step 1 (step 0). |
| `make innsegl-demo` predates the admin credential (#264) and the run token, so it cannot sign on a current stack | Verify with a real pre-move commit (step 6). |
| A fresh `innsegl-gateway-ca-key` volume is root-owned and the gateway cannot use it. A moved one keeps its owner. | Not a cutover problem; affects a first start. |
