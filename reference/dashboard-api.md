# Dashboard and query API

## Purpose

`innsegl api` serves the dashboard UI, a read-only query API over the ledger,
and the proof route that verifies a commit (doc 05 §1, doc 06 §7). Every
route except `health` and `proof` needs a signed-in session, opened with a
passkey or, for a person already linked to it, an organisation's own identity
provider (ADR-0062, #485). `innsegl accounts` manages organisations, their members and
invitations, and which machines may enrol. `innsegl erase-organisation`
erases an organisation.

## Commands

```
innsegl api [flags]
innsegl accounts <verb> [flags]
innsegl erase-organisation -account ID [flags]
innsegl admin-credential enrol-code -dsn <auth-writer DSN> [-ttl D]
```

Routes (from `innsegl api -h`):

```
GET /api/v1/runs
GET /api/v1/runs/{run_id}
GET /api/v1/runs/{run_id}/record
GET /api/v1/runs/{run_id}/steps/{n}/diff
GET /api/v1/overview
GET /api/v1/repos
GET /api/v1/proof/{commit_sha}
GET /api/v1/health
POST /api/v1/auth/enrol/begin
POST /api/v1/auth/enrol/finish
POST /api/v1/auth/login/begin
POST /api/v1/auth/login/finish
POST /api/v1/auth/logout
GET /api/v1/auth/session
POST /api/v1/auth/invitation
POST /api/v1/auth/invitation/begin
POST /api/v1/auth/invitation/finish
POST /api/v1/auth/sso/begin
GET /api/v1/auth/sso/callback
POST /api/v1/alert-resolutions/begin
POST /api/v1/alert-resolutions/finish
```

### Scoped reads

Every ledger read answers only the viewer's runs: runs list, run pages and
their steps, overview counts, repositories, alerts, recent verification
and attribution. A run belongs to the organisation of the machine the
gateway mapped it from (`gateway_run_mapping.client_id`). A run no machine
is mapped to is unowned: the operator's own organisation sees those, every
other organisation never does, and `-hide-unowned-runs` hides them from
the operator too. A run outside the viewer's scope answers 404 with the
same body as a run that does not exist. Alerts with no run are unowned.

A person in several organisations sees all of them at once, or one: the
dashboard's switcher sets the `innsegl_organisation` cookie to an
organisation id, and the reads narrow to it. A cookie naming an
organisation the person is not a member of is ignored.

`GET /api/v1/auth/session` also answers the signed-in person's
organisations with their roles, read on every request. The three
`/api/v1/auth/invitation` routes need no session: they are how a person
with no account yet accepts an invitation with a new passkey.

The account routes (all need a session; the account page's Members section
calls them):

| Route | Does |
|---|---|
| `GET /api/v1/account/members?organisation_id=ID` | the members and their roles; the invitations too for an owner or admin |
| `POST /api/v1/account/invitations/begin\|finish` | `{organisation_id, role}`; after a fresh passkey, the link, once |
| `POST /api/v1/account/members/role/begin\|finish` | `{organisation_id, user_id, role}`, after a fresh passkey |
| `POST /api/v1/account/members/remove/begin\|finish` | `{organisation_id, user_id}`, after a fresh passkey |
| `POST /api/v1/account/invitations/accept` | `{code}`: join with the account already signed in |
| `POST /api/v1/account/invitations/withdraw` | `{organisation_id, invitation_id}`: withdraw a pending link; owner or admin, no passkey |
| `POST /api/v1/account/machines/revoke\|suspend\|resume/begin\|finish` | `{machine_id}`, after a fresh passkey; suspended is undone by resume, revoked is final |
| `GET /api/v1/account/sso?organisation_id=ID` | the organisation's sign-in: name for a member; issuer, client id, redirect URI and whether a secret is saved for the owner; never the secret |
| `POST /api/v1/account/sso/configure\|remove/begin\|finish` | owner only, after a fresh passkey; configure takes `{organisation_id, sign_in_name, issuer, client_id, client_secret, keep_secret}` |
| `POST /api/v1/account/sso/link` | `{organisation_id}` or `{sign_in_name}`: where to send the browser to connect the organisation's sign-in to this account; by name is how a person not yet a member joins |
| `DELETE /api/v1/account/sign-ins/{id}` | disconnect one of your own connected sign-ins |

### Organisation sign-in

An organisation's owner can let its members sign in through the
organisation's own OpenID Connect provider (#485). One connection per
organisation: a sign-in name (what a person types on the sign-in page), the
issuer, a client id and, for a confidential client, a secret. Register the
dashboard at the provider with the redirect URI
`<rp-origin>/api/v1/auth/sso/callback`, exactly. Saving fetches the
provider's discovery document first, then asks for the owner's passkey.

The flow is the authorization code flow with PKCE (S256). The state is a
single-use ceremony that expires after 10 minutes and is bound to the
browser that began it by the `innsegl_sso` cookie (HttpOnly, SameSite=Lax,
path `/api/v1/auth/sso/callback`). The ID token's signature must verify
under a key the issuer publishes, with an asymmetric algorithm (RS, PS, ES
or EdDSA; never `none` or HMAC); its issuer, audience (and `azp` when there
are several), nonce, expiry and issue time are checked. The provider must
be https and is never reached at a loopback, link-local or unspecified
address; redirects are not followed. The API trusts the system's
certificate roots; a provider behind a private CA needs that CA added to
the container's roots (`SSL_CERT_FILE`).

A sign-in joins an existing person and never makes one. A person signed in
some other way connects the organisation's sign-in from the account page;
that links the provider's issuer and subject (nothing else: no email, no
name) to their account and makes them a member if they never were one. An
identity no account holds is refused; one already linked to another account
is refused. The session is the same cookie a passkey opens, and names the
connection. Removing a member revokes all their sessions, these included,
and the organisation's sign-in does not bring them back; an invitation
does. Changing the issuer or client id, or removing the connection, revokes
every session it opened. Passkeys keep working throughout.

When a sign-in is refused the browser lands on `/?sso=<reason>` (or
`/account?sso=<reason>` for a connect): `expired`, `browser`, `denied`,
`changed`, `provider`, `refused`, `unknown`, `removed`, `taken`, `internal`.
Auth events record the connection id and the reason, never anything the
provider sent; the audit trail records `sso.configured` and `sso.removed`
by connection id only.

### Roles

Three roles. They decide what a person may change in the accounts data.
They never decide what an agent may do: scope checks read the
installation and the grants, never a role.

| Action | owner | admin | member |
|---|---|---|---|
| read the ledger, resolve alerts, own passkeys and sign-ins | yes | yes | yes |
| connect a machine | yes | yes | yes |
| revoke, suspend or resume a machine | yes | yes | their own only |
| invite, change a role, remove a member (not an owner) | yes | yes | no |
| give or take the owner role, invite an owner | yes | no | no |
| erase the organisation | yes | no | no |
| set or remove the organisation's sign-in | yes | no | no |

The last owner cannot be removed or demoted. Removing a member ends the
membership, revokes every session of that person, and suspends the active
installations they connected in that organisation, in one transaction.
The gateway reads an installation's status with a 30 second cache, so a
suspended machine is refused within 30 seconds.

An invitation is a single-use link, `<origin>/invite#iv_<64 hex>`, valid
for 72 hours. Only a hash of the code is stored and no email is asked for
or kept. The code is in the URL fragment, which a browser never sends to
a server. The dashboard's `/invite` page reads it: a person with no
account gives a display name and creates a passkey, then saves their
recovery codes; a signed-in person joins with the account they have.
A person in several organisations gets a switcher in the header (see
Scoped reads); connecting a machine from the account page mints the token
for the organisation it names.

`innsegl accounts` verbs (each takes `-dsn`, default `$INNSEGL_API_AUTH_DSN`,
which is set in the `innsegl-api` container: run them as
`docker exec innsegl-api innsegl accounts <verb> …`; without it the error
says so). Listings print a header line first. Without `--by` a change is
the operator's and is audited with no actor; with `--by USER` it is that
user's, and their role is checked as the dashboard checks it.

| Verb | Arguments | Does |
|---|---|---|
| `list` | | every account: `ID NAME OPERATOR OWNERS REPOS` |
| `new` | `--name NAME [--owner USER]` | create an account, with its first owner; prints its id |
| `members` | `--account ID` | `USER NAME ROLE SINCE` |
| `set-role` | `--account ID [--by USER] USER ROLE` | give a member the role `owner`, `admin` or `member` |
| `remove-member` | `--account ID [--by USER] USER` | end a membership; revokes their sessions, suspends their machines there |
| `invite` | `--account ID --role ROLE [--by USER] [--origin URL]` | the invitation link on stdout; `--origin` defaults to `$INNSEGL_API_RP_ORIGIN` |
| `invitations` | `--account ID` | `ID ROLE STATE CREATED-BY ACCEPTED-BY EXPIRES` |
| `withdraw-invitation` | `--account ID [--by USER] ID` | withdraw a pending invitation |
| `audit` | `[--account ID] [--limit N]` | `AT ACCOUNT ACTOR ACTION SUBJECT DETAIL`, newest first; `--limit` 200, 0 for all |
| `enrol-token` | `--account ID --by USER --repos a,b\|* [--kind workstation\|service]` | a 15-minute single-use token for `innsegl connect` |
| `installations` | `[--account ID]` | every account's installations, or one account's: `ACCOUNT ID STATUS KIND NAME REPOS OPERATOR-AUTHOR`; the last column is the pinned operator author, `-` for none |
| `revoke-installation` | `ID` | revoke one installation, for good |
| `author-reset` | `ID` | clear one installation's pinned operator author ([commit-path.md](commit-path.md)) |
| `grant-repo` | `--account ID REPO` | give an account a repository |
| `recovery-codes` | `--user ID` | replace a user's recovery codes |

`enrol-code` mints the one-time code the first passkey enrolment (or a
recovery) consumes. `scripts/setup-link.sh`, run by `make start`, prints the
setup link while no account exists.

`innsegl erase-organisation -h`:

```
Flags:
  -account string
    	the organisation's id: the ID column of innsegl accounts list
  -body-dir string
    	the core's captured bodies; the bodies of runs in each erased repository are removed ($INNSEGL_MCP_LOG_DIR)
  -by string
    	the owner who asked; refused unless they are a live owner (default: the operator)
  -dsn string
    	the ledger database as its OWNER; no service role can delete an alias ($INNSEGL_LEDGER_DSN)
  -mirror-dir string
    	the core's repository mirror; each erased repository's mirror is removed ($INNSEGL_MIRROR_DIR)
```

It runs as the database owner, like `innsegl erase-repository`
([repository-names.md](repository-names.md)). In one transaction it erases
the aliases of every repository only this organisation held, revokes its
members' sessions, and deletes its enrolment tokens, invitations,
memberships, repository grants, installations, sign-in connection, pending passkey
confirmations and account row; then it removes those repositories'
mirrors and the captured bodies of every run registered in them. A
repository another organisation holds now keeps its name. Users are kept:
a person may belong to another organisation. The deployment's own
organisation cannot be erased. No event changes. The audit trail keeps
its rows (it refuses deletion) and gains one `account.erased` row with
counts and pseudonyms. Audit rows hold ids only (account, user,
installation, grant, token), never an organisation or machine name or a
repository, so nothing readable about an erased organisation remains.
Rows written before this release may still hold names.

## Settings

`innsegl api` (defaults in brackets):

| Flag | Variable | Meaning |
|---|---|---|
| `-listen` | `INNSEGL_API_LISTEN` | [`127.0.0.1:8082`] |
| `-tls-listen`, `-tls-cert` | `INNSEGL_API_TLS_LISTEN`, `INNSEGL_API_TLS_CERT` | HTTPS, from the certificate the core writes |
| `-dsn` | `INNSEGL_API_DSN` | READ-ONLY ledger credential; a writing one is refused |
| `-auth-dsn` | `INNSEGL_API_AUTH_DSN` | auth-writer credential; required |
| `-resolver-dsn` | `INNSEGL_API_RESOLVER_DSN` | may insert an alert resolution only; optional |
| `-rp-id`, `-rp-origin` | `INNSEGL_API_RP_ID`, `INNSEGL_API_RP_ORIGIN` | WebAuthn RP ID (a domain) [`localhost`] and origin [`http://localhost:8082`] |
| `-session-lifetime` | `INNSEGL_API_SESSION_LIFETIME` | 0 is the package default |
| `-ui-dir` | `INNSEGL_API_UI_DIR` | built UI, served on the same origin |
| `-fulcio-url`, `-rekor-url`, `-issuer` | `INNSEGL_FULCIO_URL`, `INNSEGL_REKOR_URL`, `INNSEGL_OIDC_ISSUER` | proof route |
| `-trust-history` | `INNSEGL_TRUST_HISTORY` | read on every proof |
| `-mirror-dir` | `INNSEGL_MIRROR_DIR` | the only place repositories are read from |
| `-git` | `INNSEGL_GIT` | git binary; empty is a PATH lookup |
| `-log-dir`, `-log-retention-days` | `INNSEGL_API_LOG_DIR`, `INNSEGL_API_LOG_DAYS` | tool-call bodies [`90` days] |
| `-snapshot-dir` | `INNSEGL_API_SNAPSHOT_DIR` | workspace snapshots |
| `-message-key-dir` | `INNSEGL_API_MESSAGE_KEY_DIR` | check-only agent-message key |
| `-gateway-ca-cert` | `INNSEGL_API_GATEWAY_CA_CERT` | fingerprint pinned by the connect command shown to users |
| `-hide-unowned-runs` | `INNSEGL_API_HIDE_UNOWNED_RUNS` | hide runs no machine is mapped to from the operator's organisation too; default `false` |
| `-upstream-timeout`, `-shutdown-timeout` | `INNSEGL_API_UPSTREAM_TIMEOUT`, `INNSEGL_API_SHUTDOWN_TIMEOUT` | [`15s`, `15s`] |

Compose: `INNSEGL_BIND` [`127.0.0.1`], `INNSEGL_DASHBOARD_PORT` [`8082`],
`INNSEGL_DASHBOARD_TLS_PORT` [`8443`].

## Files, volumes, containers

| Item | Holds |
|---|---|
| `innsegl-api` | its own image: the runtime plus the built UI (`Dockerfile` target `api`) |
| volume `innsegl-dashboard-tls` | certificate and key, written by the core |
| `web/` | the dashboard source (`npx tsc --noEmit && npm run build && npm test`) |
| migrations `0013`, `0014` | alert resolutions and account ceremonies |
| migration `0019` | organisation sign-in: `sso_connections`, `oidc_identities`, `sessions.sso_connection_id`, the `sso` ceremony kinds |
| migration `0017` | invitations' acceptor and withdrawal, an inviter-less invitation from the CLI, the member ceremonies |
| `innsegl_auth.audit` | one row per change to the accounts data; refuses `UPDATE`, `DELETE`, `TRUNCATE` |

## Exit codes and error classes

| Command | Code | Meaning |
|---|---|---|
| `api` | 11 | UNAVAILABLE: could not start |
| `api` | 12 | FAILED: stopped on an error while serving |
| `api` | 13 | WRITABLE: the database credential can write; refused |
| `accounts` | 2 | the command line was not understood |
| `accounts` | 19 | the database could not be opened, or the verb failed, including a role that does not allow the change |
| `erase-organisation` | 0 | erased |
| `erase-organisation` | 2 | usage: no `-account`, no `-dsn` |
| `erase-organisation` | 5 | the organisation was erased and a mirror was not removed; remove it by hand |
| `erase-organisation` | 6 | not erased: no such organisation, the operator's own, `-by` not an owner, or the role cannot delete aliases |

API answers on the member routes: 403 when the role does not allow the
change, 404 for no such member or an unusable invitation link, 409 for the
last owner or an existing membership. On the sign-in routes: 404 for no
sign-in under that name, 502 when the provider's discovery document does
not load or names another issuer, 409 for a sign-in name another
organisation holds.

## Tests

- `internal/api/*_test.go` (API-001 to API-033, AUTH-001 to AUTH-004,
  ALR-002 to ALR-004, RPG-001 to RPG-006)
- `cmd/innsegl/api*_test.go` (API-008 to API-011, VER-001), `dashboardtls_test.go`
- `cmd/innsegl/accountscli_test.go` (ACC-001), `internal/accounts/*_test.go`
  (ACC-001 to ACC-003)
- `internal/accounts/members_test.go`, `invitations_test.go`, `erase_test.go`,
  `migration_test.go` (ACC-004 to ACC-007, ACC-009 to ACC-011, AUTH-006,
  AUTH-007; real Postgres)
- `internal/api/accountmembers_test.go`, `accountorg_test.go` (ACC-004,
  AUTH-005 to AUTH-007)
- `internal/api/accountsuspend_test.go`, `internal/accounts/organisations_test.go`
  (ACC-016: suspend and resume, migration 0018's ceremony kinds)
- `internal/api/scope_test.go`, `scoperelatives_test.go` (API-035: every read answers the viewer's
  runs only; API-036: another organisation's run reads as no run; ACC-013:
  the switcher narrows; ACC-014: unowned runs are the operator's), and
  `cmd/innsegl/apiscope_test.go` (ACC-014's setting)
- `cmd/innsegl/accountsorgcli_test.go`, `eraseorganisation_test.go`
  (ACC-005, ACC-006, ACC-009 to ACC-011, AUTH-006)
- `internal/accounts/erase_test.go` (ACC-015: no accounts table names an
  erased organisation; ACC-017: the runs whose bodies erasure removes)
- `cmd/innsegl/noprincipal_test.go` (ACC-012: no organisation or person
  identifier in the machine certificate, the run's SPIRE entries, the
  commit trailers, the ledger schema or the gateway log)
- `test/deploy/apiui_test.go`, `readerrole_test.go` (OPS-011 to OPS-013),
  `resolverrole_test.go`
- `scripts/setup-link-selftest.sh`
- organisation sign-in (#485): `internal/api/ssooidc_test.go` (AUTH-010:
  every way an ID token, discovery, PKCE or a redirect URI can be wrong),
  `sso_test.go` (AUTH-008 to AUTH-011 through the server),
  `internal/accounts/sso_test.go` (AUTH-008, AUTH-011 against the real spine
  and migration 0019), `cmd/innsegl/apisso_test.go` (AUTH-011 end to end
  through `innsegl api`), and ACC-012's scan for the provider's identifiers.
  The provider is `internal/oidctest`: TLS, signed tokens, exact redirect
  URIs, PKCE, single-use codes
- `internal/api/accountwithdraw_test.go` (ACC-018)
- `web/` unit tests (`npm test`): FE-146 (`AccountPage.test.tsx`), FE-147
  (`AccountMembers.test.tsx`), FE-148 (`app/plain-empty-states.test.ts`), FE-141 (`AccountPage.test.tsx`), FE-142
  (`app/OrganisationSwitcher.test.tsx`), FE-143 (`InvitePage.test.tsx`),
  FE-144 (`run-page/scoped.test.tsx`), FE-149 (`SignInPage.sso.test.tsx`), FE-150
  (`AccountSSO.test.tsx`), FE-151 (`AccountPage.test.tsx`)
- `web/tests/a11y/organisations.pw.ts` (FE-142, FE-143 in Chromium, axe in
  both themes)

## Decisions

- [ADR-0038](../docs/adr/0038-headless-primitives-with-a-governed-token-layer-over-ibm-carbon.md) UI primitives and tokens
- [ADR-0044](../docs/adr/0044-resolve-an-alert-into-a-separate-table-and-keep-the-write-off-the-read-only-dashboard.md) alert resolution
- [ADR-0054](../docs/adr/0054-alerts-live-in-a-header-notification-menu.md) alerts menu
- [ADR-0062](../docs/adr/0062-reading-the-ledger-requires-a-signed-in-user.md) signed-in users
- [ADR-0065](../docs/adr/0065-a-per-repository-mirror-on-the-core-is-the-evidence-store.md) the mirror
- [ADR-0066](../docs/adr/0066-one-name-one-certificate.md) dashboard certificate

## Runbooks

- [cutover.md](../runbooks/cutover.md)

**Add a second organisation.** The deployment must be pseudonymous first
(ACC-008, [repository-names.md](repository-names.md)). Then
`docker exec innsegl-api innsegl accounts new --name NAME`, and
`docker exec innsegl-api innsegl accounts invite --account ID --role owner`
for its first owner; send them the link. They open it, add a passkey, and
are its owner.

**Remove a member.** `innsegl accounts remove-member --account ID USER`, or
an owner or admin from the dashboard. Their sessions end now; machines they
connected there are suspended within 30 seconds. `innsegl accounts
installations --account ID` shows them; an admin may reactivate one the
organisation keeps.

**Erase an organisation.** Run `innsegl erase-organisation -account ID` with
the database owner's DSN and the mirror directory. It is deliberate and
cannot be undone. An erasure is complete once every backup taken before it
has expired.
