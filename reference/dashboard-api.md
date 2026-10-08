# Dashboard and query API

## Purpose

`innsegl api` serves the dashboard UI, a read-only query API over the ledger,
and the proof route that verifies a commit (doc 05 §1, doc 06 §7). Every
route except `health` and `proof` needs a signed-in passkey session
(ADR-0062). `innsegl accounts` manages who may sign in and which machines
may enrol.

## Commands

```
innsegl api [flags]
innsegl accounts <verb> [flags]
innsegl admin-credential enrol-code -dsn <auth-writer DSN> [-ttl D]
```

Routes (from `innsegl api -h`):

```
GET  /api/v1/runs                     GET  /api/v1/proof/{commit_sha}
GET  /api/v1/runs/{run_id}            GET  /api/v1/health
GET  /api/v1/runs/{run_id}/record     POST /api/v1/auth/enrol/begin|finish
GET  /api/v1/runs/{run_id}/steps/{n}/diff
GET  /api/v1/overview                 POST /api/v1/auth/login/begin|finish
GET  /api/v1/repos                    POST /api/v1/auth/logout
                                      GET  /api/v1/auth/session
                                      POST /api/v1/alert-resolutions/begin|finish
```

`innsegl accounts` verbs (each takes `-dsn`, default `$INNSEGL_API_AUTH_DSN`):

| Verb | Arguments | Does |
|---|---|---|
| `list` | | every account: id, name, owners, repositories |
| `new` | `--name NAME` | create an account; prints its id |
| `enrol-token` | `--account ID --by USER --repos a,b\|* [--kind workstation\|service]` | a 15-minute single-use token for `innsegl connect` |
| `installations` | `--account ID` | list an account's installations |
| `revoke-installation` | `ID` | revoke one installation, for good |
| `grant-repo` | `--account ID REPO` | give an account a repository |
| `recovery-codes` | `--user ID` | replace a user's recovery codes |

`enrol-code` mints the one-time code the first passkey enrolment (or a
recovery) consumes. `scripts/setup-link.sh`, run by `make start`, prints the
setup link while no account exists.

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

## Exit codes and error classes

| Command | Code | Meaning |
|---|---|---|
| `api` | 11 | UNAVAILABLE: could not start |
| `api` | 12 | FAILED: stopped on an error while serving |
| `api` | 13 | WRITABLE: the database credential can write; refused |
| `accounts` | 2 | the command line was not understood |
| `accounts` | 19 | the database could not be opened, or the verb failed |

## Tests

- `internal/api/*_test.go` (API-001 to API-033, AUTH-001 to AUTH-004,
  ALR-002 to ALR-004, RPG-001 to RPG-006)
- `cmd/innsegl/api*_test.go` (API-008 to API-011, VER-001), `dashboardtls_test.go`
- `cmd/innsegl/accountscli_test.go` (ACC-001), `internal/accounts/*_test.go`
  (ACC-001 to ACC-003)
- `test/deploy/apiui_test.go`, `readerrole_test.go` (OPS-011 to OPS-013),
  `resolverrole_test.go`
- `scripts/setup-link-selftest.sh`
- `web/` unit tests (`npm test`)

## Decisions

- [ADR-0038](../docs/adr/0038-headless-primitives-with-a-governed-token-layer-over-ibm-carbon.md) UI primitives and tokens
- [ADR-0044](../docs/adr/0044-resolve-an-alert-into-a-separate-table-and-keep-the-write-off-the-read-only-dashboard.md) alert resolution
- [ADR-0054](../docs/adr/0054-alerts-live-in-a-header-notification-menu.md) alerts menu
- [ADR-0062](../docs/adr/0062-reading-the-ledger-requires-a-signed-in-user.md) signed-in users
- [ADR-0065](../docs/adr/0065-a-per-repository-mirror-on-the-core-is-the-evidence-store.md) the mirror
- [ADR-0066](../docs/adr/0066-one-name-one-certificate.md) dashboard certificate

## Runbooks

- [cutover.md](../runbooks/cutover.md)
