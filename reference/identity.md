# Identity: register, retire, admin credential, identity guard

## Purpose

Every agent run gets a short-lived SPIFFE identity from SPIRE, issued only
by the core, `innsegl serve`, the one process that holds SPIRE admin
(ADR-0053). The gateway registers a run from its own traffic and the reaper
or an operator ends it (ADR-0058); both call the identity engine in process.
The MCP tools in front of that engine are deprecated (ADR-0077). While they
are served, the identity lifecycle listener admits only a repository-scoped
admin credential.

## Commands

```
innsegl serve [flags]
docker exec innsegl-mcp innsegl retire <run_id>   # on the core host
make innsegl-retire RUN=<run_id>                  # the same, from the checkout
innsegl admin-credential keygen -key FILE -jwks FILE [-force]
innsegl admin-credential mint -key FILE -repo host/org/name [-ttl D]
innsegl admin-credential verify -jwks FILE [-token TOKEN]
innsegl admin-credential enrol-code -dsn <auth-writer DSN> [-ttl D]
```

MCP tools (`internal/mcp/tools.go`; names are protected strings). The whole
wire surface is deprecated (ADR-0077): every description begins with the
same notice, the tools keep working, and the binding is removed at the next
major release.

| Tool | Listener | Note |
|---|---|---|
| `register_agent` | admin (`-admin-listen`) when set | creates the run and its SPIRE entry |
| `retire_agent` | admin when set | records `run_retired`, then deletes the entry |
| `get_credential` | main (`-listen`) | a JWT-SVID for one audience |
| `record_event` | main | appends an event |
| `sign_commit` | main | signs in `-workspace` |
| `observe_tool_call` | main | stores a body locally, appends the tool call |
| `describe_workspace`, `observe_session` | main | deprecated (ADR-0071); bound, refuse every call |

`innsegl retire` runs on the core, inside the `innsegl-mcp` container, and
calls the retirement engine the gateway uses, in process, under the core's
own SPIRE admin identity and ledger credential. It needs no listener and no
admin credential. Use it when a run is known to be over; a quiet run is the
reaper's job. Run anywhere else, it has no SPIRE admin identity and exits 21.

`admin-credential`: `keygen` adds a public key to the key set (rotation is an
overlap); `mint` prints one credential for one repository (max TTL 15m);
`verify` explains locally why a credential is refused; `enrol-code` mints
the one-time code for the first passkey (see [dashboard-api.md](dashboard-api.md)).

## Settings

`innsegl serve` (from `-h`; defaults in brackets):

| Flag | Variable | Meaning |
|---|---|---|
| `-listen` | `INNSEGL_MCP_LISTEN` | MCP transport [`127.0.0.1:8080`] |
| `-admin-listen` | `INNSEGL_MCP_ADMIN_LISTEN` | identity lifecycle listener; empty serves all tools on `-listen` |
| `-admin-jwks` | `INNSEGL_MCP_ADMIN_JWKS_FILE` | public key set; required with `-admin-listen` |
| `-health-listen` | `INNSEGL_MCP_HEALTH_LISTEN` | `/healthz`, `/readyz` [`127.0.0.1:8081`] |
| `-also` | `INNSEGL_MCP_ALSO` | companions in this process: `seal`, `reconcile`, `reap`, `gateway` |
| `-dsn` | `INNSEGL_LEDGER_DSN` | the appending ledger credential |
| `-require-append-only-role` | `INNSEGL_REQUIRE_APPEND_ONLY_ROLE` | refuse a role that can UPDATE, DELETE or TRUNCATE |
| `-migrate` | `INNSEGL_MIGRATE` | apply ledger migrations before serving |
| `-identity-mode` | `INNSEGL_IDENTITY_MODE` | `pseudonymous` or `literal` [`pseudonymous`] |
| `-identity-secret`, `-identity-secret-file` | `INNSEGL_IDENTITY_SECRET`, `INNSEGL_IDENTITY_SECRET_FILE` | pseudonym key, at least 16 bytes |
| `-run-token-secret` | `INNSEGL_RUN_TOKEN_SECRET` | per-run token key; unset derives one from the identity secret |
| `-run-ttl` | `INNSEGL_RUN_TTL` | identity lifetime per run; 0 uses the SPIRE package default |
| `-abandon-after` | `INNSEGL_ABANDON_AFTER` | how long a withdrawn run may still resume [`720h`] |
| `-register-rate-calls`, `-register-rate-window` | `INNSEGL_REGISTER_RATE_CALLS`, `INNSEGL_REGISTER_RATE_WINDOW` | register_agent rate limit [`60` per `1m`] |
| `-spire-address`, `-spire-server-id`, `-trust-domain`, `-parent-id` | `INNSEGL_SPIRE_ADDRESS`, `INNSEGL_SPIRE_SERVER_ID`, `INNSEGL_TRUST_DOMAIN`, `INNSEGL_SPIRE_PARENT_ID` | SPIRE admin API |
| `-workload-api` | `INNSEGL_WORKLOAD_API_ADDRESS` | [`unix:///run/spire/agent-sockets/api.sock`] |
| `-svid`, `-key`, `-bundle` | `INNSEGL_MCP_SVID_FILE`, `INNSEGL_MCP_KEY_FILE`, `INNSEGL_MCP_BUNDLE_FILE` | admin SVID from files |
| `-timeout` | `INNSEGL_SPIRE_TIMEOUT` | one SPIRE RPC [`15s`] |
| `-oidc-issuer` | `INNSEGL_SPIRE_JWT_ISSUER` | the issuer SPIRE stamps and Fulcio believes |
| `-fulcio-url`, `-rekor-url` | `INNSEGL_FULCIO_URL`, `INNSEGL_REKOR_URL` | probed by `/readyz` |
| `-gitsign` | `INNSEGL_GITSIGN` | gitsign binary; empty is a PATH lookup |
| `-workspace` | `INNSEGL_WORKSPACE` | root the `sign_commit` tool signs in; empty leaves the tool unconfigured. The commit path signs without it |
| `-observe-body-dir` | `INNSEGL_MCP_LOG_DIR` | where tool-call bodies are kept |
| `-sign-author-name`, `-sign-author-email`, `-sign-author-operators`, `-sign-author-allow-unlinked` | `INNSEGL_SIGN_AUTHOR_*` | commit author and the I6 gate |
| `-idempotency-lease` | `INNSEGL_IDEMPOTENCY_LEASE` | [`1m`] |
| `-session-timeout`, `-shutdown-timeout` | `INNSEGL_MCP_SESSION_TIMEOUT`, `INNSEGL_MCP_SHUTDOWN_TIMEOUT` | [`0`, `15s`] |
| `-clock-skew-bound`, `-health-timeout` | `INNSEGL_CLOCK_SKEW_BOUND`, `INNSEGL_HEALTH_TIMEOUT` | [`0`, `5s`] |
| `-trusted-origins` | `INNSEGL_TRUSTED_ORIGINS` | browser origins allowed to change state |
| `-addr-file` | `INNSEGL_MCP_ADDR_FILE` | publish the bound address |

`innsegl retire` reads the variables the core's container already sets:
`-dsn` (`INNSEGL_LEDGER_DSN`), `-spire-address` (`INNSEGL_SPIRE_ADDRESS`),
`-trust-domain` (`INNSEGL_TRUST_DOMAIN`), `-spire-server-id`
(`INNSEGL_SPIRE_SERVER_ID`), `-workload-api` (`INNSEGL_WORKLOAD_API_ADDRESS`),
`-spire-timeout` (`INNSEGL_SPIRE_TIMEOUT`) [`15s`], `-timeout`
(`INNSEGL_RETIRE_TIMEOUT`) [`30s`].

## Files, volumes, containers

| Item | Holds |
|---|---|
| `innsegl-mcp` container | `innsegl serve`; host ports `127.0.0.1:28080` (MCP), `28081` (health), `28090` (admin) |
| `innsegl-admin-credential-init` | mints the admin key set at bring-up |
| `innsegl-identity-init` | generates the identity secret |
| volumes `innsegl-admin-jwks`, `innsegl-admin-key` | public key set, private signing key |
| trust volume `<prefix>-identity-secret` | the pseudonymisation secret |
| `innsegl-spire-server`, `innsegl-spire-agent`, `innsegl-spire-oidc` | SPIRE (`deploy/compose/spire.yml`) |

The gateway's identity guard (`internal/gateway/registrar.go`,
`lifecycle.go`, `guard.go`) registers runs from traffic. See [gateway.md](gateway.md).

## Exit codes and error classes

| Command | Code | Meaning |
|---|---|---|
| `serve` | 7 | UNAVAILABLE: could not start |
| `serve` | 8 | FAILED: stopped on an error while serving |
| `retire` | 18 | ALREADY ENDED |
| `retire` | 19 | NO SUCH RUN |
| `retire` | 20 | UNREACHABLE: the ledger or SPIRE could not finish; run it again |
| `retire` | 21 | REFUSED: no SPIRE admin identity; run it on the core |
| `admin-credential` | 18 | REFUSED: the credential is not admissible |
| `admin-credential` | 19 | UNUSABLE: the command could not do its job |

MCP error classes (`internal/mcp/errors.go`, protected): `ATTESTATION_FAILED`,
`IDENTITY_UNAVAILABLE`, `CREDENTIAL_EXPIRED`, `AUDIENCE_MISMATCH`,
`LEDGER_UNAVAILABLE`, `SIGNING_UNAVAILABLE`, `TRANSPARENCY_UNAVAILABLE`,
`RUN_NOT_FOUND`, `RUN_ALREADY_RETIRED`, `DUPLICATE_REQUEST`,
`INVARIANT_VIOLATION`.

## Tests

- `internal/mcp/*_test.go` (MCP-001 to MCP-100, PRI-003, PRI-004)
- `internal/mcp/admincred_test.go`, `adminscope_test.go` (MCP-078 to MCP-093)
- `cmd/innsegl/retire_test.go` (MCP-086, on a real Postgres)
- `cmd/innsegl/admincred_test.go` (MCP-090), `adminenrolcode_test.go` (AUTH-002)
- `cmd/innsegl/serve_test.go`, `servewiring_test.go` (MCP-058 to MCP-060),
  `servealso_test.go` (CLI-011, CLI-012)
- `internal/spire/*_test.go` (SPI-001 to SPI-023)
- `internal/identity/pseudonym_test.go` (MCP-001, PRI-001, PRI-002)
- `internal/gateway/registrar_test.go`, `lifecycle_test.go` (GID-001, GID-002, GID-010, GID-011)
- `test/contract/contract_test.go` (MCP and SPI contract)

## Decisions

- [ADR-0011](../docs/adr/0011-compose-spire-admin-api-segmentation.md) SPIRE admin API segmentation
- [ADR-0012](../docs/adr/0012-scope-the-mcp-admin-credential-with-an-opa-authorization-policy.md) admin credential policy
- [ADR-0018](../docs/adr/0018-record-run-registered-before-creating-the-spire-entry.md) record before creating the entry
- [ADR-0020](../docs/adr/0020-retire-a-run-by-its-run-id-alone-recording-before-deleting.md) retire by run id
- [ADR-0025](../docs/adr/0025-rate-limit-register-agent-per-asserted-caller-and-alert-out-of-band.md) register rate limit
- [ADR-0041](../docs/adr/0041-pseudonymise-agent-type-and-task-ref-in-the-spiffe-id-and-resolve-through-the-ledger-row.md) pseudonyms
- [ADR-0052](../docs/adr/0052-a-withdrawn-credential-is-a-lapse-not-a-death.md) withdrawal is a lapse
- [ADR-0053](../docs/adr/0053-issue-a-runs-identity-only-through-the-attested-mcp.md) identity only through the MCP
- [ADR-0056](../docs/adr/0056-a-single-machine-deployment-runs-the-loops-in-the-mcp.md) loops run in the MCP
- [ADR-0058](../docs/adr/0058-an-agents-identity-lifecycle-is-driven-by-its-traffic.md) lifecycle driven by traffic
- [ADR-0077](../docs/adr/0077-the-mcp-wire-surface-is-deprecated.md) the MCP wire surface is deprecated; retire runs on the core
- [ADR-0079](../docs/adr/0079-adoption-runs-on-the-commit-path.md) an ended run's uncommitted work is adopted on the commit path; its identity never signs again (see [commit-path.md](commit-path.md))

## Runbooks

- [spire-admin-access.md](../runbooks/spire-admin-access.md)
- [trust-domain-re-rooting.md](../runbooks/trust-domain-re-rooting.md)
- [orchestrated-run.md](../runbooks/orchestrated-run.md)
