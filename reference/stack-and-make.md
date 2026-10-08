# Stack modes, trust volumes and make targets

## Purpose

The reference deployment is three compose projects: SPIRE, Sigstore and
innsegl. The Makefile brings them up, updates them and tears them down. A
stack is either live or dev (ADR-0072). The trust root lives in volumes the
teardown cannot reach.

## Commands

Every target with a `##` help line:

| Target | Does |
|---|---|
| `make build` | compile the single innsegl binary |
| `make test` | the full suite with the race detector, through `scripts/test-suite.sh` |
| `make lint` | `go vet` and `golangci-lint` |
| `make cover` | coverage profile and per-function summary |
| `make clean` | remove build and coverage artefacts |
| `make test-clean` | remove containers a killed test run left behind (label `dev.innsegl.test`) |
| `make test-ids` | every test id in the code has a row in doc 07 (local only) |
| `make install-hooks` | set `core.hooksPath` so a commit tracking a local-only spec is refused |
| `make dev-stack` | mark this checkout's stack as a DEVELOPMENT stack, once |
| `make innsegl-trust-volumes` | create the trust volumes (`deploy/compose/trust-volumes.sh ensure`) |
| `make start` | bring everything up, ready to sign; picks a free Rekor port; prints the setup link |
| `make innsegl-up-here` | the stack, built from this working tree |
| `make update` | rebuild and restart only innsegl's services whose image or settings changed |
| `make image-bundle` | build the images once into `dist/` with a `.sha256`, for another host |
| `make link` | install the commit hook in a project (see [commit-path.md](commit-path.md)) |
| `make spire-up` | boot SPIRE and create its bootstrap entries |
| `make spire-verify` | prove SPIRE issues an SVID for an agent run |
| `make spire-down` | tear SPIRE down, volumes included (guarded) |
| `make spire-admin-relay-up` | publish the SPIRE admin API to `127.0.0.1` (off by default) |
| `make spire-admin-relay-down` | remove the admin relay; always run when done |
| `make innsegl-images` | load this checkout's image bundle (ADR-0070), or build the images here; every target that runs `innsegl:local` depends on it, the CA custodian included (OPS-160) |
| `make fulcio-file-ca-run` | Fulcio on the file CA, unless it already runs under custody. `make update` reaches it through `fulcio-file-ca-up`, which picks this or `ca-custody-up` by `INNSEGL_CA_CUSTODY` (OPS-156) |
| `make sigstore-up` | boot SPIRE and Fulcio/Rekor (see [transparency-log.md](transparency-log.md)) |
| `make sigstore-verify` | get a real Fulcio certificate for a real JWT-SVID |
| `make sigstore-down` | tear Sigstore down, volumes included (guarded) |
| `make rekor-tlog-id` | print and pin the log's tree |
| `make rekor-reindex` | backfill the log's search index from the whole log |
| `make innsegl-verify` | ask Postgres and the object store what the credentials can do |
| `make innsegl-canary` | SEG-005: the object store refuses to delete a segment |
| `make innsegl-demo` | register an identity, sign a commit under it, retire it |
| `make innsegl-retire` | end a run an operator knows is over, on the core: `RUN=<run_id>` |
| `make innsegl-init` | run `innsegl init` as a one-shot workload: `REPO=<path> ARGS='...'` |
| `make innsegl-verify-commit` | verify a commit with no route to the ledger: `COMMIT=<sha>` |
| `make innsegl-down` | stop the innsegl stack, keeping the ledger and segments |
| `make innsegl-purge` | tear the innsegl stack down AND delete its data volumes |
| `make innsegl-backup` | `pg_dump` the ledger and verify it against the sealed segments |
| `make backup-freshness` | age of the last verified backup, and whether its host copy landed |
| `make smoke` | the fresh-clone contract (OPS-004); takes the shipped projects down with volumes |
| `make smoke-down` | remove what a kept `make smoke` stack left |
| `make verify-branch` | verify every agent-signed commit on this branch before merging |
| `make verify-branch-selftest` | the branch gate, watched failing |
| `make innsegl-ca-rotate` | replace the Fulcio CA (see [ca-password-and-rotation.md](ca-password-and-rotation.md)) |
| `make innsegl-ca-rollback` | put an archived CA back |
| `make innsegl-ca-custody-init` | custody, once (see [ca-custody.md](ca-custody.md)) |
| `make ca-custody-up` | the CA key store and custodian |
| `make ca-custody-volumes` | the two custody trust volumes |
| `make ca-custody-ready` | is the store unlocked |
| `make ca-custody-stage` | mint the store's root and print it |
| `make ca-custody-restore` | restore custody from a backup |
| `make ca-custody-switch` | Fulcio onto the store |
| `make ca-custody-back` | Fulcio onto the file CA |

`make update` in detail: refuses unless SPIRE and Rekor run; does nothing
when `.innsegl/deployed-commit` matches the checkout and the core runs;
otherwise brings the log's services up again, recreates a file-CA Fulcio,
then builds (or loads a matching bundle from `dist/`) and runs
`docker compose up -d --remove-orphans --no-build`. The deployed state is
the commit plus a checksum of the compose `.env`.

## Settings

Stack mode (`scripts/stack-mode.sh`):

| Signal | Meaning |
|---|---|
| `INNSEGL_STACK=dev\|live` | wins |
| `.innsegl/stack-mode` in this checkout or its main worktree | written by `make dev-stack` |
| neither | live |

A dev stack: names prefixed `innsegl-dev` (overlays in `deploy/compose/dev/`),
trust volumes prefixed `innsegl-dev-trust`, host folders under
`~/.innsegl/dev/`, loopback bind only. The trust domain is unchanged.

Make variables and environment (defaults in brackets):

| Name | Used by | Meaning |
|---|---|---|
| `COMPOSE_ENV_FILE` | all | [`deploy/compose/.env`] |
| `INNSEGL_SPIRE_JWT_ISSUER` | all | [`http://spire-oidc:8080`] |
| `INNSEGL_IMAGE` | verify-commit | [`innsegl:local`] |
| `REPO` | up-here, innsegl-init | `host/org/name`, default from `origin`; for innsegl-init a host path |
| `INNSEGL_MCP_ADMIN_LISTEN` | up-here | [`0.0.0.0:8090`] |
| `INNSEGL_MCP_ALSO` | up-here | empty keeps the compose default |
| `INNSEGL_REBASE_BRANCH`, `INNSEGL_REBASE_REPOS` | up-here | both or neither |
| `INNSEGL_WRITES_LOG_DIR`, `INNSEGL_WRITES_REPOS` | up-here | [`/harness-log`, empty] |
| `INNSEGL_LOG_DIR`, `INNSEGL_GATEWAY_CA_HOST_DIR`, `INNSEGL_BACKUP_HOST_DIR` | up-here | [`~/.innsegl/log`, `~/.innsegl/ca`, `~/innsegl-backups`] |
| `INNSEGL_IMAGE_PLATFORM`, `INNSEGL_IMAGE_BUNDLE` | image-bundle, update | [`linux/amd64`, `dist/` for this commit] |
| `INNSEGL_REKOR_PORT` | many | [`scripts/rekor-port.sh`, compose default `23000`] |
| `INNSEGL_BIND` | compose | [`127.0.0.1`] |
| `DIR` | link | the repository |
| `COMMIT`, `DEMO_REPO` | verify-commit | the commit, and the repository identifier it is in |
| `ARGS` | innsegl-init | flags passed to `innsegl init` |
| `BASE` | verify-branch | [`origin/main`] |
| `INNSEGL_BACKUP_DIR` | innsegl-backup | [`backups`] |
| `INNSEGL_TEST_KEEP_STACK` | smoke | `1` keeps the stack |
| `INNSEGL_DESTROY_TRUST_ROOT` | teardown guard | name a trust volume to really remove |

## Files, volumes, containers

Compose files in `deploy/compose/`: `spire.yml`, `sigstore.yml`,
`innsegl.yml`; overlays `innsegl.custody.yml`, `sigstore.keycustody.yml`,
`dev/*.yml`.

Trust volumes (`deploy/compose/trust-volumes.sh names`; prefix
`innsegl-trust`, external to every project, label `dev.innsegl.trust-root`):

| Suffix | Holds |
|---|---|
| `ledger-data` | the hash chain and every event body |
| `identity-secret` | the pseudonymisation secret |
| `fulcio-pki` | the Fulcio CA key, certificate and password |
| `rekor-key` | the Rekor signing key |
| `trillian-db` | the transparency log |
| `history` | the trust history |

Custody adds `innsegl-trust-ca-store` and `innsegl-trust-ca-custody`.
`scripts/teardown-guard.sh` stands in front of every `down -v` and refuses
to remove a trust volume.

Containers (live names; dev adds `-dev`): SPIRE `innsegl-spire-*`; Sigstore
`innsegl-sigstore-*`; innsegl `innsegl-postgres`, `innsegl-db-init`,
`innsegl-s3`, `innsegl-s3-identities`, `innsegl-object-init`,
`innsegl-identity-init`, `innsegl-admin-credential-init`, `innsegl-mcp`,
`innsegl-api`, `innsegl-backup`; by profile `innsegl-init` (`init`),
`innsegl-reconciler` and `innsegl-sealer` (`separate`),
`innsegl-trust-backup` (`trust-backup`), `innsegl-demo-agent` (`demo`),
`innsegl-canary` (`canary`).

Host ports (all `127.0.0.1` unless `INNSEGL_BIND`): MCP `28080`, health
`28081`, admin `28090`, gateway `28095` (bind), dashboard `8082` and `8443`
(bind), Fulcio `5555`, Rekor `23000`, SPIRE OIDC `28443`, admin relay `18081`.

Local state: `.innsegl/stack-mode`, `.innsegl/deployed-commit` (`-dev` on a
dev stack), `deploy/compose/.rekor-tlog-id`, `dist/`.

## Exit codes and error classes

| Script | Code | Meaning |
|---|---|---|
| `stack-mode.sh` | 2 | the marker holds something other than dev or live |
| `stack-mode.sh` | 4 | REFUSED: dev stack with a non-loopback bind, or a legacy trust prefix |
| `stack-mode.sh` | 5 | REFUSED: a live-named stack is running here |
| `teardown-guard.sh` | 9 | REFUSED: would have destroyed a trust volume |
| `image-bundle.sh` | 1 | refused (dirty tree, or a bundle that fails its checks) |
| `make update` | 2 | SPIRE or Rekor is not running |

## Tests

- `test/deploy/devstack_test.go` (OPS-033, OPS-127, OPS-129), `topology_test.go`
  (OPS-007, OPS-008), `trustroot_test.go` (OPS-031 to OPS-047),
  `updateenv_test.go` (OPS-135), `buildonce_test.go`, `imagebundle_test.go`,
  `hostports_test.go`, `bindaddress_test.go` (OPS-127), `oneprocess*_test.go`,
  `volumeowner_test.go`, `destructivetag_test.go`, `awkportable_test.go` (OPS-134)
- `test/deploy/referencedocs_test.go` (DOC-001, PROPOSED)
- `scripts/stack-mode-selftest.sh` (OPS-129), `innsegl-update-selftest.sh`,
  `image-bundle-selftest.sh`, `install-selftest.sh`, `setup-link-selftest.sh`,
  `test-suite-selftest.sh`, `worktree-link-selftest.sh` (OPS-040, OPS-041)
- `test/smoke/*_test.go` (OPS-004 to OPS-006, OPS-014 to OPS-018)

## Decisions

- [ADR-0010](../docs/adr/0010-self-hosted-sigstore-is-the-shipped-default.md) self-hosted Sigstore
- [ADR-0022](../docs/adr/0022-a-compose-project-per-test-process-for-the-shipped-spire-stack.md) compose project per test process
- [ADR-0029](../docs/adr/0029-compose-self-hosted-sigstore-as-its-own-project-joined-to-spires-oidc-network.md) Sigstore as its own project
- [ADR-0056](../docs/adr/0056-a-single-machine-deployment-runs-the-loops-in-the-mcp.md) loops in the MCP
- [ADR-0067](../docs/adr/0067-the-developer-machine-runs-a-development-stack-never-the-live-one.md) developer machine stack
- [ADR-0070](../docs/adr/0070-build-once-deploy-a-verified-image-bundle.md) image bundle
- [ADR-0072](../docs/adr/0072-a-development-stack-is-never-the-live-one.md) dev stack

## Runbooks

- [cutover.md](../runbooks/cutover.md)
- [backup-ledger.md](../runbooks/backup-ledger.md)
- [spire-admin-access.md](../runbooks/spire-admin-access.md)
