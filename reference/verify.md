# Verify

## Purpose

`innsegl verify` checks a commit's attribution with git, Fulcio and Rekor
only. It never reads the ledger, and no flag points it at one (invariant I5).
The dashboard's proof route uses the same code (`internal/verify`).

## Commands

```
innsegl verify <commit> [flags]
make innsegl-verify-commit COMMIT=<sha> [DEMO_REPO=host/org/name]
make verify-branch [BASE=<ref>]
make verify-branch-selftest
```

- `make innsegl-verify-commit` runs the verifier in a container on the
  Sigstore network only, with no route to the ledger.
- `make verify-branch` verifies every agent-signed commit between `BASE`
  (default `origin/main`) and `HEAD` before a merge. It runs locally, where
  the deployment's log is reachable.
- `make verify-branch-selftest` watches the gate fail: green, forged, unreachable.

The three checks (`internal/verify/verify.go:154`):

1. Fulcio certificate chain valid
2. Rekor inclusion proven
3. Trailer matches certificate identity

## Settings

| Flag | Variable | Meaning |
|---|---|---|
| `-repo` | | repository holding the commit [`.`] |
| `-fulcio-url` | `INNSEGL_FULCIO_URL` | certificate authority |
| `-rekor-url` | `INNSEGL_REKOR_URL` | transparency log |
| `-issuer` | `INNSEGL_OIDC_ISSUER` | OIDC issuer the certificate must name; empty reports it |
| `-trust-history` | `INNSEGL_TRUST_HISTORY` | every root and log key used (ADR-0073); empty is the published ones only |
| `-json` | | report as JSON |

`verify-branch.sh` also reads `INNSEGL_BIN` (default: built from
`./cmd/innsegl`) and `INNSEGL_REPO`. The make targets default Fulcio to
`http://127.0.0.1:5555` and Rekor to `http://127.0.0.1:$INNSEGL_REKOR_PORT`.

## Files, volumes, containers

- `make innsegl-verify-commit` uses network `<prefix>-sigstore-published`
  and mounts `<prefix>-core_innsegl-workspace` read-only.
- A trust history file, if given (see [trust-history.md](trust-history.md)).

## Exit codes and error classes

| Code | Verdict | Meaning |
|---|---|---|
| 0 | `verified` | all three checks hold |
| 3 | `failed` | the checks ran and the attribution does not hold |
| 4 | `unavailable` | a check could not run; never read as pass or fail |
| 5 | `unattributed` | no signature and no `Agent-*` trailer; not a failure |
| 6 | | unusable: no such commit, or a configuration that cannot verify |
| 7 | `pre-history` | signed before the trust history began; cannot be verified |

`pre-history` (ADR-0073): the root and log that would prove the commit are
gone. It is reached only when the trailer still matches the certificate. It
is not a pass and not a failure.

`content-verified` (ADR-0047): the commit object was rewritten by a merge,
and the change it makes is one a signed run recorded. The dashboard shows
it. The CLI has no status for it; any verdict it does not list exits 6
(`cmd/innsegl/verify.go:163`).

`verify-branch.sh` uses the same 3, 4 and 6. All three fail the gate.

## Tests

- `internal/verify/*_test.go` (VER-001 to VER-024, ADP-012, ADP-016, ADP-017)
- `internal/verify/carotation_test.go` (OPS-133)
- `cmd/innsegl/verify_test.go` (VER-006)
- `internal/api/proof_test.go`, `rederive_test.go` (API-004 to API-006, VER-002, VER-006)
- `test/smoke/*_test.go` (OPS-004, VER-001)
- `scripts/verify-branch-selftest.sh` (not in CI: needs the deployment's log)

## Decisions

- [ADR-0034](../docs/adr/0034-verify-against-the-logs-record-of-the-commit-sha-and-evaluate-the-certificate-at-its-signed-integration-time.md) verify against the log's record
- [ADR-0037](../docs/adr/0037-gate-i6-over-the-repositorys-own-commits-and-date-the-empirical-half.md) I6 gate
- [ADR-0042](../docs/adr/0042-answer-anyone-can-verify-with-a-public-rekor-anchor-over-a-self-hosted-fulcio-root.md) anyone can verify
- [ADR-0047](../docs/adr/0047-anchor-attribution-to-the-change-not-the-commit-object.md) content-verified
- [ADR-0073](../docs/adr/0073-trust-roots-are-kept-as-an-append-only-history.md) trust history and pre-history

## Runbooks

- [trust-rotation.md](../runbooks/trust-rotation.md)
- [trust-domain-re-rooting.md](../runbooks/trust-domain-re-rooting.md)
