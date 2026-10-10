# Repository names

## Purpose

What the chain records for the repository and branch a run works in
(ADR-0080). From schema 5 a deployment records them either literally
(`host/org/name`, the branch name) or as keyed pseudonyms
(`pn:<key-id>:<32 hex>`). A pseudonym is resolved through an alias table
outside the chain. Erasing an alias changes no event.

Everything that shows or compares a repository resolves it: the run
directory, the commit path, adoption, the reconciler, the query API and the
dashboard. A name that does not resolve was erased; the dashboard shows it
as "Name erased" with the pseudonym's first eight hex digits.

The mode is literal by default. The switch to pseudonymous is one-way. A
second account is refused until the switch is made (ACC-008).

Events recorded before the switch keep the literal name forever. Erasure
cannot reach them (E7).

## Commands

```
innsegl serve [-repo-mode literal|pseudonymous] [-repo-key-file FILE] ...
innsegl erase-repository -repo host/org/name [flags]
innsegl migrate-schema -from 4
innsegl status
```

`innsegl erase-repository -h`:

```
Flags:
  -actor string
    	who asked, for the audit record
  -dsn string
    	the ledger database as its OWNER; the append role cannot delete an alias ($INNSEGL_LEDGER_DSN)
  -mirror-dir string
    	the core's repository mirror; the repository's mirror is removed with its name ($INNSEGL_MIRROR_DIR)
  -repo string
    	the repository to erase, as host/org/name
```

- `innsegl erase-repository` deletes the repository's aliases under every
  key id and its branches' aliases in one transaction, writes an audit row
  naming the pseudonyms (never the name), and removes the repository's
  mirror. It runs as the database owner: the role every service holds may
  insert an alias and never delete one.
- `innsegl status` shows the mode as the component `repository names`.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `INNSEGL_REPO_MODE` | `literal` | `literal` or `pseudonymous`. One-way: a core in `literal` refuses to start once the switch is recorded |
| `INNSEGL_REPO_KEY_FILE` | `/run/innsegl/identity/repo-key` | the repository key; read only in `pseudonymous` mode. Its key id is `rk-` and 8 hex digits derived from the key |

Readiness (`/readyz`) always carries `repo_mode`.

## Files, volumes and containers

| What | Where |
|---|---|
| repository key | `innsegl-identity-secret` volume, `repo-key`, written once by `innsegl-identity-init` beside the identity secret (so its backup covers it) |
| alias table | `innsegl.pseudonyms`; the append role may `SELECT` and `INSERT` |
| switch record | `innsegl.repo_mode`, one row, refused `UPDATE`, `DELETE` and `TRUNCATE` to every role |
| reads | `innsegl.resolve_alias(text)`, `innsegl.resolved_body(jsonb)` |

The alias table is part of the ledger backup, so a restore keeps the names.
An erasure is complete once every backup taken before it has expired.

## Exit codes and error classes

`innsegl erase-repository`:

| Code | Meaning |
|---|---|
| 0 | erased, or nothing to erase |
| 2 | usage: no `-repo`, a value that is not `host/org/name`, no `-dsn` |
| 5 | the aliases were erased and the mirror was not removed; remove it by hand |
| 6 | the ledger could not be reached, or the role cannot delete aliases |

`innsegl serve` refuses to start (usage, exit 2) in `pseudonymous` mode with
no key or a key under 32 bytes, and refuses to start when `literal` meets a
recorded switch.

Creating an account beyond the first while literal fails with SQLSTATE
`IN006`.

## Tests

- `internal/event/v5fields_test.go` (SER-027, SER-028)
- `internal/identity/repository_test.go` (PRI-007)
- `internal/ledger/pseudonyms_test.go` (MCP-097, MCP-098, MCP-099, LED-046, OPS-175)
- `internal/rundir/pseudonyms_pg_test.go` (MCP-098)
- `internal/api/pseudonyms_test.go` (API-037)
- `internal/reconciler/pseudonyms_test.go` (REC-019)
- `internal/accounts/repomode_test.go` (ACC-008)
- `internal/erasure/erasure_test.go`, `internal/mirror/remove_test.go`,
  `cmd/innsegl/eraserepository_test.go` (LED-046)
- `cmd/innsegl/repomode_test.go`, `internal/mcp/repomode_test.go`,
  `test/deploy/repokey_test.go` (OPS-175)
- `web/src/app/pseudonym.test.ts` (FE-145)

## Decisions

ADR-0080 (this page), ADR-0041 (agent type and task pseudonyms), ADR-0065
(the mirror), ADR-0079 (adoption).

## Runbooks

**Switch a deployment to pseudonymous.** After the schema-5 release is
running and `innsegl migrate-schema -from 4` has run, set
`INNSEGL_REPO_MODE=pseudonymous` in the deployment's environment file and run
`make update`. The core's definition changes, so only the core is recreated;
it records the switch at start. Check `innsegl status` shows
`repository names: pseudonymous`. Runs registered from then on record
pseudonyms.

**Erase a repository's name.** Run `innsegl erase-repository -repo
host/org/name` with the owner's DSN and the mirror directory. It is
deliberate and cannot be undone.
