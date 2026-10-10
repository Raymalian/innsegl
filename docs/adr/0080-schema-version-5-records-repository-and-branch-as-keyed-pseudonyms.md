# ADR-0080: Schema version 5 records repository and branch as keyed pseudonyms, resolved through an erasable alias table

- Status: accepted
- Date: 2026-10-10
- Deciders: the operator
- Tracks: #483 (RM-304), #484 (RM-305), epic #478 (E29)

## Context

Three events name the repository a run works in: `run_registered` (`repo`,
`branch`), `commit_intent` (`repo`) and `commit_recorded` (`repo`). Doc 02 §5
fixes their values: `repo` is `host/org/name`, and `branch` is a git
reference name stored verbatim. `event.ValidateRepo` enforces the repo form
on every append.

That was fine for one organisation that runs its own core. It is not fine for a
core that holds a second organisation's work. The chain is permanent (I4). It is
copied into sealed segments under object lock and into backups, and it is read
by anyone allowed to verify. A repository name such as
`github.com/acme/secret-acquisition` or a branch such as
`fix/cve-2026-1234-before-disclosure` is information the owner may later need
to withdraw. Nothing on the chain can ever be withdrawn.

ADR-0041 solved the same problem for `agent_type` and `task_ref` in the SPIFFE
ID, but without a schema change. Eight hex digits fit the segment grammar, and
the literal values stayed on `run_registered` as the mapping. That approach
does not carry over. The mapping it relied on is the chain row this ADR has to
keep the name out of. And `repo` has a grammar, `host/org/name`, that a
pseudonym does not meet without pretending to be a repository.

So putting repository and branch on the chain only as pseudonyms changes the
value constraints in doc 02 §5. Doc 02 §7 and doc 08 §3 allow that only in a
new major `schema_version`. That release must ship verifiers that accept every
earlier version, new golden fixtures, a signed migration attestation and a
superseding ADR. This is that ADR.

## Decision

### 1. Value forms in schema 5

In a schema-5 event, `repo` and `branch` each take **one of two forms**:

| Member | Literal form (unchanged) | Pseudonymous form (new) |
|---|---|---|
| `repo` | `host/org/name`, lowercase host | `pn:<key-id>:<32 lowercase hex>` |
| `branch` | git reference name, verbatim, ≤255 bytes; `detached` | `pn:<key-id>:<32 lowercase hex>`; `detached` stays literal |

```
repo   = "pn:" key_id ":" hex32( HMAC-SHA256(K[key_id], "repo"   ‖ ":" ‖ repo_literal) )
branch = "pn:" key_id ":" hex32( HMAC-SHA256(K[key_id], "branch" ‖ ":" ‖ repo_literal ‖ "\n" ‖ branch_literal) )
key_id = [a-z0-9][a-z0-9-]{0,62}        (doc 02 §5's identifier grammar, as ADR-0061's)
hex32  = the first 32 lowercase hex characters (128 bits)
```

The reasons for each choice:

- **A form that cannot be mistaken for a repository.** `pn:` holds no slash,
  so no value passes for both a pseudonym and `host/org/name`. A tool that
  reads a pseudonym as a path or URL fails instead of quietly naming a
  repository that does not exist.
- **The key id is inside the value**, as `agent_message.payload_digest`
  already does it (ADR-0061). Rotation never makes an older value ambiguous.
- **128 bits, not ADR-0041's 32.** These values are join keys: runs per
  repository, adoption candidates, pass rates. On the chain they need
  collision resistance, not just unlinkability. The value is not
  length-constrained the way a SPIFFE segment is.
- **The branch is keyed by its repository.** `main` in two repositories gets
  two pseudonyms, so the most frequent pseudonym on a chain does not simply
  read as `main` across every repository at once. Inside one repository,
  frequency still shows which branch is the default. That residual is
  accepted (doc 04).
- **`detached` stays literal.** It is a state, not a name, and it reveals
  nothing an observer could not already infer.
- **Both forms are valid in schema 5.** A deployment's mode (decision 5)
  decides which form it writes. A schema-5 core in literal mode writes the
  same values it writes today, so the schema release and the mode switch are
  separate operator decisions.

`ValidateRepo` and `ValidateBranch` take the event's `schema_version`. At
schema ≤4 they accept only the literal form, exactly as today. At schema 5
they accept either form, and they check the grammar of the *literal* before
it is hidden, as ADR-0041 decision 1 does. A traversal string or an
over-long branch is refused, not turned into 32 hex digits.

### 2. The key: ADR-0041's code and custody, its own key

- **Code reuse.** `internal/identity`'s Pseudonymiser gains `Repo` and
  `Branch`. There is one package for pseudonyms and every consumer is handed
  one instance (ADR-0041 decision 1). No second implementation.
- **A separate key, in the same custody.** The repository key is its own
  secret, at least 32 bytes. It is generated per host by the same one-shot
  that generates the identity secret (ADR-0078) and kept in the same custody,
  so ADR-0074's existing backup covers it.
- **The key id is derived from the key**: `rk-` and the first 8 hex digits of
  SHA-256 over `innsegl-repo-key-id:` and the key. A new key is a new key id,
  and no second setting can disagree with the key it names.
- **Why not ADR-0041's secret directly?** That secret has no key id, and
  rotating it changes the SPIFFE ID of a run SPIRE already holds an entry
  for (OPS-081). Tying the repository key to it would make one rotation
  carry the risk of the other.
- **Rotation.** A new key id applies to new events. Values under an older key
  id stay valid and resolvable, because resolution is a lookup (decision 3),
  not a recomputation. A repository seen after a rotation gets a second
  pseudonym and a second alias row. Readers group by the resolved name. A
  reader with no alias sees two pseudonyms for one repository; that is
  accepted, and it is the point of rotating. Old keys may be destroyed after a
  rotation. Nothing reads them again.
- **The secret is needed to create a pseudonym, never to resolve one**
  (ADR-0041 decision 6, kept). Losing the key stops new pseudonymous
  appends; the core refuses to start, as ADR-0041 decision 3 does. It
  orphans no history.

### 3. The alias table: outside the chain, erasable

`innsegl.pseudonyms` maps a pseudonym back to its literal:

| Column | Meaning |
|---|---|
| `value` (PK) | the `pn:…` value exactly as on the chain |
| `kind` | `repo` or `branch` |
| `literal` | the repository or branch name |
| `repo_value` | for a branch: the `pn:` value of its repository |
| `key_id` | the key the value was made under |
| `first_seen` | when the core first wrote it |

- **Written in the same transaction as the append** that first carries the
  value. An event never commits without its alias. After a crash between the
  two, neither exists, and the append's own idempotency key retries both.
- **Not hash-covered, not in any segment, not anchored.** The chain, the
  sealed segments and Rekor never see it. That is what makes it erasable.
- **No I4 trigger on it.** It is the one table in the ledger schema whose
  rows may be deleted. The append role may only insert into it.
- **Erasure deletes rows.** Erasing a repository deletes its row and every
  branch row whose `repo_value` points at it, across all key ids.
- **Who may erase.** In this ADR: the operator, from the core's own command
  line, through the admin path every other destructive core command uses.
  When organisations exist (E27, #482), an account owner may also erase a
  repository their account holds a grant for. No agent, client installation
  or dashboard session can erase. A pseudonym is erased only on a deliberate
  human decision.
- **Erasure is not recorded on the chain.** A chained record of an erasure
  would need a new event type and would date the erased repository's
  activity. The record goes in the accounts audit table (E27), holding the
  pseudonym, the actor and the time, never the literal.
- **Backups.** The alias table is in the ledger schema and so in the ledger's
  backup: a restore keeps the names. An erasure is complete once every backup
  taken before it has expired.

### 4. How each reader works with and without the alias

| Reader | Resolves by | After erasure |
|---|---|---|
| Commit path (ADR-0059) | The client sends the literal repository (ADR-0064). The core checks scope against it, as today, and pseudonymises at append. Trailers carry no repository, so nothing changes in the commit. | Commits go on. The next append writes a new alias row: erasure removes a past name, it does not ban future use. |
| Adoption (ADR-0079) | `DeadRunsForRepo` takes the literal, looks up every value with that literal (all key ids) plus the literal itself (rows from before the switch), and matches `repo = ANY(…)`. Mode switches and key rotations do not split a repository's dead runs. | An erased repository's dead runs can no longer be found by name, so its work cannot be adopted. Accepted: erased means forgotten. |
| Mirror (ADR-0065) | The mirror stays keyed by literal path on the core's disk. A reader gets from an event's `repo` to the literal through the alias table, then to the mirror. | Erasure deletes the mirror for that repository as well. A mirror left behind keeps the name in its path, which defeats the erasure. |
| Reconciler | Resolves each intent's `repo` to find the mirror. | An unresolvable intent is "not held". It stays open and is never expired (ADR-0065 amendment): a missing name is not evidence that nothing was signed. |
| Query API and dashboard | Reads join on the alias table and show the literal to a reader allowed to see the run (ADR-0062; scoped by account in E28). Rows from before the switch are shown as stored. Two values that resolve to one name are grouped as one repository. | The short pseudonym is shown with "name erased". Nothing is left blank or hidden. |
| `innsegl verify` | Not affected. It verifies a commit from a local repository by its SHA, the certificate and Rekor. It reads no chain `repo` and holds no key. | Not affected. |
| Chain and segment verification | Hash and Merkle checks run over bytes; values are opaque to them. | Not affected. LED-046 proves erasure changes no byte. |

No reader that resolves a value holds the key. No reader recomputes a
pseudonym to look something up, so key rotation and key loss never break a
read.

### 5. Mode is a setting, default literal, and switching is one-way

- `-repo-mode` / `INNSEGL_REPO_MODE`: `literal` (default) or `pseudonymous`.
  The default stays `literal` so this release changes no deployment's
  behaviour on upgrade. Unlike ADR-0041, which defaulted to pseudonymous,
  this switch makes a deployment's names unreadable without its alias
  table, and that should be an operator's deliberate act.
- **One-way.** The switch is recorded in `innsegl.repo_mode`, a one-row table
  outside the chain that the core writes at its first start in pseudonymous
  mode and that no role may update or delete. A core in `literal` refuses to
  start once that row exists, and the refusal names the setting. The record
  is not an alias, so erasing every alias does not undo the switch. Without
  this check, switching back would split one repository's history across two
  forms with no deliberate reason.
- **Pseudonymous needs the key.** A core in `pseudonymous` with no repository
  key refuses to start (ADR-0041 decision 3's rule).
- **What the operator sees.** The health surface reports
  `repo_mode: literal|pseudonymous` from the running process.
  `innsegl status` prints it. In literal mode, the start-up log names the
  ACC-008 consequence.
- **ACC-008.** Creating any account beyond the first is refused until the
  switch is recorded. The database refuses the insert, so every path that
  creates an account meets the same check at the moment of creation
  (ADR-0062's "ask every time" property), and the refusal names the setting
  and this ADR.
- **How a deployment switches.** Set the variable in the deployment's
  environment file and run `make update`. The core's compose definition
  changes, so the core service is recreated and reads the new mode at start.
  No other long-running service reads the mode.

### 6. What stays literal forever

- **Every event before the switch**, at any schema version, keeps its literal
  `repo` and `branch`. There is no backfill and no rewrite (E7, I4, doc 08's
  "records are never migrated in place"). Erasure cannot reach them. An
  operator who needs a name off the chain had to switch before its first
  run.
- **`task_ref` and `agent_type` on `run_registered`** stay literal in this
  ADR (ADR-0041 decision 5). Schema 5 does not pseudonymise them.
- **Off-chain stores** still hold literal names: the mirror path,
  `innsegl_auth.repo_grants` and installation repository lists (scope needs
  the literal), and captured bodies. Erasing names from bodies belongs to
  E27 #482, not here.

### 7. The migration attestation

The operator appends `schema_migrated` with `from_schema_version: "4"`,
`to_schema_version: "5"` and `cutover_position` through
`innsegl migrate-schema -from 4`, as for 3→4. The command finds the cutover
from the chain, so it is correct even when the upgraded core started first.
It is appended in either mode, because the schema changes whatever the mode. The repository key's id in effect at the switch is
operational detail, recorded in the release record and not on the chain.

## Alternatives considered

- **A pseudonym shaped as `host/org/name`** (for example
  `pn.invalid/<hex>/<hex>`). Rejected. It passes the schema-4 validator and
  avoids the major release, but it is a schema change disguised as a value,
  exactly what doc 02 §7 forbids. Every tool that reads `repo` as a
  repository would quietly accept it.
- **Make the schema version the mode** (stay on 4 while literal, migrate to 5
  only when switching). Rejected. It records the switch on the chain, which
  is attractive. But every future major would carry the mode with it: a
  literal deployment could never take schema 6 without pseudonymising, and
  the core would have to write two schema versions. The value form already
  shows which mode wrote a row.
- **Pseudonyms only in the gateway mapping and the API, chain unchanged.**
  Rejected. It fails the epic's exit criterion: the chain would still name
  every repository forever.
- **Encrypt the names on the chain and erase by destroying the key.**
  Rejected. Ciphertext on a permanent public-to-verifiers chain is a promise
  that depends on the cipher's future. Destroying one key per repository is
  a key-management system in itself. Erasure would also be all or nothing
  per key, where alias rows erase one repository at a time.
- **Reuse ADR-0041's secret.** Rejected, for decision 2's reason: it couples
  two rotations with different risks.
- **A fully separate custody for the key.** Rejected. It adds a store and a
  backup path for no gain over the one ADR-0074 already backs up.
- **ADR-0041's 8 hex digits.** Rejected. 32 bits gives a birthday collision
  near 65,000 values, and a collision here merges two repositories' runs.

## Consequences

- A MAJOR-release procedure (doc 08 §3, (a)–(d)), taken early under
  `VERSIONING.md`'s pre-1.0 rule: schema `"5"`, fixtures, verifiers accepting
  `"1"`–`"5"` forever, `schema_migrated` 4→5, and this ADR.
- A chain written in pseudonymous mode cannot be read for repository names
  without the alias table. Losing the table loses the names, not the proofs.
  This is the trade-off the epic asked for.
- Erasure is real for the chain, segments and Rekor. It is not real against
  anyone who holds the repository, who can match `commit_sha` to it.
  Pseudonyms hide names from ledger readers, not from holders of the code
  (doc 04 residual).
- ACC-008 makes "pseudonyms before a second organisation" a check the code
  enforces, not a plan-file promise.

### Tests to write, first

SER-027, SER-028, PRI-007, PRI-008, MCP-097..099, LED-046, ACC-008, VER-025,
REC-019, API-037, FE-145, OPS-175, as defined in doc 07.

## Operator decisions, 2026-10-10

1. The `pn:<key-id>:<32 hex>` form, with both forms valid at schema 5: yes.
2. Length: 32 hex (128 bits).
3. Branch pseudonyms keyed by their repository: yes.
4. A chained record of the mode switch: no. The first `pn:` value is the switch.
5. A separate repository key in the existing custody: yes.
6. Erasing a repository also deletes its mirror: yes.
7. `task_ref` and `agent_type` are not pseudonymised in this release.
8. Doc 02 §2's `schema_version` cell is left as it is.
9. Erasure by the operator now, and by account owners from E27: yes.
10. #463's live two-machine test is OPS-174; the in-process client test that
    reused OPS-130 is renumbered.
11. Default `literal`; the switch is one-way: yes.
12. A deployment that will hold a second organisation switches to
    `pseudonymous` once schema 5 is installed, before that organisation is
    created.
