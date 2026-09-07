# ADR-0044: Resolve an alert into a separate table, and keep the write off the read-only dashboard

- Status: accepted
- Date: 2026-09-07
- Deciders: #167 (RM-102), applying #118's precedent

## Context

#167: the dashboard's overview counts `unattributed_signature_detected` and
`ledger_drift_detected` events and exposes no way to read them — an operator
who wants to know *which* alerts make up the number has to reach for `psql`.
The issue's own decision comment settles the schema half of the gap: a
twelfth `event_type` (`alert_resolved`) would need a new major
`schema_version` (doc 02 §7, IP §2's protected-strings rule), so the two
alert types stay in `innsegl.events`, permanently and unchanged, and a
resolution is a row in a separate table keyed by the alert's `event_id`.
"Open" becomes derived: an alert event with no row there.

That comment is #118's precedent applied a second time. #118 asked the same
question about pruning old ledger rows and found that the stated blocker
("what `event_type` should the marker carry") was not the binding one — the
binding one was `events_append_only`'s `FOR EACH STATEMENT` trigger, measured
directly against a real TRUNCATE, refusing a deletion whatever the marker was
called. The fix there was a separate, unprotected table for the prunable
index, leaving `innsegl.events` untouched. This issue's decision comment
draws the same shape: alert events are the record, a resolution is index-like
metadata about the record, and the record stays in the one place I4 protects.

**What #167's decision comment does not settle is where the write goes.**
Scope item 2 says "a resolutions table and the endpoint that writes it" — the
word "endpoint" is doing unexamined work. `internal/api` is the ONLY HTTP
surface this project ships to the dashboard, and it is not a general-purpose
API that happens to also serve the dashboard — it IS doc 05 §1's
`innsegl-dashboard` row, in its own docstring:

> "The dashboard's backend half: doc 05 §1's `innsegl-dashboard` row is
> 'Read-only UI + BFF proof checks'... It runs under a read-only database role
> and refuses to start without one (RM-083, #121)."
> — `cmd/innsegl/cli.go`

`internal/api.Open` calls `AssertReadOnly` before it serves a single request,
and that function does not check "no INSERT on `innsegl.events`" — it probes
INSERT on every table in the `innsegl` schema, `CREATE TABLE` in both `innsegl`
and `public`, and `CREATE SCHEMA`, and refuses to start if any of them is
allowed:

> "FD §7 requires a credential incapable of writing anywhere; provision one
> with `EnsureReadOnlyRole` and point the API at that"
> — `internal/api/readonly.go`

Doc 05 §1's own table says the same thing about the deployment, not just the
code: `innsegl-dashboard` | ... | "No write credentials mounted — enforced by
giving it a read-only DB role". And doc 06 P6 says it about the UI in terms
that name no exception: "No mutating action exists anywhere in the UI. No
delete, no edit, no retry buttons that write. The only 'actions' are copy,
filter, export, and navigate." A resolutions table does not touch
`innsegl.events`, but a "Resolve" action reachable from the dashboard is a
mutating UI action regardless of which table it targets, and P6 does not
carve out an exception for a table outside doc 02's schema.

So building "the endpoint that writes it" into `internal/api`'s `Server` —
the literal reading of scope item 2 — requires one of:

- handing the dashboard's query API a write-capable database credential,
  which RM-083/#121 built `AssertReadOnly` specifically to make impossible at
  start-up, and which doc 05 §1 states in the topology table as a property of
  the deployed service, not a coding convention; or
- adding a "Resolve" affordance to the dashboard UI, which doc 06 P6 forbids
  categorically, independent of which backend answers the click.

Neither is available without contradicting a normative document this project
does not permit editing to fit an inference (`.claude/CLAUDE.md`: "Never edit
a spec document to match an inference. A conflict is a question for the
human, not permission to amend the doc"). This ADR is that question, answered
the way #118 answered its analogous one: settle the binding constraint before
building around it, rather than discovering it by breaking a measured
guarantee.

## Decision

**The resolutions table is written by a fifth CLI subcommand,
`innsegl resolve-alert`, never by `internal/api`, and the dashboard renders no
mutating action.**

1. **`migrations/0003_alert_resolutions.sql`** adds `innsegl.alert_resolutions`
   — `event_id` (the alert's, no `FOREIGN KEY` — see "Measured, not assumed"
   below), `resolved_by`, `resolved_at`, `reason`. No append-only trigger, no
   `REVOKE UPDATE, DELETE`: unlike `innsegl.events`, a resolution row may be
   corrected or removed. `innsegl.events` is not touched by this migration in
   any way.

2. **`internal/ledger.Store.ResolveAlert`** is the write, on the SAME writer
   `Store` type that already owns `Append`, `Migrate` and every other
   ledger-database write in this project — not a new package, because the
   split #167 draws is "which table", not "which service". It looks up the
   named event, refuses with a distinct, named error if it does not exist
   (`ErrAlertNotFound`), is not one of the two alert types
   (`ErrNotAnAlert`), or already has a resolution (`ErrAlertAlreadyResolved`
   — not idempotent, on purpose: a second, different `resolved_by`/`reason`
   for one alert is a correction two people should look at together, not code
   silently picking one).

3. **`innsegl resolve-alert`** is the operator surface, the fifth
   write-credentialed subcommand beside `reap`, `reconcile`, `seal` and
   `serve` — run once, from a trusted host, holding `$INNSEGL_LEDGER_DSN`,
   the same environment variable and the same writer role
   (`innsegl_appender`) those already use. It is not a loop and elects no
   leader: resolving an alert is one deliberate human action, not a sweep.

4. **`internal/api` gains only a read.** `Store.ListAlerts` and
   `GET /api/v1/alerts` — #167's scope item 1 — read `innsegl.alert_resolutions`
   with a plain `LEFT JOIN`, exactly as they read every other table, through
   the same read-only role. `overviewSQL`'s `open_alerts` is recomputed as
   `count(*) ... WHERE NOT EXISTS (SELECT 1 FROM innsegl.alert_resolutions ...)`.
   Nothing in `internal/api` ever holds a credential that can write, and
   `AssertReadOnly`'s probes did not need to change to keep proving it: they
   already probe every table in the schema, this one included.

5. **The dashboard's alert feed (doc 06 §3.1's "drift/alert feed") lists,
   it does not act.** Each open alert renders as its own banner with its
   identifying fields and a link to its evidence (P1) — the run it concerns
   for a drift alert, the filtered raw record for an unattributed one — and
   there is no button, form or affordance anywhere on it that writes. An
   operator who wants to resolve one runs `resolve-alert` themselves, off the
   page, the same way `EnsureReadOnlyRole` is "operator tooling and
   deliberately not something the API can do" for the reader role's own
   provisioning.

### Measured, not assumed: the FOREIGN KEY that almost broke LED-003

A first draft of the migration gave `alert_resolutions.event_id` a
`REFERENCES innsegl.events (event_id)`. `TestLED003DirectSQLMutationIsRefused`
caught what that does to a live TRUNCATE:

```
TRUNCATE innsegl.events failed with SQLSTATE 0A000
(cannot truncate a table referenced in a foreign key constraint);
want IN001 from the append-only guard
```

Postgres refuses to `TRUNCATE` a table another table's `FOREIGN KEY`
references, and it refuses it BEFORE `events_append_only`'s own
`BEFORE STATEMENT` trigger gets to raise `IN001`. LED-003 measures the
specific `SQLSTATE` a direct SQL mutation is refused with — that is I4's own
proof, not merely whether some error comes back — and this FK silently
changed the answer for the one verb (`TRUNCATE`) whose refusal is otherwise
proven identically for the append-only owner and for every other role. The FK
is gone; `event_id`'s format is checked with the same regex
`innsegl.events.event_id` carries, and existence and alert-type membership
are checked in Go, in the one writer this table has
(`internal/ledger.Store.ResolveAlert`). A migration adding a table is not
permitted to change what a protected refusal is measured returning, even by
accident, and this is why it is recorded rather than silently reverted.

## Alternatives considered

**A. A twelfth `event_type`, `alert_resolved`.** Rejected by #167's own
decision comment before this ADR: a new major `schema_version`, released with
everything doc 02 §7 requires, to buy the ability to dismiss an alert. Not a
price this issue's scope should cost.

**B. Build the resolve endpoint into `internal/api`'s existing `Server`, and
weaken `AssertReadOnly` (or its probe set) to permit it.** This is the literal
reading of scope item 2, and it is rejected because it is not a smaller
change than it looks — it is the same move #118 rejected for the pruner: "a
privileged prune path... turns 'nobody can delete' into 'nobody except this
one program'... a smaller guarantee, and it would need its own ADR to justify."
Here the guarantee is "the dashboard cannot write," proven at every process
start by a real credential probe (RM-083, #121) and stated as deployment
topology in doc 05 §1, not only as application code. Narrowing `AssertReadOnly`
to let exactly one write through is a change to what "read-only" means for the
one component doc 06 calls "the read-only, web-facing proof surface" in its
opening sentence.

**C. Add a "Resolve" button to the dashboard, backed by a NEW, separate
write-capable service the button calls.** This keeps `internal/api` itself
untouched but still puts a mutating action in the UI, which doc 06 P6
forbids in terms that do not distinguish by backend: "No mutating action
exists anywhere in the UI... The only 'actions' are copy, filter, export, and
navigate." Whichever service receives the click, the click itself is the
violation.

**D. Expose resolution as a sixth MCP tool.** MCP tool names are IP §2's own
protected-strings example ("MCP tool names and error-class vocabulary... These
change only in a major release"). More fundamentally, the five existing tools
(`register_agent`, `get_credential`, `record_event`, `sign_commit`,
`retire_agent`) are an AGENT's interface to the system; a human operator
reviewing an integrity finding is not the actor that surface exists for, and
bending it to fit would be the same category error #109 documents the MCP
server being pulled out of in the first place.

**E. A new writer-scoped Go package instead of a method on `ledger.Store`.**
Considered and rejected on grounds of unnecessary duplication: `ledger.Store`
already wraps the one writer `pgxpool.Pool` this database gets, already owns
`Migrate` (which is what created this table), and every other CLI subcommand
that writes to Postgres (`reap`, `reconcile`, `seal`, `serve`) opens a
`ledger.Store` to do it. `internal/ledger/resolutions.go` is additive to that
package, not a parallel one.

## Consequences

**Easier.** An operator can now see WHICH six alerts a "6 open integrity
alerts" count refers to, with the fields that distinguish a benign local
sigstore reset from a real compromise, without a database credential —
closing the exact gap #167 opened with (`docker exec ... psql ...`, quoted in
the issue, is no longer the only way to read them).

**Harder.** Resolving an alert now takes two credentials and two surfaces
where the issue's literal wording suggested one: an operator reads the
dashboard, then runs a separate command with a separate, writer credential,
against a host they must be trusted with. This is deliberate friction, not an
oversight — see Alternative B.

**Honest cost, restated from #167's own decision comment.** A resolution row
is less durable than the alert it resolves: it can be corrected or deleted,
`innsegl.events` cannot. That asymmetry is accepted for v0.1 for the same
reason #167 gave it — the half that must never be lost is the half that is
protected — and is worth revisiting at the next major `schema_version`, when
folding resolution into the chain costs nothing extra because the schema is
being bumped anyway.

**Operator-visible surface.** `documentedSubcommands` in `cmd/innsegl` grows
from eight to nine. Exit statuses 16 (`REFUSED`) and 17 (`INCONCLUSIVE`) join
the sequence `reap`/`reconcile`/`seal`/`api`/`init` already established;
changing what they mean changes the meaning of every scripted resolution run
since.

**Now fixed.** `internal/api/readonly.go`'s probe set already covers this
table without modification, because it probes by SCHEMA rather than by table
name — "`ALTER DEFAULT PRIVILEGES IN SCHEMA innsegl GRANT SELECT ON TABLES`"
in `readonly.sql` is what makes a table added by THIS migration arrive
read-only for the dashboard's role automatically, the same guarantee 0002's
own comment makes about a table added by a later migration in general. That
is confirmed against the live reference deployment, not only against the test
suite: rebuilding and redeploying `innsegl-api` picked up `GET /api/v1/alerts`
with no change to the read-only role's provisioning.

**Exit cost if reversed.** Low. If a future major `schema_version` folds
resolution into the chain as a real `event_type` (the honest-cost note above
already anticipates this), `innsegl.alert_resolutions` and
`resolve-alert` are dropped and `ListAlerts`/`overviewSQL` stop joining
against them — nothing else in this project depends on the table's
existence. If instead a future decision widens the dashboard's role, that is
squarely Alternative B and needs its own ADR arguing the FD §7/P6 change
directly, not a quiet grant added to `readonly.sql`.
