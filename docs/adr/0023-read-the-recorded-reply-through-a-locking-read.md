# ADR-0023: Read the recorded reply through a locking read, so a completion that loses the race is handed the winner's bytes

- Status: accepted
- Date: 2026-08-29
- Deciders: Mike

## Context

ADR-0017 §2 records the store's shape: "claim, run, record — as three single
statements, with no window between deciding and acting". The recording
statement was

```sql
WITH done AS (
    UPDATE innsegl.idempotency
       SET status = 'completed', response = $2, completed_at = clock_timestamp()
     WHERE idempotency_key = $1 AND status = 'in_progress'
    RETURNING true AS mine, response
)
SELECT mine, response FROM done
UNION ALL
SELECT false, response FROM innsegl.idempotency
 WHERE idempotency_key = $1 AND NOT EXISTS (SELECT 1 FROM done)
```

with the intent stated in its own comment: "the first caller to complete wins
and a caller that was overtaken reads the winner's reply out of the second arm".

It does not do that. Two callers complete one claim — which ADR-0017 §5 makes
an ordinary event, because a lease takeover deliberately runs the tool a second
time — and the loser is handed an **empty** reply:

* its `UPDATE` blocks on the winner's row lock, and when the winner commits,
  READ COMMITTED re-evaluates the `WHERE` against the *post-commit* row. The
  row now says `completed`, so nothing matches and `done` is empty;
* the second arm is a plain `SELECT`, and a plain `SELECT` reads the
  **statement's** snapshot — taken before the winner committed. It therefore
  returns the row as it was: `status = 'in_progress'`, `response IS NULL`.

Neither arm has the winner's bytes, and the caller receives `[]byte(nil)` as if
it were a recorded reply. RM-022 measured it rather than inferring it: a direct
probe of `complete` over 40 rounds produced **39 empty replies in 80 calls**.
Downstream it surfaced as `register_agent` reporting `INVARIANT_VIOLATION` —
"the recorded reply … is not a `register_agent` result: unexpected end of JSON
input" — which is loud and fail-closed, but a legitimate caller was being given
an error where the store exists to give it the recorded reply (IP §6.6). RM-022
worked around it by releasing its two executions one at a time.

This is the mirror of the snapshot subtlety ADR-0017's Consequences already
record for the *claim* statement, which RM-021 answered by treating "neither arm
returned a row" as "someone else holds this key" and waiting. That answer is not
available here, and the difference matters:

* in `claimSQL` the competing row **does not exist in the loser's snapshot at
  all**. There is nothing to lock, so no locking clause could find it; waiting
  and re-reading on a fresh snapshot is the only thing that can work, and it is
  a correct thing to report, because "someone else holds the key" is true.
* in `completeSQL` the row **is** in the loser's snapshot — it is the claim this
  caller itself took, committed by its own earlier statement — merely at a
  stale version. There is nobody left to wait for: the winner has committed and
  the answer is final. The caller has already run the tool and is owed those
  bytes now.

## Decision

**The recording statement reads the row with `FOR UPDATE`, in a CTE the
`UPDATE` depends on.**

```sql
WITH recorded AS (
    SELECT status, response
      FROM innsegl.idempotency
     WHERE idempotency_key = $1
       FOR UPDATE
), done AS (
    UPDATE innsegl.idempotency
       SET status = 'completed', response = $2, completed_at = clock_timestamp()
     WHERE idempotency_key = $1
       AND status = 'in_progress'
       AND EXISTS (SELECT 1 FROM recorded WHERE recorded.status = 'in_progress')
    RETURNING true AS mine, response
)
SELECT mine, response FROM done
UNION ALL
SELECT false, response FROM recorded WHERE NOT EXISTS (SELECT 1 FROM done)
```

Three properties, each load-bearing:

1. **A locking read is the one construct that sees past the statement
   snapshot.** READ COMMITTED gives `SELECT … FOR UPDATE` the same
   follow-the-update-chain behaviour it gives `UPDATE`: it waits for the
   competing transaction, walks to the row's current version, re-checks the
   `WHERE` against it, and returns *that* version. So the loser reads what
   actually committed. Nothing else inside one statement can: the snapshot is
   taken before the statement executes, which is why an advisory lock or an
   ordering trick acquired *inside* the statement is already too late.

2. **The read happens before the write, fixed by data and not by the planner.**
   PostgreSQL does not order the sub-statements of a `WITH`; the `EXISTS` makes
   `done` depend on `recorded`, so the row is locked and re-read first and the
   `UPDATE` fires only when that current version is still in flight.

3. **First-completion-wins is decided against the committed row, twice.** The
   `EXISTS` checks the locked current version, and the `UPDATE` keeps its own
   `status = 'in_progress'`, which EvalPlanQual re-checks on the version it
   would write. A completed row is therefore never the target of an `UPDATE`,
   so the schema's `IN003` guard is never provoked into refusing a legitimate
   call — the guard stays exactly as ADR-0017 §7 and migration 0002 wrote it.

## Alternatives considered

- **Retry the statement until the second arm returns a non-NULL response.**
  Rejected: it converts a wrong answer into a variable delay and hides the
  reason. The winner has already committed by the time the loser's `UPDATE`
  declines, so there is nothing to wait *for*; a loop would be a bound nobody
  configured, on a path that has a correct one-shot answer available.

- **Two statements: `UPDATE … RETURNING`, and, when it matched nothing, a fresh
  `SELECT`.** The closest rival, and correct on the mechanism — a second
  statement takes a second snapshot, which is bedrock READ COMMITTED rather
  than a locking subtlety. It lost on two concrete counts. First, it opens a
  window the single statement does not have: ADR-0017 §7 permits pruning a
  *completed* row, so between the two statements the reply can legitimately
  disappear, turning a correct call into an error. Second, it adds two error
  branches — "the follow-up read failed" and "the claim vanished" — and the
  first is unreachable by any test that does not fault-inject between two
  statements, so IP §2's 100% branch floor on the store's error paths could
  only be met by simulating a failure the one-statement form cannot have.

- **Make the `UPDATE` always match, so `done` always returns a row** (drop
  `status = 'in_progress'`, or write the response through a `CASE` that leaves
  a completed row's value alone). Rejected: migration 0002's trigger raises
  `IN003` on *any* `UPDATE` of a completed row, by design, and a no-op update
  is still an update. Relaxing the trigger to let one through would remove the
  guard that makes "a recorded reply is never rewritten" true from a `psql`
  prompt, which is the only version of that claim worth having.

- **Serialize completers with `pg_advisory_xact_lock` at the head of the
  statement.** Rejected: it does not address the fault. The snapshot is
  acquired before execution begins, so a lock taken during execution leaves the
  loser reading exactly the same stale snapshot it reads today.

- **Hold an explicit transaction: `BEGIN; SELECT … FOR UPDATE; UPDATE; COMMIT`.**
  Rejected: three round trips and a transaction pinned open on the store's hot
  path, for a result one statement already produces. ADR-0017 rejected holding
  a transaction across a call for the same class of reason.

- **Let the overtaken caller return the reply it computed itself.** Rejected by
  ADR-0017 §5 and not reopened: two callers of one key would be given different
  answers, which is the property the store exists to prevent.

## Consequences

- Every completion now takes a row lock for the duration of its statement.
  Concurrent completers of one key serialize where they previously raced; the
  lock is held only until the statement ends, and completion writes one row by
  primary key.

- `claimSQL` is untouched, and the fix is deliberately not portable to it. Its
  loser cannot see the competing row at all, so there is no row to lock;
  RM-021's answer — report the in-flight state, wait, and re-read on a fresh
  snapshot — remains the right one there. The two statements now differ because
  the situations differ, and
  `TestAClaimThatCommitsDuringAnotherCallersStatementIsWaitedForNotLost` still
  pins the claim side.

- The schema is unchanged: no migration, and the `IN003` guard still refuses to
  rewrite or reopen a completed reply, to repoint a claim, or to delete an
  in-flight one. The lease takeover path is unchanged.

- Two tests pin the fix deterministically, by the device RM-021 used — holding
  the conflicting statement open in a transaction and committing it only once
  the caller under test is *demonstrably* parked on the row lock, observed in
  `pg_stat_activity` rather than assumed after a sleep.
  `TestACompletionOvertakenMidStatementStillReturnsTheRecordedReply` probes
  `complete` directly; `TestTwoCallersCompletingAtOnceAreBothGivenTheRecordedReply`
  drives the same interleaving through `Do`. Both failed 20 times in 20 against
  the old statement.

- `TestMCP007ATakenOverClaimStillMintsOneIdentity` releases its two executions
  at once again, as RM-022's comment said it could once this was fixed. It
  fails 5 in 5 against the old statement and passes 20 in 20 against this one,
  so the un-staggering is itself a regression test.

- **Exit cost.** Low. The change is one SQL constant with no schema, no API and
  no wire effect; reverting it restores a measured bug and nothing else.
