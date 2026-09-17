# ADR-0050: Prune the hot tier without deleting a row

- Status: accepted
- Date: 2026-09-17
- Deciders: #118 (RM-081), applying ADR-0044's precedent a third time

## Context

#118 decided that the hot tier is prunable: a sealed range is replaced by one
marker row carrying its segment hash, Merkle root and Rekor index, and "a
thousand rows become one". The reasoning holds — the hot tier is an INDEX, the
segment is the RECORD, and attribution is in neither, which VER-001 proves by
verifying a commit with the database unreachable.

What the issue does not settle is how a row leaves `innsegl.events`, and the
answer measured against the running deployment on 2026-09-17 is that it cannot.

Every mutation is refused, as the SCHEMA OWNER, which is the most privileged
role this deployment has:

```
DELETE one event        IN001      UPDATE an event    IN001
DELETE a range          IN001      DELETE from chain  IN001
TRUNCATE events         IN001
```

`events_append_only` is `BEFORE UPDATE OR DELETE OR TRUNCATE ... FOR EACH
STATEMENT` and `ENABLE ALWAYS`, with UPDATE, DELETE and TRUNCATE additionally
revoked from PUBLIC. There is no role in this deployment that can remove a row.

The enforcement binds DML. What it does not cover, which roles can reach it,
and why that is acceptable are threat-model questions and are recorded in doc 04
rather than here.

ADR-0044 reached this conclusion twice before, for #167's alert resolutions and
for #118's own first pass, and both times the answer was the same: leave
`innsegl.events` untouched and put the new thing in a table the triggers do not
guard.

## The fork this ADR exists to settle

"A thousand rows become one" and "no row is ever deleted" cannot both be true of
one table. Three shapes resolve it differently:

**A. Marker beside, rows stay.** The marker goes in a separate table; the
events remain. `ledger.Verify` meets a marker and can verify a range against its
segment without reading the rows. I4 is untouched, nothing new can delete, and
the API can serve deep history from segments. **No space is reclaimed** — which
is most of what #118 asked for.

**B. Partition, then detach.** `innsegl.events` becomes range-partitioned on
`chain_position`. A sealed range is one partition; pruning DETACHES it, which is
DDL and therefore not caught by the statement trigger. Space is reclaimed when
the detached partition is dropped. This works, and the cost is that pruning now
REQUIRES the owner credential and DDL on the ledger — the exact combination
every other decision here has kept apart. A scheduled job holding it is a
standing capability to drop the events table.

**C. Reclaim nothing; bound growth elsewhere.** Accept the hot tier grows, and
treat #118's cost concern with retention on the OBJECT store and a smaller
event body instead. Cheapest, and declines the issue's actual request.

## Decision

**A — the marker goes beside the rows, and no row is removed.** `ledger.Verify`
meets a marker and verifies the range against its segment; deep history serves
from segments; `innsegl.events` is untouched and nothing gains the ability to
remove a ledger row.

**Because the compression is not worth what B costs.** Measured on 2026-09-17:

```
5,212 events        9.3 MB total, including indexes
1,819 bytes/event   4,493 events/day
projected 12 months about 2.8 GB
```

Pruning would reclaim under three gigabytes a year. B buys that by giving a
scheduled job a credential that can drop the events table, and every other
decision in this project has kept those two things apart.

Two measurements make the case stronger rather than weaker. The rate is taken
over 1.2 days of unusually heavy development, so it is an UPPER bound. And the
bodies are within budget: `tool_call` averages 693 bytes canonical against IP
§6's 1 KB target and is 89% of all events, so the volume is honest rather than
bloat.

The 1,819 bytes/event is total relation size — roughly 2.6× the canonical body,
which means INDEXES are most of the footprint and not the events. If the hot
tier ever does need to shrink, that is the cheaper and far safer place to look
first.

**B is not refused on principle; it is refused on arithmetic.** Revisit it if a
measured figure ever justifies it. Nothing is close.

### A is the shape, and it is not built yet, deliberately

A marker earns its place only when the rows it stands in for are gone. With the
rows present it is a mechanism with nothing to do: `ledger.Verify` can already
read them, and doc 06 §3.2's deep-history view can already serve them. Building
it now would be shipping a code path that no query takes, on a table nothing
writes, to be maintained until it is needed.

So the decision is the SHAPE — when the hot tier is pruned, it is pruned this
way and not by deleting — and the work waits for the number that makes pruning
worth doing. #118 stays open against that, rather than being closed as done or
built as something inert.

**What would reopen it**, concretely, so the next reader does not have to guess:

- the hot tier passing roughly 50 GB, which at the measured upper-bound rate is
  about eighteen years away and would arrive far sooner on a busier deployment
- a deployment where the database is the expensive component rather than a
  container on a laptop
- a restore time that becomes operationally painful, which is a property of row
  count rather than of bytes

Any of those is a measurement. None of them is today.

## What is already settled

- Pruning must not DELETE from `innsegl.events`. Every role is refused IN001,
  and a design that reached for `ALTER TABLE ... DISABLE TRIGGER` would be
  removing the enforcement in order to pass the test that enforcement exists.
- A marker is additive wherever it lives, and `ledger.Verify` must meet it
  rather than a hole, or a pruned range reads as an invariant violation.
- Whatever is chosen, the segment remains the record and the hot tier remains
  an index. Nothing here may make attribution depend on a row being present.
