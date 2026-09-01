# ADR-0039: Size the deployment from OPS-002's measurements, and record what each measured number replaces in doc 05 §4

- Status: accepted
- Date: 2026-09-01
- Deciders: Mike

## Context

doc 05 §4 is titled "Sizing posture (initial, revisit with data)" and says so in
its own text:

> Events are ≤1 KB canonical (LED-011): at 10⁶ runs/year with ~20 events/run,
> the hot tier carries ~20 GB/year before pruning to index-only for sealed
> ranges — well inside a single modest Postgres. Segment objects to standard
> object storage; lifecycle to archive class per the storage plan already
> agreed. **The first real load test (OPS-002) replaces these estimates with
> measurements; per the verification methodology, measured numbers supersede
> this section and get recorded in an ADR appendix.**

OPS-002 has now been run (RM-052, #60, `test/load/ops002_test.go`). This ADR is
the appendix doc 05 §4 asks for. It records what was measured, on what, and
which sentence of doc 05 §4 each number replaces.

Two properties of this project make the *manner* of the recording as
load-bearing as the numbers.

**A load test is the easiest place in a repository to produce a confident wrong
number.** A throughput figure can measure the program doing the appending
rather than the ledger being appended to, and nothing in the figure itself says
which. So OPS-002 does not report a throughput unless it has first established
that its writers spent essentially all of their wall time inside
`ledger.Store.Append`, and the run fails if they did not. The evidence that the
ledger and not the harness was the constraint is in §"Was the harness the
bottleneck?" below, and it is the most important part of this ADR.

**doc 02 §2 assigns `chain_position` "under serialized append."** The store
takes a Postgres advisory lock to do it (`internal/ledger/postgres.go`,
`appendLockKey`). That single fact is the shape of every throughput number
here: the ledger has one writer whatever the client concurrency, so its ceiling
is `1 / (serialized append)` and additional writers buy latency, not rate. The
measurements confirm it rather than assume it.

Invariants touched: **I1/I2** (a gap in chain positions would be a violation of
the serialized append that assigns them; none occurred), **I3** (an append that
fails under load is the ledger declining to record an action, and the run
treats one as a failure rather than as a slow append), **I5** (every segment's
anchor was read back out of a real Rekor and its inclusion proof verified from
first principles by a client holding no key of ours).

## Decision

**doc 05 §4's estimates are superseded by the measurements in the appendix
below.** Concretely:

1. The hot tier is sized at **1467 B per event**, not at the ≤1 KB canonical
   event size. The canonical event is 600 B on average; the rest is Postgres
   row overhead and the four indexes the schema carries. At doc 05 §4's own
   workload of 10⁶ runs/year × ~20 events/run this is **≈29.3 GB/year**, where
   the section estimated ~20 GB/year.
2. Segment objects are sized at **74 B per event**, which is a number doc 05 §4
   did not carry at all. At the same workload that is **≈1.5 GB/year** of
   object storage.
3. "Well inside a single modest Postgres" is upheld, and now has a margin
   attached: the sized workload averages **0.63 appends/s**, and a single
   containerised Postgres sustained **580–730 appends/s** — roughly **1000×**
   the average rate.
4. doc 05 §4's "Events are ≤1 KB canonical (LED-011)" is **confirmed**, not
   replaced: the largest canonical event observed across ~23,000 events was
   769 B.

The measurement is not a one-off. OPS-002 runs on every CI build at a sizing
that drives four real rollovers, and re-derives every number above; the
`INNSEGL_LOAD_REPORT` environment variable writes them as JSON. A future run
that contradicts this ADR supersedes it with a new one.

## Alternatives considered

**Estimate from the canonical event size and be done.** This is what doc 05 §4
already did, and the measurement shows why it was not enough: the stored cost
of an event is **2.4× its canonical bytes**, because a ledger row is a row in a
heap with four indexes over it and not a byte string in a file. An estimate
built from the serialized size understates the hot tier by that factor, and the
error is systematic rather than random — it grows with the number of indexes,
which is exactly the direction a query-serving ledger evolves in.

**Measure against an in-memory ledger and object store, and run in seconds.**
Rejected on the same ground IP §2 rejects a mocked Fulcio. Every number this
ADR records is a property of a real server: bytes-per-event is Postgres's row
layout and index fanout; throughput is an advisory lock, a trigger and an
`fsync`; the anchor latency is a real Trillian sequencing a real leaf. A run
against fakes would produce all of the same fields with none of the same
meaning, and the resulting page would be indistinguishable from this one.

**Take the throughput number and skip the single-writer calibration.** Rejected
because the calibration is what makes the concurrent number interpretable. 724
appends/s at 8 writers could be a saturated ledger or a lazy generator, and
only the serialized ceiling (589/s) and the latency-vs-concurrency curve
distinguish them. Without it this ADR would state a number it could not defend.

**Run the load test only on demand, behind an environment variable.** Rejected
for the reason issue #101 exists: a test that runs only when somebody remembers
is a test that has stopped running, and this repository has already shipped a
CI run in which five I5 cases silently did not execute. The full case runs in
CI at a smaller sizing, with the same assertions; the environment variables
scale it up and turn nothing off.

**Turn `fsync` off to get a bigger number.** Rejected outright. A ledger that
can lose an acknowledged append is not the system doc 05 is sizing, and the
figure would be a measurement of a different product.

## Consequences

**Easier.** doc 05 §4's revisit clause is discharged, and the sizing question
now has an answer with a machine behind it. Anyone provisioning a deployment
can multiply 1467 B by their expected event count. The hot-tier pruning doc 05
§4 mentions ("before pruning to index-only for sealed ranges") is now
quantifiable: pruning a sealed range to index-only removes the `canonical`
column, which is 600 of the 1467 bytes — a **41% reduction**, and it can be
stated instead of hoped for.

**Harder.** OPS-002 costs CI time. It stands up eight containers — Postgres,
MinIO, and Rekor over Trillian over MySQL with Redis — and the stack's start-up
dominates its runtime. On the machine below the whole case took **14 s wall**,
of which the four rollovers and every assertion took **2.8 s**. It also spends
one Docker network, which matters on a machine that refuses roughly the 29th
(#100).

**Now fixed.** The numbers below are dated and conditioned. They are not
portable: they were taken on Apple silicon under Docker Desktop, where the
container filesystem is a VM's and a published port is a proxied one. A
deployment on bare-metal Linux with local NVMe should expect a *different*
throughput, most likely a higher one, and the same bytes-per-event — because
row layout and index fanout are properties of Postgres and not of the disk.

**Doc changes.** doc 05 §4 is superseded by this ADR to the extent of the four
numbered items in the Decision. The section itself is not edited: it is a
normative specification, its own text says measured numbers supersede it "and
get recorded in an ADR appendix", and this is that appendix.

**Test-catalogue changes.** doc 07's OPS-002 row is unchanged; this is its
implementation. Four new test IDs are proposed for the catalogue's TC-OPS
section, all of them already implemented in `test/load/` and all of them
runnable without Docker:

| ID | L | Case | Expected |
|---|---|---|---|
| OPS-002a | U | Position scan convicts a gap, a duplicate, a reversal and a chain not starting at 1 | Each corrupt sequence reported; a contiguous run clean |
| OPS-002b | U | Heartbeat checker fed ten corrupted snapshots | Each convicted, with the reason naming the corrupted member |
| OPS-002c | U | Load harness routes an absent Docker to a skip and a stack that would not start to a failure | Both branches asserted; the sentinel is unreachable from a start-up fault (#101) |
| OPS-002d | F | One anchor watched at microsecond resolution during sustained load | The heartbeat reports the segment pending while it is in flight |

**Exit cost if reversed.** Low. The ADR is a record; reversing it means running
OPS-002 again and writing ADR-00NN with the newer numbers. What would be
expensive to undo is the CI cost, which is the eight containers — and that is
one line of sizing in `test/load/ops002_test.go`, not a design.

---

## Appendix — the measurements

### Conditions

Every number below was taken on one machine on **2026-09-01**. A throughput
figure without its conditions is not a measurement, so they are stated once
here and repeated in the test's own output on every run.

| | |
|---|---|
| Host | Apple M5 Pro, 18 cores, 48 GiB RAM, macOS 26.6.2 (25G83) |
| Container runtime | Docker Desktop, engine 29.6.2, VM with 18 CPUs and 15.6 GiB RAM |
| Go | go1.27.0 darwin/arm64, `GOMAXPROCS=18` |
| Postgres | `postgres:16`, started with `fsync=on` |
| Object store | `minio/minio:RELEASE.2025-09-07T16-13-09Z`, bucket with S3 object lock on, compliance mode |
| Transparency log | `ghcr.io/sigstore/rekor/rekor-server:v1.3.10` over `trillian_log_server`/`trillian_log_signer` v1.7.1 and `db_server:v1.4.0`, with `redis:7-alpine` |
| Workload | `tool_call` events, doc 02 §3's shape, distinct `idempotency_key` per append |

Two conditions matter enough to name separately.

**The race detector.** CI builds with `-race`, which instruments every memory
access in a process whose append path is Go all the way down to the socket.
Every run below records which build produced it. The race-detector numbers are
**lower bounds** on the same code built without it: 533 appends/s with, 724
without, at the same concurrency — a **26% cost**.

**Docker Desktop is a VM.** Postgres's storage is the VM's, and every published
port is proxied. The round-trip floor — a `SELECT 1` through the same pool and
socket the appends use — was **0.21 ms p50**, which is 12% of a serialized
append. That floor is part of what the append latencies below contain.

### What was run

Six runs. All twenty-one rollovers sealed, anchored and verified; **no run
produced a gap, a duplicate or an out-of-order chain position.**

| Run | Build | Writers | Rollovers × events | Appends | Wall |
|---|---|---|---|---|---|
| A (CI default) | `-race` | 8 | 4 × 200 | 905 | 1.70 s |
| B (soak) | plain | 8 | 5 × 2000 | 10 146 | 14.02 s |
| C1 | plain | 1 | 3 × 1000 | 3 073 | 5.29 s |
| C4 | plain | 4 | 3 × 1000 | 3 119 | 4.78 s |
| C16 | plain | 16 | 3 × 1000 | 3 150 | 5.14 s |
| C32 | plain | 32 | 3 × 1000 | 3 266 | 4.49 s |

### 1. Event size — doc 05 §4's "Events are ≤1 KB canonical (LED-011)"

**Confirmed, with the distribution attached.** Over run B's 10 156 events:

| | bytes |
|---|---|
| Smallest canonical event | 576 |
| Mean | 600.0 |
| Largest | 769 |

The mean is stable across every run (599.5–600.0 B). The maximum is a
`segment_sealed` event carrying its anchor, which is the largest event type the
schema has. **≤1 KB holds with ~25% headroom on the worst case.**

This is one shape of event. A deployment whose `tool_name`, `run_id` and
`spiffe_id` are longer will sit higher within the same bound; doc 02 §5's
bounds on those members are what keeps the bound a bound.

### 2. Hot tier — doc 05 §4's "~20 GB/year"

**Superseded.** Measured over run B, after `VACUUM (ANALYZE)`:

| Relation | total size | per event |
|---|---|---|
| `innsegl.events` (heap + 4 indexes + toast) | 14 802 944 B | 1457.6 B |
| `innsegl.chain` | 32 768 B | 3.2 B |
| `innsegl.idempotency` | 32 768 B | 3.2 B |
| `innsegl.schema_migrations` | 32 768 B | 3.2 B |
| **Whole `innsegl` schema** | **14 901 248 B** | **1467.2 B** |

**1467 B per event, against a 600 B canonical event: a 2.4× multiplier.** That
multiplier is the finding. It is Postgres's 24-byte row header and alignment,
the primary key on `chain_position`, and the three indexes migration 0001
creates (`events_run_id_idx`, `events_event_type_idx`, `events_ts_idx`).

Two honesty notes on this table.

- The three small relations are all at **32 768 B, which is four 8 KiB pages —
  their floor.** They are empty or near-empty. `innsegl.idempotency` is the MCP
  layer's store and is untouched by `ledger.Store.Append`, so a deployment
  serving MCP tools will carry more there than this run did.
- **Small runs overstate bytes-per-event, and the effect is visible in the
  data.** Run A's 913 events measured **1758.6 B/event**, because ~98 KiB of
  fixed relation floor is divided by 913. Run C's ~3100-event runs measured
  1476–1517 B. Run B's 10 156 events measured 1467 B. The number to size from
  is the largest run's, and the trend is why.

**Extrapolation, and it is arithmetic rather than measurement.** Nothing here
ran for a year. Taking doc 05 §4's own workload — 10⁶ runs/year × ~20
events/run = 2 × 10⁷ events/year — and multiplying by the measured
bytes-per-event:

- hot tier: 1467.2 B × 2 × 10⁷ = **29.3 GB/year (27.3 GiB/year)**
- doc 05 §4 estimated **~20 GB/year**, so the estimate was low by **≈1.47×**

The estimate was not unreasonable; it was the canonical size times the event
count, and it omitted what a database costs to keep a row in.

The pruning doc 05 §4 anticipates ("before pruning to index-only for sealed
ranges") removes the `canonical` column, which the table above measures at 600
of the 1467 bytes. **That the remainder is therefore ~867 B/event, or ≈17.3
GB/year, is arithmetic on a measurement and not itself measured** — nothing in
this run pruned anything, and a real prune leaves row headers and page
fragmentation behind. It is recorded as the direction and rough size of the
saving, not as a figure to provision against.

### 3. Segment objects — a number doc 05 §4 did not carry

Segment objects hold event *hashes*, not events (ADR-0006), so their cost per
event is small and nearly constant:

| Run | segment | object bytes | per event |
|---|---|---|---|
| B | 2000 events | 148 187 | 74.1 B |
| C | 1000 events | 74 186 | 74.2 B |
| A | 200 events | 14 984 | 74.9 B |

**≈74 B per event.** Extrapolated at doc 05 §4's workload: **1.5 GB/year
(1.4 GiB/year)** of object storage before any lifecycle transition. doc 05 §4
says "segment objects to standard object storage; lifecycle to archive class" —
at this size, the lifecycle policy is about retention rather than about cost.

### 4. Throughput — doc 05 §4's "well inside a single modest Postgres"

**Upheld, with a margin.**

| Writers | Throughput | append p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| 1 | 580 /s | 1.68 ms | 1.91 ms | 2.82 ms | 6.06 ms |
| 4 | 652 /s | 5.47 ms | 10.71 ms | 14.01 ms | 18.37 ms |
| 8 (run B) | 724 /s | 10.70 ms | 12.51 ms | 18.85 ms | 58.64 ms |
| 16 | 613 /s | 25.14 ms | 33.87 ms | 46.32 ms | 87.54 ms |
| 32 | 728 /s | 43.10 ms | 47.56 ms | 51.41 ms | 82.01 ms |
| 8, `-race` (run A) | 533 /s | 14.51 ms | 16.72 ms | 22.29 ms | 46.30 ms |

Single-writer serialized append, measured separately on a chain of its own with
the first fifth discarded as warm-up: **p50 1.70 ms**, a ceiling of **589
appends/s**.

Against doc 05 §4's workload, 2 × 10⁷ events/year is **0.63 appends/s** on
average. The measured sustained rate is **roughly 1000× that**. Even a
100×-peak-to-average burst leaves an order of magnitude of headroom on one
container on a laptop.

### 5. Seal and anchor

| | run B (2000-event segments) | run C (1000-event) | run A (200-event) |
|---|---|---|---|
| Seal p50 (Merkle tree, encode, `PUT` to MinIO under object lock, read back) | 12.1 ms | 8.5–9.8 ms | 13.8 ms |
| Anchor p50 (real Rekor: submit `hashedrekord`, Trillian queue, MySQL) | 159.7 ms | 149–171 ms | 134.1 ms |

Sealing is not on the append path, and the measurements confirm it stayed off
it: the writers kept appending through every rollover, which is IP §6.4's
"appends to the next segment continue".

### 6. The anchoring heartbeat — FD §3.1

Sampled every 5 ms for the whole of every run, with **2804 readings in run B
and 340 in run A, every one of them checked**. Checked means: the bound is the
configured bound, `over_bound` follows from the lag, `anchored` is never
claimed while a segment is pending, the pending count never exceeds what had
been submitted and not completed, the reported segment is the one the driver
anchored and ends where it says, `last_position` never walks backwards, and the
reported lag agrees with the *test's own* clock to within 500 ms.

| | |
|---|---|
| Maximum lag observed, 2000-event segments at 724 appends/s | **2.695 s** |
| Maximum lag observed, 1000-event segments | 1.20–1.63 s |
| FD §3.1's default amber bound | 15 min |

The steady-state lag is the interval between rollovers, which is what it should
be: it grows while the next segment fills and drops when that segment anchors.
At these segment sizes the default bound has roughly **330× of headroom**, and
an operator choosing a segment size can now read the lag off the segment size
and the append rate rather than guess it.

One assertion here is deliberately not left to sampling. A heartbeat pinned at
zero pending would satisfy every per-reading rule above, so OPS-002 watches one
whole anchor at microsecond resolution — 651 polls across the 194 ms the first
anchor took, in a default-sizing `-race` run — and requires the heartbeat to
have shown the segment pending while it was genuinely in flight.

### Was the harness the bottleneck?

**No, and this is measured rather than assumed.** Three independent pieces of
evidence.

**1. The writers were inside the ledger essentially all the time.** The
fraction of writer wall time spent inside `ledger.Store.Append` was **99.97%**
in run B, **99.63%** in run A, and never below **99.54%** in any run including
the 32-writer one. Everything the generator does — building a body, scheduling,
recording a latency — is the remaining 0.03–0.46%. The run **fails** if this
falls below 90%, so a future regression that made the generator the constraint
would be reported rather than published as a ledger throughput.

**2. Throughput plateaus while latency scales linearly with concurrency.** From
1 to 32 writers the rate stays in a 580–730 /s band — a 1.26× spread over a 32×
change in concurrency — while p50 latency goes 1.68 → 5.47 → 10.70 → 25.14 →
43.10 ms, which is very close to linear. That is the signature of a fully
serialized resource, and it is exactly what doc 02 §2's "serialized append" and
the store's advisory lock predict.

**3. Little's law closes.** Throughput × latency should equal the number of
writers if the writers are always queued at the same resource:

| Writers | throughput × p50 |
|---|---|
| 1 | 0.97 |
| 4 | 3.57 |
| 16 | 15.4 |
| 32 | 31.4 |

Every writer is queued at the ledger essentially all the time. **The number
being reported is the ledger's, not the generator's.**

What this does *not* establish is which part of the append costs the 1.70 ms.
The round-trip floor puts 0.21 ms of it in the driver and the socket; the
remaining ~1.5 ms is the advisory lock, the head read, the canonicalisation,
the insert, the append-only trigger and the `fsync`, and this ADR does not
apportion it. That decomposition is a separate measurement and nobody needs it
to size a deployment that is running at a thousandth of the rate.
