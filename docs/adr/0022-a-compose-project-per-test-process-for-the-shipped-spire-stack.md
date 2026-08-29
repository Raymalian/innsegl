# ADR-0022: Give every test process that drives the shipped SPIRE stack a compose project of its own, and require the project name rather than defaulting it

- Status: accepted
- Date: 2026-08-29
- Deciders: Mike

## Context

`deploy/compose/spire.yml` is the adopter-facing artifact. It pins
`name: innsegl-spire`, a fixed `container_name:` on every service and a fixed
`name:` on every network, which is correct for a deployment: an operator wants
to find `innsegl-spire-server` under that name, and ADR-0011's segmentation is
expressed as membership of networks with stable names.

That same property makes it a shared mutable singleton for tests. Four packages
drive a SPIRE stack, and three of them used to select this one:

| package | what it drove | scoped to the process? |
|---|---|---|
| `test/failure` | the shipped stack under an overlay | yes, since ADR-0015 |
| `internal/spire` | the shipped stack, fixed names | no |
| `internal/mcp` | the shipped stack, fixed names | no |
| `cmd/innsegl` | an anonymous MinIO container, no compose | not applicable |

`go test ./...` runs packages concurrently, so `internal/spire` and
`internal/mcp` raced each other inside a single invocation; and two concurrent
`go test` invocations — routine while `scripts/coverage-floors.sh` runs beside
an ordinary test run, or two agents work at once — raced two copies of *each*
binary as well. `-p 1` was shipped in `.github/workflows/ci.yml` and
`scripts/coverage-floors.sh` as a stopgap. It orders packages within one
invocation and does nothing at all between processes, which is why the flake
survived it.

**The damage is not flakiness.** ADR-0015 records the first measurement of what
a shared datastore does to an assertion about a datastore: a control entry
belonging to pid 38913 appeared in pid 35815's datastore mid-case and failed
SPI-006 with "an entry appeared 18.99s after recovery ... That is a queued
identity" — a false accusation of exactly what SPI-006 exists to detect.

RM-065 measured the same class of damage on the two remaining packages. Two
concurrent `go test ./internal/spire/ ./internal/mcp/ -race` processes against
the pre-change harnesses, 2026-08-29:

- **SPI-005** planted its *local-socket control* — the entry that shows the
  server itself has no objection, so that the admin denial is attributable to
  the authorization policy — and got
  `AlreadyExists ... "similar entry already exists"`, because the other process
  had planted the identically-named control first. The case reported: *"the
  local socket refused `spiffe://innsegl.dev/innsegl/rogue-local-control` too,
  so the admin denial above is not attributable to the authorization policy."*
  ADR-0012's policy was working; the test said it could not be shown to be.
- **SPI-008** failed to plant its unexplained entry at all, same
  `AlreadyExists`, same cause.
- **SPI-003** reported *"the reaper recorded the expiry but did not delete the
  entry"* — the other process's reaper had deleted it, so the shipped reaper
  was accused of a half-completed retirement it had in fact completed.

Three cases, three false conclusions about production behaviour, none of them
true of the system under test. IP §2 makes CI a merge gate; a gate that can
convict the system of a violation it did not commit is worse than one that
occasionally fails, because a green run after a red one now teaches the reader
to discount the red.

## Decision

Every test process that drives `deploy/compose/spire.yml` brings it up under a
**compose project, container names and network names unique to that process**,
via a `-f` overlay applied on top of the shipped file:

- `deploy/compose/spire-testscope.yml`, interpolating the **required** variable
  `INNSEGL_SPIRE_TEST_STACK`, used by `internal/spire` (`innsegl-spiretest-<pid>`)
  and `internal/mcp` (`innsegl-mcptest-<pid>`);
- `test/failure/spire-isolated.yml`, interpolating the required variable
  `INNSEGL_FAILURE_STACK` (`innsegl-failure-<pid>`), unchanged from ADR-0015 —
  it additionally sets `restart: "no"` on the two services SPI-006 and SPI-007
  SIGKILL, which the other suites must not have.

The variables are `:?`-required and never defaulted, so an unset value is a
compose error naming the fix rather than a silently shared stack that no test
process owns or tears down. The suite component of the prefix makes "no two
packages can select the same project name" true by reading, not merely true
because two live processes cannot share a pid.

`deploy/compose/spire.yml` is unchanged. The overlays change names and, for
`test/failure`, the restart policy — nothing else: not the image digests, the
configs, the PKI bootstrap, the selectors, the authorization policy, or the
network segmentation of ADR-0011.

Two consequences are deliberate and follow directly: a harness can no longer
reuse a stack a developer already had up, because it cannot see one; and it
therefore always tears its own down. The `-p 1` stopgap is removed from all
three call sites.

## Alternatives considered

**Keep `-p 1`.** It does not fix this. `go test -p 1` serialises packages
within one invocation; the measured collisions above are between *processes* —
`coverage-floors.sh` beside a test run, two agents at once, CI's `test` job
beside nothing at all but a developer's laptop beside plenty. It also pays a
real cost for the appearance of a fix: the suite loses package-level
parallelism everywhere, including in the packages that never touch Docker.

**Parameterise `deploy/compose/spire.yml` itself with a defaulted project
name.** Would remove the overlay, and breaks the requirement that makes the
overlay sound. A default is what produces a shared stack under a name no
process owns — the state RM-018 traced to "No such container:
innsegl-failure-spire-server" for someone running the suite while an older
fixed-name stack was up. Making the variable required in the shipped file
instead is worse still: `docker compose -f deploy/compose/spire.yml up -d`,
which `spire/README.md` documents and adopters run, would fail with a variable
error. The deployment shape must stay identical, so the requirement lives in a
file only tests pass.

**One overlay shared by all three suites.** Rejected on the restart policy.
`test/failure` needs `restart: "no"` on `spire-server` and `spire-agent` or
Docker restarts them within a second of the SIGKILL and the outage window
closes before the assertion runs — a failure-injection test that injects
nothing. `internal/spire` and `internal/mcp` must run the shipped restart
policy, since it is part of what they are testing. A single file with the
restart policy in it would silently weaken layer-F, and a single file without
it would silently weaken layer-I.

**A lock file, or a `TestMain` mutex, serialising access to one shared stack.**
Fixes the concurrency and not the state: a process killed mid-case leaves its
entries in the datastore for the next holder of the lock to find, which is the
SPI-005 and SPI-008 failure above with extra steps. A stale lock hangs CI
rather than failing it. And it cannot be taken by `test/failure` at all, which
destroys the stack by design.

**Let each harness reuse a running stack when it finds one, as `internal/spire`
and `internal/mcp` did.** This was the mechanism, not a mitigation. It made the
outcome depend on scheduling: whichever package started first "owned" the stack
and tore it down on exit, while the other was mid-case; and `internal/mcp`'s
reuse path additionally ran `compose restart spire-server` — needed because
SPIRE reads `authz-policy.rego` once at startup from a bind mount — which
landed on whatever `internal/spire` was doing at the time. With a stack per
process there is nothing to reuse and nothing to restart: a server this process
just created cannot be enforcing a stale policy.

**Randomise the project name instead of deriving it from the pid.** Loses the
one useful property of the pid: a leftover stack can be reclaimed and removed
by the process that inherits its pid, which is how an interrupted run stops
being a permanent leak. Randomness accumulates orphans that nothing will ever
clean up.

## Consequences

**Easier.** `go test ./... -race` at default parallelism is the supported way
to run the suite, and two agents can run it at once. No case's result depends
on which package the runner scheduled first, or on what the developer had
running before. A developer's own `docker compose -f deploy/compose/spire.yml
up -d` stack is now untouchable by the test suite — neither reused nor torn
down.

**Harder, and paid every run.** Up to three SPIRE stacks concurrently instead
of one shared: roughly 30–40 seconds of bring-up and three containers, three
networks and five volumes each, per concurrent `go test ./...`. The suite is
heavier on a laptop than it was; it is also, for the first time, measuring what
it claims to measure.

**Duplication is now three-way.** `internal/spire`, `internal/mcp` and
`test/failure` each carry their own copy of the socat-onto-the-admin-network
hop and the `spire-server x509 mint` admin credential, because a harness in a
`_test.go` file cannot be imported. ADR-0015 already recorded this for two;
adding the third does not change the shape, but the drift risk grows. If a
fourth appears, extracting an internal test-support package is the answer, not
a fourth copy.

**What must change with this.** `-p 1` is gone from `.github/workflows/ci.yml`
(both jobs) and `scripts/coverage-floors.sh`; re-adding it would hide a
regression here rather than work around one. Any future package that drives
`deploy/compose/spire.yml` must apply an overlay and set its own prefix — a
package that does not is a shared-singleton bug that will present as a false
accusation, not as a compile error.

**Exit cost.** Low and local. Deleting `deploy/compose/spire-testscope.yml` and
pointing the two harnesses back at the bare shipped file is a few lines per
harness, and re-introduces every failure quoted above. Nothing outside the test
harnesses depends on the overlay, and the shipped stack has not changed, so
nothing an adopter runs is affected either way.
