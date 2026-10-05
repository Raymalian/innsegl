# ADR-0072: A development stack is never the live one

- Status: accepted
- Date: 2026-10-05
- Deciders: the operator

## Context

A machine that develops innsegl can also be an enrolled client of a core
somewhere else, and still bring up a full stack of its own with `make start`.
That stack used the live names: the compose projects `innsegl-spire`,
`innsegl-sigstore` and `innsegl-core`, the same container and network names,
and the same trust volumes, `innsegl-trust-*`. So:

- its Fulcio signed with whatever CA key `innsegl-trust-fulcio-pki` held on that
  machine. If that volume held a live deployment's CA, a commit the
  development stack signed would verify as live. `innsegl verify` pins the
  Fulcio root, not the trust domain (`internal/verify/sigstore.go`), so the CA
  key is what separates the two;
- its gateway wrote its CA certificate to `$HOME/.innsegl/ca/gateway-ca.pem`.
  That is the file the machine's own commit hook trusts for its core
  (`internal/commitpath`), so starting the stack re-pointed the client;
- nothing in its names or its output said it was a development stack, and an
  agent could start it by accident.

Being enrolled is not a safe signal that a host is not the core. The core host
connects to itself as well (`install.sh --local-client`). If a live core
switched modes because `~/.innsegl/client/core.json` exists, its next start
would boot an empty trust root next to its real one.

## Decision

1. **The mode is an explicit marker.** `INNSEGL_STACK=dev|live` in the
   environment wins. Otherwise the checkout's `.innsegl/stack-mode` decides,
   or failing that the repository's main worktree's, which is gitignored and
   written by `make dev-stack`. **No marker means live**, and live is
   unchanged: the same compose files, names, trust volumes and settings, so a
   live core sees nothing on its next `make update`. `scripts/stack-mode.sh`
   is the one place that decides.
2. **An enrolled client without a marker is warned and never switched.**
   `make start` prints one line naming the core it is a client of and
   `make dev-stack`.
3. **A dev stack has its own names.** Overlays in `deploy/compose/dev/`
   rename every compose project, container and network to `innsegl-dev-*`.
   They follow the `spire-testscope.yml` pattern and leave the base files
   untouched. Every host-side script that calls a container by name takes the
   prefix from `INNSEGL_STACK_PREFIX`. The transparency-log pin is
   `deploy/compose/.rekor-tlog-id.innsegl-dev`.
4. **A dev stack has its own trust root.** Its trust volumes are
   `innsegl-dev-trust-*`. `trust-volumes.sh` creates them empty and migrates
   only into the default prefix, so a dev Fulcio mints its own CA. A commit it
   signs chains to a root no live Fulcio publishes, and verification fails it.
   Live-named volumes already on the machine are not touched. Key custody is
   live only.
5. **A dev stack keeps out of the client's folders.** The gateway CA, the
   harness log and the backups move under `$HOME/.innsegl/dev/`. Nothing on
   the bring-up path writes harness settings or runs `innsegl connect`.
6. **A dev stack is loopback only.** A non-loopback `INNSEGL_BIND`, from the
   environment or `deploy/compose/.env`, is refused before anything starts. So
   is a legacy trust prefix, and so is a running live-named stack whose ports
   a dev stack would collide with.
7. **The trust domain is unchanged.** It stays `innsegl.dev`. SPIRE's
   configuration states it as a literal on purpose, so that it cannot be
   re-rooted by a variable. A distinct dev trust domain is deferred. What says
   DEV is the names, the bring-up line and the separate CA.

## Consequences

- A development machine marks itself once with `make dev-stack`. Its first dev
  start mints a new, empty deployment: a new CA, log and ledger, and a new
  admin account through the setup link.
- `scripts/test-suite.sh` counts the dev projects as a deployment, so the
  destructive test packages refuse while a dev stack is up.
- A dev stack and a live-named stack cannot run side by side on one machine.
  They publish the same loopback ports.
- OPS-129 (`test/deploy/devstack_test.go`, `scripts/stack-mode-selftest.sh`)
  holds the live names unchanged and every dev name distinct.
