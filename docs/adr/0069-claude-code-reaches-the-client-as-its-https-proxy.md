# ADR-0069: Claude Code reaches the client as its HTTPS proxy

- Status: accepted
- Date: 2026-10-03
- Deciders: the operator

## Context

The client service (ADR-0063) captured Claude Code's model requests by being
its base URL: the managed settings set `ANTHROPIC_BASE_URL` to the client.
Claude Code turns off the features it reserves for a direct connection
whenever that variable points anywhere but the provider. Measured on Claude
Code 2.1.288: `/remote-control` and `/ultrareview` disappear, and the
documentation lists more. Connecting innsegl therefore took features away,
which connecting must never do.

Claude Code documents standard proxy support: `HTTPS_PROXY`, and a
TLS-inspecting proxy whose root is trusted through `NODE_EXTRA_CA_CERTS`. It
pins no certificate, turns nothing off behind a proxy, and sends the session
and agent ids as request headers either way.

## Decision

1. The managed settings never set `ANTHROPIC_BASE_URL`. They set the four
   proxy variables to the client, `NO_PROXY` to loopback, and
   `NODE_EXTRA_CA_CERTS` to the client's proxy CA. `connect --update`
   removes the base URL an earlier version wrote, and any other one: a base
   URL routes model requests past the client.
2. The client accepts CONNECT. It opens the provider's API host only. A model
   request there goes into the path to the core that a base-URL request took:
   recorded, with the fallback and journal of ADR-0068. Any other request
   there (Remote Control, sign-in, settings, telemetry) passes straight to the
   provider and is never logged or journaled. A POST under the API that is
   neither is passed through and reported as a finding. Every other host is a
   blind tunnel; one that cannot be reached is a 502.
3. The proxy CA is the client's own: created on the machine, the key never
   leaving the client folder, name-constrained to the provider's API host, so
   whatever trusts it can be fooled about no other site. Leaves are
   short-lived and held in memory.
4. The proxy is for Claude Code's own requests. The session hook removes the
   proxy variables that point at the client from the agent's shell
   (`CLAUDE_ENV_FILE`), so the agent's tools never depend on the client and
   never trust its CA. A proxy the person set themselves stays.
5. The client's own outbound connections never use a proxy.
6. Whether connecting innsegl changes what Claude Code offers is checked, not
   assumed: a harness-compatibility check compares the slash-command, tool
   and MCP lists and a set of functions with innsegl and without it, and is
   run on each new Claude Code version.

## Alternatives considered

- **Keep the base URL.** Loses the direct-connection features, now and with
  every feature added to that list later.
- **Pause innsegl for sessions that need them.** Those sessions go
  unrecorded.
- **Proxy every host through the client unopened, and capture elsewhere.**
  Nothing else sees the model requests.

## Consequences

- Connecting innsegl leaves Claude Code's features as they were; measured
  2026-10-03 against a machine without innsegl.
- The client decrypts the provider traffic it passes through, including
  sign-in and Remote Control. It holds none of it and logs paths only (doc 04).
- A program an agent runs that calls the provider itself goes direct, as any
  program without the proxy does; it is not recorded. Before, it reached the
  core and was refused. The unrouted-session detector is what notices it.
- A machine that already routes Claude Code through a proxy of its own is not
  covered yet: the client tunnels other hosts directly.
