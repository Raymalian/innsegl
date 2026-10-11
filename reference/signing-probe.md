# Signing probe

## Purpose

Says whether the core's CA can sign, by asking it to. Every five minutes the
core requests one certificate from Fulcio for a fresh key, under a probe
identity. The probe passes when the certificate carries that key, names the
probe identity, and chains to the trust root Fulcio publishes. Nothing is
written to the transparency log or the ledger; the certificate and its key
are thrown away (RM-339).

Fulcio serving its root certificate means only that Fulcio is reachable. That
is still `/readyz`'s `sigstore` dependency. Whether signing works is this
probe's report.

The probe identity is a run identity in the existing grammar:
`spiffe://<trust-domain>/agent/innsegl-signing-probe/scheduled/probe`. It has
no registration entry; the core mints its credential the way `get_credential`
does, through SPIRE's `MintJWTSVID`, which the mint policy already admits for
the agent subtree.

## Commands

```
usage: innsegl signing-probe [serve flags]

Ask the CA for one certificate under the probe identity, now, and say whether it
passed. Run inside the core: it reads the same settings as `innsegl serve`.
Exits 0 on a pass, 35 when the CA did not issue a certificate that passed,
36 when the probe could not be set up.
```

Inside the core's container, the variables are already set:

```
docker exec innsegl-mcp innsegl signing-probe
```

It prints one line: `signing: ok — the CA issued a certificate at <time>`, or
`signing: FAILING — <reason>`.

## Settings

None of its own. The schedule is fixed at 5 minutes. The probe uses `innsegl
serve`'s `-fulcio-url` (`INNSEGL_FULCIO_URL`), `-trust-domain`
(`INNSEGL_TRUST_DOMAIN`), `-spire-address` (`INNSEGL_SPIRE_ADDRESS`) and the
admin credential settings ([identity.md](identity.md)).

## Where it shows

| Where | What |
|---|---|
| `/readyz` `reports` | `{"name":"signing","ok":false,"detail":"FAILING since <time> — <reason>"}`, or `ok: true` with `a certificate was issued at <time>`. A report: it never makes the core unready |
| `innsegl status` | `signing: FAILING since <time> — <reason>`, counted as down (exit 1); `signing up a certificate was issued at <time>` when it works |
| Client service | a macOS notification on the first failure, and a log line; nothing more until signing has worked again. `GET /_client/status` `signing` holds the last reading |
| Commit hook | a refused unsigned commit says `signing is down since <time> (<reason>)` ([commit-path.md](commit-path.md)) |

`since` is the first failed probe of the current outage. A result older than
two intervals (10 minutes) is a failure: `no probe has finished since then;
the probe is not running`. Before the first probe finishes, the report is
`the first probe has not finished`, not a pass.

## Files, volumes, containers

Runs inside `innsegl-mcp` (`innsegl serve`). No file, no volume. The client
service reads it from `/_core/status` every minute.

## Exit codes and error classes

| Command | Code | Meaning |
|---|---|---|
| `signing-probe` | 0 | the CA issued a certificate that passed |
| `signing-probe` | 35 | FAILING: the reason is on stdout |
| `signing-probe` | 36 | the probe could not be set up (no SPIRE credential, a setting it cannot use) |

## Tests

- `internal/signprobe/integration_test.go` (SIG-015, PROPOSED): a real SPIRE
  mints the probe's credential and the shipped Fulcio issues the certificate;
  a token Fulcio refuses, a certificate under another root, and a stopped
  Fulcio are failures with the reason
- `internal/signprobe/signprobe_test.go`, `monitor_test.go` (SIG-015): every
  named refusal; failing since the first failure; stale after two intervals
- `cmd/innsegl/servesignprobe_test.go` (SIG-015): the `/readyz` report and
  the one-shot command
- `cmd/innsegl/status_test.go` (SIG-015): the `signing: FAILING since` line
- `internal/client/signingwatch_test.go` (SIG-015): one notification per outage;
  (JRN-011) the last reading in `/_client/status`, read back by the hook
- `cmd/innsegl/hookoffswitch_test.go` (JRN-011): the refusal carries the
  outage the client service reports

## Decisions

- No transparency-log write: a probe every five minutes would leave a
  permanent public entry each time.
- A report, not a readiness gate: the core keeps recording when it cannot
  sign.

## Runbooks

`signing: FAILING`: on the operator's machine, run `innsegl doctor`
([doctor.md](doctor.md)). `HTTP 500` from Fulcio usually means the CA cannot
reach its key. See [ca-custody.md](ca-custody.md).
