# Doctor

## Purpose

`innsegl doctor` runs on the operator's machine. It checks every link of the
signing chain in order, one line each, runs the repairs that cannot lose
data, and prints anything that must happen on the core as one line starting
`VM:` (RM-344). It is the repair line `make update` prints when signing
fails after an update ([signing-probe.md](signing-probe.md)).

## Commands

```
usage: innsegl doctor [--identity F] [--repo DIR]... [--wait D]

Check the signing chain from this machine to the core's CA, in order, one
line per check. Repairs it runs itself: restart the client service; unlock
the CA key store (asks for Touch ID). Anything on the core is printed as a
line starting "VM:" for you to run there. Exits 0 only when the signing probe
passes after the repairs; 37 when it does not; 2 on a usage error.

Flags:
  -identity string
    	the age identity that opens the CA's unlock material (a Secure Enclave identity asks for Touch ID) (default "~/.innsegl/trust-backup/identity.txt")
  -repo value
    	a repository whose git hooks to check (repeatable; default: the current one)
  -wait duration
    	how long to wait for the signing probe to pass after a repair (default 6m0s)
```

The checks, in order:

| Line | Source | Repair |
|---|---|---|
| `host` | this machine's tools: git 2.31 or later, and each age plugin the identity file names ([client-and-connect.md](client-and-connect.md), Host dependencies) | none; each `MISSING` line names the install command for this OS. The checks after it run either way |
| `client service` | `/_client/status`: answers, runs this binary's build, not revoked, certificate not expired | restarts the service (`launchctl kickstart -k`, or `systemctl --user restart`). A service still down is pointed at its log: `~/Library/Logs/innsegl-client.log` on macOS, `journalctl --user -u innsegl-client.service` on Linux |
| `hooks` | each `--repo`: innsegl's `prepare-commit-msg`, `post-commit` and `reference-transaction` hooks | none; prints `innsegl link <repo>` |
| `core` | `/_core/status` over the machine's certificate | none; prints a `VM:` line |
| `clock` | the core answer's `Date` against this machine; more than 30 s apart is `SKEWED` | none; prints a `VM:` line |
| `ca custody` | `/_core/ca-custody`: `can_sign` and its reason | sealed, or a token absent, refused, expired or unable to read the key: unlock (Touch ID). A key that drifted from `chain.pem`: none, the runbook |
| `spire`, `ledger`, `sigstore`, `worm canary`, others | `/readyz` through `/_core/status` | none; prints a `VM:` line |
| `signing` | the signing probe's report | after an unlock, waits up to `--wait` for a probe that passed after it |

The last line is `signing: OK (probe passed <time>)` when signing works.

An age plugin's own prompt during the unlock (for example, to touch a key)
is printed as a line starting `innsegl:`. `innsegl ca-custody unlock` and
`innsegl trust-backup drill` print it the same way, on stderr.

A run makes at most three custody calls. The core allows six per machine per
ten minutes; past that, doctor says to run it again in ten minutes.

It never runs anything else. Every command goes through a fixed allow-list
that holds only the client service restart for this user. It never runs
`docker`, `down`, a volume removal, `ca-custody-reset`, a rotation, a
restore, or a destructive test package. A trust root that drifted is never
"fixed" from here.

## Settings

None of its own. It reads the enrolment under `~/.innsegl/client`, like
`innsegl status`.

## Files, volumes, containers

None. The unlock goes through the client service, as `innsegl ca-custody
unlock` does ([ca-custody.md](ca-custody.md)).

## Exit codes and error classes

| Code | Meaning |
|---|---|
| 0 | the signing probe passed after the repairs |
| 2 | usage error |
| 37 | signing is not proven: a check failed that doctor cannot repair, or no probe passed within `--wait` |

## Tests

- `cmd/innsegl/doctor_test.go` (CLI-023, PROPOSED): the allow-list holds only
  the client restart; a fake runner records every call in every scenario and
  none is destructive; one line per check in order; a sealed store and a
  dead token are unlocked through a test age identity; drift is never
  repaired; core repairs are printed as `VM:` lines; clock skew; missing hooks
- `cmd/innsegl/doctorincident_test.go` (OPS-192, PROPOSED): a real store;
  custodians recreated faster than renewal keep the token alive; on the old
  behaviour the token dies, and on the new a revoked token, and each is
  reported by the probe within two intervals; doctor repairs each with one
  unlock, no command run and no container restarted
- `cmd/innsegl/doctorhost_test.go` (CLI-024, PROPOSED): the log hint on Linux
  is the user journal; `cmd/innsegl/preflight_test.go` (CLI-027, PROPOSED):
  the first line is the host check
- `cmd/innsegl/pluginprompt_test.go` (BAK-031, PROPOSED): a fake age plugin's
  message reaches the terminal

## Decisions

- Repairs that cannot lose data only: the client restart and the unlock.
- Nothing on the core is run from the operator's machine.

## Runbooks

[runbooks/ca-custody.md](../runbooks/ca-custody.md), section "Signing
stopped".
