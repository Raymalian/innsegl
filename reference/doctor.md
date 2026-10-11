# Doctor

## Purpose

`innsegl doctor` runs on the operator's machine. It checks every link of the
signing chain in order, one line each, runs the repairs that cannot lose
data, and prints anything that must happen on the core as one line starting
`VM:` (RM-344). It is the repair line `make update` prints when signing
fails after an update ([signing-probe.md](signing-probe.md)).

## Commands

```
usage: innsegl doctor [--identity F] [--managed-settings F] [--repo DIR]... [--wait D]

Check the signing chain from this machine to the core's CA, in order, one
line per check, and the rights innsegl holds on it: the hooks in Claude
Code's managed settings and the binaries they, the git hooks and the client
service run. Repairs it runs itself: restart the client service; unlock the
CA key store (asks for Touch ID); tighten the modes of innsegl's own key
files. Anything else is printed: a line starting "VM:" for you to run on the
core, or the command to run here. Exits 0 only when the signing probe
passes after the repairs; 37 when it does not; 2 on a usage error.

Flags:
  -identity string
    	the age identity that opens the CA's unlock material (a Secure Enclave identity asks for Touch ID) (default "~/.innsegl/trust-backup/identity.txt")
  -managed-settings string
    	the Claude Code managed settings whose innsegl hooks to check (default "/Library/Application Support/ClaudeCode/managed-settings.json")
  -repo value
    	a repository whose git hooks to check (repeatable; default: the current one)
  -wait duration
    	how long to wait for the signing probe to pass after a repair (default 6m0s)
```

The checks, in order:

| Line | Source | Repair |
|---|---|---|
| `host` | this machine's tools: git 2.31 or later, and each age plugin the identity file names ([client-and-connect.md](client-and-connect.md), Host dependencies) | none; each `MISSING` line names the install command for this OS. The checks after it run either way |
| `managed settings` | the managed settings (`--managed-settings`; on Linux `/etc/claude-code/managed-settings.json`): each hook event has exactly one innsegl hook, and each names this binary. `MISSING` (no hook for an event, or a binary that is gone), `DUPLICATE`, `FOREIGN` (another binary), `WRITABLE` (you own the binary or a folder above it, or one is group- or world-writable) | none: the file is an administrator's. Prints `innsegl connect --update`, or, for `WRITABLE`, to install innsegl where only an administrator can write it first |
| `service binary` | the binary the client service's definition starts (the LaunchAgent plist, or the systemd `--user` unit): the same checks | none; prints `innsegl connect --update --service` |
| `modes` | innsegl's own key files and folders: `~/.innsegl/client` and its `outbox`, `key.pem`, `proxy-ca-key.pem`, `authors.json`, the trust-backup identity and its folder, `~/.innsegl/trust-backups` and each `*.age` in it | removes group and other access (`chmod`), only on these, only ones you own, never through a symlink, never adding a bit. A file already tighter keeps its mode |
| `client service` | `/_client/status`: answers, runs this binary's build, not revoked, certificate not expired | restarts the service (`launchctl kickstart -k`, or `systemctl --user restart`). A service still down is pointed at its log: `~/Library/Logs/innsegl-client.log` on macOS, `journalctl --user -u innsegl-client.service` on Linux |
| `hooks` | each `--repo`: innsegl's `prepare-commit-msg`, `post-commit` and `reference-transaction` hooks, and the binary each runs (`FOREIGN`, `MISSING`, `WRITABLE` as above) | none; prints `innsegl link <repo>` |
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

Every command it runs goes through one fixed allow-list:

| Command | Why |
|---|---|
| `launchctl kickstart -k gui/<uid>/dev.innsegl.client`, or `systemctl --user restart innsegl-client.service` | the client restart, for this user only: the one repair it runs |
| `git --version` | the `host` line |
| `git -C <repo> rev-parse --path-format=absolute --git-common-dir`, `git -C <repo> rev-parse --git-path hooks/<name>` for each of innsegl's three hooks | the `hooks` line; read-only |
| `age-plugin-se --age-plugin=identity-v1`, `age-plugin-yubikey --age-plugin=identity-v1` | the unlock: the age library runs the plugin, so doctor checks it against the list first. An identity naming any other plugin is `NOT REPAIRED` |

It never runs `docker`, `down`, a volume removal, `ca-custody-reset`, a
rotation, a restore, or a destructive test package, and never writes the
managed settings. A trust root that drifted is never "fixed" from here.

## Settings

None of its own. It reads the enrolment under `~/.innsegl/client`, like
`innsegl status`.

## Files, volumes, containers

Reads the managed settings, the client service definition
(`~/Library/LaunchAgents/dev.innsegl.client.plist` or
`~/.config/systemd/user/innsegl-client.service`) and each repository's git
hooks. Changes only the modes in the `modes` row. The unlock goes through the client service, as `innsegl ca-custody
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
- `cmd/innsegl/doctorrights_test.go` (CLI-037, CLI-038, CLI-039, PROPOSED):
  managed-settings hooks naming another binary, a missing one or a writable
  one, events with none or two, are flagged and the file is only read; the
  service definition and git hooks naming another binary are flagged; every
  command reaches the fake runner and is on the allow-list, a plugin off it
  is refused, and programs on `PATH` that record being run never run; modes
  are only tightened, only on innsegl's own files
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

- Repairs that cannot lose data only: the client restart, the unlock, and
  tightening the modes of innsegl's own key files.
- What innsegl's hooks and service run is reported, never repaired: the
  managed settings need an administrator.
- Nothing on the core is run from the operator's machine.

## Runbooks

[runbooks/ca-custody.md](../runbooks/ca-custody.md), section "Signing
stopped".
