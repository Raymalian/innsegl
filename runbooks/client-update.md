# Updating the client on a machine

A machine enrolled with `innsegl connect` runs the client service from a
binary you built. After an update, the service has to run the new binary:
the CLI reaches the core through it, and an old service does not know the
CLI's newer calls.

"Machine" below is the enrolled machine, in the checkout its client service
runs from. The `make` targets run there: `cd` into the checkout first, or
name it, `make -C <checkout> client-restart`.

## Update

**Machine (macOS or Linux):**

```sh
git pull && make build && make client-restart
```

- `make build` compiles `./innsegl`. On macOS it then signs it with the
  newest-issued `Developer ID Application` identity in your keychain, as
  `dev.innsegl.cli`. macOS keeps the binary's Local Network permission across
  rebuilds only for a signed binary; an unsigned one is asked about again
  after every build. Most commands reach the core through the client service
  and do not need it; `innsegl connect` itself does, and so does
  `connect --disconnect` when the service is down. With no Developer ID
  identity it builds unsigned and says so. It then links the binary as
  `~/.local/bin/innsegl`, so `innsegl` runs by name from any directory, and
  says so once if `~/.local/bin` is not on your PATH. It restarts nothing.
- `make client-restart` restarts the client service, but only if it runs the
  `./innsegl` this checkout just built. If it runs another binary, it names
  that binary and leaves the service alone. It returns once the restarted
  service answers on its port, at most 30 seconds
  (`INNSEGL_CLIENT_RESTART_TIMEOUT`).

To sign with another identity, name it by its SHA-1 hash (two identities can
share one name):

```sh
security find-identity -v -p codesigning
INNSEGL_CODESIGN_IDENTITY=<sha-1> make build
```

`INNSEGL_CODESIGN_IDENTITY=none` builds unsigned.

## Check

**Machine:**

```sh
innsegl status
```

`innsegl` here is `~/.local/bin/innsegl`, the link `make build` made; in the
checkout, `./innsegl status` is the same binary. It says `client service up`,
and a `core up` line with the core's version. On macOS, `codesign -dv ./innsegl`
shows `Identifier=dev.innsegl.cli`.

## When it says something else

| Output | What to do |
|---|---|
| `client-restart: the client service runs <path>, not <path>; left as it is` | the service runs another binary. To move it onto this checkout's: `./innsegl connect --update --service`, with the same `--hardened` and `--managed-settings` you connected with. To restart it as it is: the command printed |
| `client-restart: the client service (…) is not loaded` | the machine has no client service. `innsegl connect` installs it |
| `client-restart: restarted the client service on <path>, but it did not answer on <addr> within 30s` | the service restarted and is not serving. Read its log (macOS: `tail -n 50 ~/Library/Logs/innsegl-client.log`; Linux: `journalctl --user -u innsegl-client.service -n 50`), then `innsegl status` |
| `innsegl: command not found` | `~/.local/bin` is not on your PATH: add `export PATH="$HOME/.local/bin:$PATH"` to your shell's startup file, or run `./innsegl` in the checkout |
| `link-bin: ~/.local/bin/innsegl is not a link; left as it is` | a file of your own is there. Remove it to have `make build` link this checkout's binary, or run `./innsegl` |
| `the client service is not answering at <addr>; start it: …` | run the command printed (macOS: `launchctl kickstart -k gui/$(id -u)/dev.innsegl.client`; Linux: `systemctl --user restart innsegl-client.service`) |
| `the client service is older than this command` | the binary was rebuilt and the service still runs the old one: `make client-restart` |
| `the core is older than this client; update the core` | update the core host, then run the command again |
| `codesign: … is not a code-signing identity this keychain holds` | `INNSEGL_CODESIGN_IDENTITY` names an identity you do not have; pick one from `security find-identity -v -p codesigning` |

## Rollback

**Machine:**

```sh
git checkout <previous-commit> && make build && make client-restart
```

## Gaps

| Gap | Instead |
|---|---|
| `make build` does not check that macOS granted the Local Network permission | a `no route to host` from `innsegl connect`, started in a terminal, is the permission. Allow it in System Settings → Privacy & Security → Local Network |
