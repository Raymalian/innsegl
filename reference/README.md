# Reference

One page per part of innsegl. Each page has the same headings: Purpose,
Commands, Settings, Files/volumes/containers, Exit codes and error classes,
Tests, Decisions, Runbooks.

Flags and defaults are copied from `innsegl <cmd> -h` and the Makefile's `##`
help lines. When the code changes, the code wins; fix the page.

| Part | Page |
|---|---|
| Every `innsegl` subcommand, one line each | [cli.md](cli.md) |
| Client service, `connect`, `status` | [client-and-connect.md](client-and-connect.md) |
| Commit hook and signing path (`hook`, `git-hook`, `sign`, `link`, `init`) | [commit-path.md](commit-path.md) |
| Identity: register, retire, admin credential, identity guard | [identity.md](identity.md) |
| Gateway capture of model traffic | [gateway.md](gateway.md) |
| Ledger, segments, sealing, canary, ledger backup | [ledger-and-segments.md](ledger-and-segments.md) |
| Reconciler and reaper | [reconciler-and-reaper.md](reconciler-and-reaper.md) |
| Verify: CLI, verdicts, pre-history, branch gate | [verify.md](verify.md) |
| Dashboard and query API, accounts | [dashboard-api.md](dashboard-api.md) |
| Trust history (ADR-0073) | [trust-history.md](trust-history.md) |
| Trust-key backup and drill (ADR-0074) | [trust-key-backup.md](trust-key-backup.md) |
| CA password and rotation (ADR-0075) | [ca-password-and-rotation.md](ca-password-and-rotation.md) |
| CA key custody (ADR-0076) | [ca-custody.md](ca-custody.md) |
| Stack modes, trust volumes, every make target | [stack-and-make.md](stack-and-make.md) |
| Transparency log (Rekor and Trillian) operations | [transparency-log.md](transparency-log.md) |

## Keeping it complete

`test/deploy/referencedocs_test.go` (DOC-001, PROPOSED) fails when a
subcommand in `cmd/innsegl/cli.go`'s command table, or a Makefile target with
a `##` help line, is not named in backticks on some page here. Run it with:

```
go test -count=1 ./test/deploy/ -run DOC
```

Specs (doc 01 to doc 08) are local only and are cited by number, never quoted.
