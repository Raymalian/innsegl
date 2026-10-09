# Commit hook and signing path

## Purpose

An agent's `git commit` is attributed to the tool call that made it, and
signed by the core (ADR-0059). Three host commands do this: the harness hook
adds the tool call id, git's prepare-commit-msg hook adds the run's trailers,
and git's signing program asks the core to sign. A human's own commit is left
alone.

## Commands

```
innsegl hook pre-tool-use | session
innsegl git-hook prepare-commit-msg <message file> [<source> [<sha>]]
innsegl sign --status-fd=<fd> -bsau <key>      (run by git as gpg.x509.program)
innsegl link <repo dir>
innsegl link -remove <repo dir>
innsegl init [flags]
innsegl init -undo [-repo path]
make link DIR=<path to a git repository>
```

| Command | Run by | Does |
|---|---|---|
| `innsegl hook pre-tool-use` | the harness, before a Bash tool call | for a `git commit`, prefixes the command with `INNSEGL_TOOL_USE_ID` and places the signing config inside the git invocation as `-c` options, using this same binary as `gpg.x509.program` |
| `innsegl hook session` | the harness, on session start, user prompt, subagent start, cwd change | tells the gateway the session's working directory |
| `innsegl git-hook prepare-commit-msg` | git | asks the core for the trailers `Agent-Identity`, `Agent-Run`, `Agent-Task` and writes them into the message |
| `innsegl sign` | git | sends the commit payload to the core and returns the signature; `--verify` is git's verify mode |
| `innsegl link` | the operator | installs (or with `-remove`, restores) the repository's prepare-commit-msg hook; touches nothing else |
| `make link` | the operator | runs `innsegl link` with the binary `make build` wrote; refuses a linked worktree path |
| `innsegl init` | the operator | the older one-repository path: pins gitsign, chooses a trust root, signs a test commit and verifies it; `--local` git config only |

`innsegl init` flags (from `-h`; defaults in brackets):

| Flag | Meaning |
|---|---|
| `-repo` | repository to set up [`.`] |
| `-trust-root` | `self-hosted` or `public`; empty prompts (`$INNSEGL_INIT_TRUST_ROOT`) |
| `-identity-mode` | `pseudonymous` or `literal` (`$INNSEGL_IDENTITY_MODE`) |
| `-identity-secret`, `-identity-secret-file` | the pseudonymisation key (`$INNSEGL_IDENTITY_SECRET`, `$INNSEGL_IDENTITY_SECRET_FILE`) |
| `-fulcio-url`, `-rekor-url` | this deployment's endpoints (`$INNSEGL_FULCIO_URL`, `$INNSEGL_REKOR_URL`) |
| `-oidc-issuer` | the issuer Fulcio believes (`$INNSEGL_SPIRE_JWT_ISSUER`) |
| `-spire-address`, `-spire-server-id`, `-trust-domain` | SPIRE admin API (`$INNSEGL_SPIRE_ADDRESS`, `$INNSEGL_SPIRE_SERVER_ID`, `$INNSEGL_TRUST_DOMAIN`) |
| `-workload-api` | Workload API socket [`unix:///run/spire/agent-sockets/api.sock`] |
| `-admin-svid`, `-admin-key`, `-admin-bundle` | PEM files instead of the Workload API |
| `-gitsign-path`, `-gitsign-version` | trust this gitsign binary, or pin a release [`0.17.1`] |
| `-hook` | also install a pre-push hook refusing unsigned commits |
| `-author-name`, `-author-email` | author of the test commit |
| `-non-interactive` | never prompt (`$INNSEGL_INIT_NONINTERACTIVE`) |
| `-json` | report as JSON |
| `-undo` | reverse a prior run exactly, and exit |

### Commit author per repository

```
innsegl author                                    list the setting
innsegl author repo <path> operator|agent          one repository's mode
innsegl author operator 'Name <address>'           optional: a typed identity instead
```

Every repository is `agent` mode unless set otherwise: agent commits are
authored and committed as `Innsegl <agent@innsegl.invalid>`. In `operator`
mode they are authored as the repository's own `git config user.email`, which
must be a GitHub noreply address, with that address's login as the name;
`user.name` is never read. The agent stays in the trailers and the signature
(I6 allows the operator as author).

Setting operator mode reports the pair to the core (`POST
/_core/operator-author`, over the machine's certificate). The core pins it
for that installation on first use, and gate 3 of the sign path then admits
it for that installation's commits, beside the agent address and any pair in
`INNSEGL_SIGN_AUTHOR_OPERATORS`. A different pair later is refused (409) until
`innsegl accounts author-reset <installation>` on the core. A repository with
no noreply address falls back to the agent address, with a note on stderr.
A command that sets `GIT_AUTHOR_*` itself is left as it is.

## Settings

| Variable | Read by | Meaning |
|---|---|---|
| `INNSEGL_CORE_URL` | `hook`, `git-hook`, `sign` | the client service, which forwards to the core (`internal/commitpath/commitpath.go:36`) |
| `INNSEGL_TOOL_USE_ID` | `git-hook`, `sign` | the tool call id the hook injected |
| `INNSEGL_BIN_PATH` | `make link` | the binary to run [`./innsegl`] |
| `INNSEGL_SIGN_AUTHOR_OPERATORS` | the core (`.env`) | pinned `Name <address>` pairs an agent commit may be authored as; empty by default |

Core routes: `/_gateway/commit-trailers` and `/_gateway/commit-sign`, on the
gateway's listener, scoped to the calling installation; and, on a hosted
core, `/_core/operator-author` (POST, behind the client certificate guard).

## Files, volumes, containers

- The repository's `prepare-commit-msg` hook, written by `innsegl link`.
- `~/.innsegl/client/authors.json` (0600): the repositories set to `operator` mode, and the optional typed operator identity.
- On the core, `innsegl_auth.installations.operator_author_name` and
  `operator_author_email` (migration 0015): each installation's pinned pair.
- No repository git config is written by the hook path; the signing config
  travels with the one commit as `git -c` options placed before the
  subcommand word (`git -C dir -c commit.gpgsign=true … commit`), never as
  a `GIT_CONFIG_*` variable: the harness's worktree-isolation guard refuses
  a command that sets one.
- `make innsegl-init` runs `innsegl init` in the `innsegl-init` container
  (compose profile `init`); see [stack-and-make.md](stack-and-make.md).

## Exit codes and error classes

| Command | Code | Meaning |
|---|---|---|
| `hook pre-tool-use` | 0 | always; anything it cannot handle is left alone and refused later by git |
| `hook session` | 2 | before a user turn only: the client service is unreachable, so the prompt is stopped |
| `git-hook`, `sign` | 1 | refused (no resolvable tool call id, or the core said no); git aborts the commit |
| `link` | 2 | usage or a refusal; the message says which |
| `init` | 14 | UNVERIFIED: setup did not prove itself |
| `init` | 15 | INCONCLUSIVE: nothing could be attempted, or nothing to undo |

## Tests

- `cmd/innsegl/hook_test.go` (CMT-001 to CMT-003, ENF-005), `hooksession_test.go`,
  `sessionworkspace_test.go`, `sessionworkspacestated_test.go`
- `cmd/innsegl/githook_test.go` (CMT-004, CMT-005, CMT-016, SIG-006),
  `committrailers_test.go`
- `cmd/innsegl/sign_test.go` (CMT-013, CMT-014), `commitsign_test.go`,
  `signpush_test.go`, `signrepo_test.go`, `commitpathmount_test.go`
- `cmd/innsegl/link_test.go` (ENF-004, ENF-005)
- `cmd/innsegl/init*_test.go` (INIT-001 to INIT-010)
- `internal/commitpath/*_test.go` (CMT-006, TLS-001, TLS-002)
- `internal/mcp/signpayload_test.go`, `signpayload_crash_test.go` (CMT-007 to CMT-012)
- `internal/signing/*_test.go` (SIG-001 to SIG-012), `signpayload_test.go` (GH-006)
- `cmd/innsegl/hookauthor_test.go` (ENF-010), `authorcli_test.go` and `internal/client/authors_test.go` (ENF-011)
- `cmd/innsegl/hookauthorauto_test.go` (ENF-013): the repository's noreply address, never `user.name`
- `internal/client/operatorauthor_test.go` (ENF-012): the machine's report to the core
- `internal/accounts/operatorauthor_test.go` (GH-008, real Postgres): first-use pin, refusal, reset
- `internal/mcp/operatorauthor_test.go` (GH-009): gate 3 admits the installation's pin only
- `cmd/innsegl/coreoperatorauthor_test.go` (GH-010): the core route, including an enrolled machine end to end
- `test/deploy/authoroperators_test.go` (GH-007)

## Decisions

- [ADR-0028](../docs/adr/0028-place-commit-trailers-in-process-and-refuse-the-messages-git-places-ambiguously.md) trailer placement
- [ADR-0031](../docs/adr/0031-orchestrate-released-gitsign-through-git-commit-and-configure-around-the-absent-ct-log.md) gitsign through git commit
- [ADR-0046](../docs/adr/0046-make-every-agent-commit-signed-without-anyone-remembering-to.md) every agent commit signed
- [ADR-0047](../docs/adr/0047-anchor-attribution-to-the-change-not-the-commit-object.md) attribution to the change
- [ADR-0059](../docs/adr/0059-a-commit-is-attributed-through-the-tool-call-that-made-it.md) the commit path
- [ADR-0071](../docs/adr/0071-the-projects-mount-tools-are-deprecated-and-their-implementation-removed.md) mount tools removed

## Runbooks

- [orchestrated-run.md](../runbooks/orchestrated-run.md)
- [commit-author.md](../runbooks/commit-author.md)
