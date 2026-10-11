# Commit hook and signing path

## Purpose

An agent's `git commit` is attributed to the tool call that made it, and
signed by the core (ADR-0059). Three host commands do this: the harness hook
adds the tool call id, git's prepare-commit-msg hook adds the run's trailers,
and git's signing program asks the core to sign. A human's own commit is left
alone.

## Commands

```
innsegl hook pre-tool-use | post-tool-use | session
innsegl git-hook prepare-commit-msg <message file> [<source> [<sha>]]
innsegl git-hook post-commit
innsegl git-hook reference-transaction prepared|committed|aborted   (run by git; ref updates on stdin)
innsegl git-hook push-mirror <dir> branch|snapshot <core url> ...   (started by the hooks, detached)
innsegl sign --status-fd=<fd> -bsau <key>      (run by git as gpg.x509.program)
innsegl resign <range>                          (run by the agent)
innsegl link <repo dir>
innsegl link -remove <repo dir>
innsegl init [flags]
innsegl init -undo [-repo path]
make link DIR=<path to a git repository>
```

| Command | Run by | Does |
|---|---|---|
| `innsegl hook pre-tool-use` | the harness, before a Bash tool call | in a linked repository, for a `git commit`, prefixes the command with `INNSEGL_TOOL_USE_ID` and places the signing config inside the git invocation as `-c` options, using this same binary as `gpg.x509.program` |
| `innsegl hook post-tool-use` | the harness, after every tool call | in a linked repository, on a hosted client: snapshots the working tree as the tool call left it and sends it to the core's mirror (see below) |
| `innsegl hook session` | the harness, on session start, user prompt, subagent start, cwd change, session end | tells the gateway the session's working directory; at session end, also sends a linked repository's branch to the core's mirror |
| `innsegl git-hook prepare-commit-msg` | git | asks the core for the trailers `Agent-Identity`, `Agent-Run`, `Agent-Task` and writes them into the message |
| `innsegl git-hook post-commit` | git | after a commit innsegl signed for an agent, sends its branch to the core's mirror (see below); always exits 0 |
| `innsegl git-hook reference-transaction` | git, on every ref update | in an agent session, refuses a branch update that would add an unsigned commit (see below) |
| `innsegl git-hook push-mirror` | the two hooks above and `hook session` | the push itself, in a process of its own; not run by hand |
| `innsegl sign` | git | sends the commit payload to the core and returns the signature; `--verify` is git's verify mode |
| `innsegl resign` | the agent, as its own Bash command | signs the unsigned commits of a range on the current branch again, through `innsegl sign` (see below) |
| `innsegl link` | the operator | installs (or with `-remove`, restores) the repository's prepare-commit-msg, post-commit and reference-transaction hooks; touches nothing else. A repository linked before a hook was added gains it on its next use by an agent |
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

### Which repositories the hook acts on

`innsegl hook pre-tool-use` acts only in a repository linked to innsegl
(#575). The repository is the one the tool call's working directory is in.

| The working directory is | The hook |
|---|---|
| in a repository whose prepare-commit-msg hook `innsegl link` wrote | rewrites the commit and refuses one with signing off |
| in a repository with a usable `origin`, not linked yet | links it (as `innsegl hook session` does) and acts |
| in any other repository, such as a local one with no remote | prints nothing: no `-c` options, no refusal, nothing sent to the core |
| not in a repository, or not given | acts, since the command may commit anywhere |

A linked worktree, the harness's isolated one included, shares its
repository's hooks, so it counts as linked when the repository is.

### An agent never makes an unsigned commit

Signing fails closed. In a linked repository, an agent session cannot turn
it off (#584). Two layers do this. The operator's own commits are unchanged.

**The hook refuses the command.** `innsegl hook pre-tool-use` refuses a Bash
command that turns signing off, and says why:

- `--no-gpg-sign` on any git subcommand (`commit`, `rebase`, `merge`,
  `cherry-pick`, `revert`, `pull`, `am`)
- `-c commit.gpgsign=false` (or `0`, `no`, `off`), and any `-c gpg.*`
- `--config-env` for `commit.gpgsign` or a `gpg.*` key
- setting or exporting `GIT_CONFIG_COUNT` or `GIT_CONFIG_PARAMETERS`
- `git commit-tree` without `-S` or `--gpg-sign`
- `git config` that writes a `gpg.*` key, or sets `commit.gpgsign` off or unsets it

Reading a key (`git config --get`) and text inside a quoted message are not
refused. Only that one command is refused: the tool call and every other
command are recorded as usual.

**The ref backstop refuses the branch update.** The hook reads command text,
so a script file or plumbing passes it. `innsegl link` also installs a
`reference-transaction` hook. git runs it for every ref update, whatever made
it, and `--no-verify` does not skip it. In the `prepared` state, for each
update of a `refs/heads/*` branch, it lists the commits the new value would
add: reachable from it and from no branch, tag or remote-tracking ref. If any
has no `gpgsig` header, the whole update is refused and the branch stays
where it was. This covers commit, rebase, merge, cherry-pick, am,
`commit-tree` with `update-ref`, and scripts. A new branch at existing
commits, a reset, and a delete add no commit and pass.

It acts only in an agent session: a shell where the harness set
`CLAUDECODE`, or a command the hook gave `INNSEGL_TOOL_USE_ID`. The installed
script checks this itself, so the operator's own git never runs innsegl
here. In an agent session a missing `innsegl` binary refuses the update.
A hook the repository already had is moved aside and still runs, with the
same arguments and input.

**While signing is down**, both refusals say `signing is down since <time>`
and the reason, then `do not retry with signing off; keep working and commit
after repair`. The outage comes from the core's signing probe (#583), as the
client service last read it: the hook asks `GET /_client/status` at the
address `core.json` names, with a 2-second limit. No client service, no
reading yet, or a core that does not answer: the refusals carry no outage line.
Afterwards, commit again with plain `git commit`, or run `innsegl resign` for
unsigned commits already on a branch.

### What a hosted client sends to the core's mirror

On a client connected to a hosted core, a linked repository sends the core's
per-repository mirror (ADR-0065) two things besides a commit's objects:

| What | When | Ref on the mirror | The mirror's rule |
|---|---|---|---|
| the branch | after a commit innsegl signed (`git-hook post-commit`), and at session end | `refs/heads/<branch>` | created or fast-forwarded only; a rewrite or a delete is refused |
| a workspace snapshot | after every tool call (`hook post-tool-use`) | `refs/innsegl/snap/<installation>/<tool call id>` | written once; another installation's, a second write and a delete are refused |

- Only a linked repository sends anything, and only to a client service
  (`INNSEGL_CORE_URL` is plain `http://` on loopback). A commit with no tool
  call id, an unsigned one, or a detached `HEAD` sends nothing.
- Nothing waits for the core. The push runs as `innsegl git-hook push-mirror`,
  detached; a push that fails is carried by the next one. Its last output is
  in `<git common dir>/innsegl/last-push.log`.
- A snapshot is taken with a private index into a private object store
  (`<git common dir>/innsegl/snapshots/objects`, a cache), so the
  repository's own index, objects and refs are never written. Like `git add
  --all`, it leaves ignored files out.
- The core puts a snapshot's tree on the tool call's `workspace_tree_hash`
  only when its mirror holds that tree, waiting at most 10 s on the
  recording, never on the request. A snapshot that does not arrive leaves the
  tool call recorded without one. The ledger holds the hash only (E4).
- A branch push that is not a fast-forward of the mirror's branch (a
  rebase, an amend, a reset, or a branch moved on from another machine) is
  refused, and the mirror keeps what it had: it holds no rewrites. The
  client records the refusal once, in `~/.innsegl/client/mirror-behind.json`,
  and `innsegl status` shows a `mirror WARN` line naming the branch, the
  repository, since when and why, and what to do: merge rather than rebase or
  amend once a branch has reached the mirror, or carry on under a new branch
  name. The next push of that branch the mirror takes clears it. Signed
  commits are kept either way.
- The dashboard's per-step diffs read the snapshot trees from the mirror
  (`innsegl api -mirror-dir`). A root run's first step has no "before" there,
  so it shows no diff.

### Commit author per repository

```
innsegl author                                    list the setting, and the pair the core holds for this machine
innsegl author repo <path> operator|agent          one repository's mode
innsegl author operator 'Name <address>'           optional: a typed identity instead
```

Every repository is `agent` mode unless set otherwise: agent commits are
authored and committed as `Innsegl <agent@innsegl.invalid>`. In `operator`
mode they are authored as the repository's own `git config user.email`, which
must be a GitHub noreply address, with that address's login as the name;
`user.name` is never read. The agent stays in the trailers and the signature
(I6 allows the operator as author).

`innsegl author repo <path> operator` always reports the effective pair (the
typed identity if set, else the repository's) to the core (`POST
/_core/operator-author`, over the machine's certificate) and prints one
result line (ENF-014). The core pins it for that installation on first use,
and gate 3 of the sign path then admits it for that installation's commits,
beside the agent address and any pair in `INNSEGL_SIGN_AUTHOR_OPERATORS`. A
different pair later is refused (409) until
`docker exec innsegl-api innsegl accounts author-reset <installation>` on the
core. A repository with no noreply address falls back to the agent address,
with a note on stderr. A command that sets `GIT_AUTHOR_*` itself is left as
it is.

| Exit | Result line |
|---|---|
| 0 | `pinned on the core for this machine: …`, or `already pinned … (same pair)`; the repository is set |
| 2 | usage, or the path is not a git repository |
| 29 | `refused:` the core holds a different pair; prints the reset command with this machine's installation id; the repository stays in agent mode |
| 30 | `core unreachable:` with the error; or, said as such, the core is older than this client (`update the core`, ENF-016) or the client service is down or older (with the command that starts it); the repository stays in agent mode |
| 31 | `not pinned:` the pair is not a noreply address named by its own login. With no typed identity the repository stays in agent mode; with one, it is set, and signed only if `INNSEGL_SIGN_AUTHOR_OPERATORS` lists it |

`innsegl author` with no arguments ends with the pair the core holds for this
machine (`GET /_core/operator-author`, ENF-015): the pair, `none`, or
`unknown (core unreachable: …)`, or `unknown (the core is older than this client; update the core …)` for a core older than the GET (ENF-016). The local listing prints either way.

### A dead run's work (adoption)

When a commit hands over work a run left behind and that run has ended, the
commit says so: it gains `Agent-Adopted-Run: <dead run>` after the three
usual trailers, and the ledger gets a `run_adopted` event before the commit's
intent (ADR-0051, ADR-0079). Nobody asks for it.

- `prepare-commit-msg` sends the core the index's tree and `HEAD`. A hosted
  client pushes those objects to the core first. It sends nothing for
  `--amend`, `-c`/`-C`, merges and squashes.
- The core looks at the repository's runs that are not active and were last
  active in the past 7 days (at most 32, newest first). It proposes a run only
  when exactly one of them wrote every changed path through `Write` or `Edit`,
  and the bytes match what it left. The committing run must not have written
  any of those paths itself.
- Signing proves the named run again against the commit's own tree, and
  refuses the commit if the proof fails.
- A change that mixes two runs' work is committed as the live run's own.
  Commit each run's paths separately to adopt them.
- The proof reads the gateway's recorded bodies on the core's body volume
  (`-observe-body-dir`). With no body volume, nothing is adopted.

## Settings

| Variable | Read by | Meaning |
|---|---|---|
| `INNSEGL_CORE_URL` | `hook`, `git-hook`, `sign` | the client service, which forwards to the core (`internal/commitpath/commitpath.go:36`); the mirror pushes go only to a plain `http://` one |
| `INNSEGL_TOOL_USE_ID` | `git-hook`, `sign` | the tool call id the hook injected |
| `CLAUDECODE` | `git-hook reference-transaction` | set by the harness in an agent's shell; with it (or `INNSEGL_TOOL_USE_ID`) the ref backstop acts |
| `INNSEGL_BIN_PATH` | `make link` | the binary to run [`./innsegl`] |
| `INNSEGL_SIGN_AUTHOR_OPERATORS` | the core (`.env`) | pinned `Name <address>` pairs an agent commit may be authored as; empty by default |

Core routes: `/_gateway/commit-trailers` and `/_gateway/commit-sign`, on the
gateway's listener, scoped to the calling installation; and, on a hosted
core, `/_core/operator-author` (POST pins, GET reads the caller's own pin;
behind the client certificate guard, and never another installation's).

## Files, volumes, containers

- The repository's `prepare-commit-msg`, `post-commit` and `reference-transaction` hooks, written by `innsegl link`.
- `<git common dir>/innsegl/snapshots/objects` and `<git dir>/innsegl-snapshot-index`:
  the client's private snapshot store and index. A cache; the core's mirror is
  the evidence.
- `<git common dir>/innsegl/last-push.log`: the last mirror push's output.
- `~/.innsegl/client/mirror-behind.json` (0600 folder): branches the mirror
  refused as a rewrite, read by `innsegl status`.
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

### Signing commits left unsigned: `innsegl resign`

Signing is fail-closed, so a commit made while signing could not run is left
unsigned. `innsegl resign <range>` is the recovery (RM-328). The agent runs
it as its own command: the harness hook gives it the tool call id and the
agent's identity, as it does `git rebase`, and the core signs each commit
under that tool call. It rebases the range from the first unsigned commit
with this binary as git's signing program. Trees are unchanged; each
rewritten commit keeps its message and carries the trailers of the run that
signed it, since git runs prepare-commit-msg for every commit it replays. It
prints each old commit with its new one.

It refuses, with nothing changed: a range that does not end at the current
branch's tip, a detached HEAD, a dirty working tree, a merge in the range, a
run outside an agent's tool call, and any commit a remote-tracking branch or
tag already contains. Published history is never rewritten, and no flag
allows it. If the core refuses a signature, the rebase is aborted and the
branch is where it was.

`innsegl resign -h`:

```
usage: innsegl resign <range>

Sign the unsigned commits in <range> again, through the core, as the agent's
own command. <range> is <base>..HEAD, or <base> for the same. Every commit from
the first unsigned one to HEAD is rewritten and signed; earlier ones are kept.

Refused, with nothing changed: a range that does not end at the current
branch's tip, a dirty working tree, a commit any remote-tracking branch or tag
already contains (published history is never rewritten), a merge, and a run
outside an agent's tool call. If the core refuses a signature, the branch is
left where it was.
```

## Exit codes and error classes

| Command | Code | Meaning |
|---|---|---|
| `hook pre-tool-use` | 0 | always; anything it cannot handle is left alone and refused later by git |
| `hook session` | 2 | before a user turn only: the client service is unreachable, so the prompt is stopped |
| `git-hook`, `sign` | 1 | refused (no resolvable tool call id, or the core said no); git aborts the commit |
| `git-hook reference-transaction` | 1 | an agent session's branch update would add an unsigned commit, or its commits could not be checked; git refuses the whole update |
| `link` | 2 | usage or a refusal; the message says which |
| `resign` | 0 | re-signed, or nothing to sign |
| `resign` | 2 | usage |
| `resign` | 33 | refused: the range may not be re-signed; nothing changed |
| `resign` | 34 | a signature was refused or git failed; the branch is where it was |
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
- `cmd/innsegl/resign_test.go` (SIG-013, SIG-014), `internal/commitpath/commitpath_test.go` (SIG-013)
- `cmd/innsegl/mirrorpush_test.go`, `internal/commitpath/mirrorpush_test.go` and
  `internal/mirror/clientrefs_test.go` (SNAP-006, SNAP-007): the branch after a
  signed commit and at session end, and a tool call's snapshot, reach the
  mirror without holding anything up; an unlinked repository and an unsigned
  commit send nothing; the mirror's fast-forward and write-once rules
- `internal/gateway/mirrorsnapshot_test.go`, `cmd/innsegl/gatewaysnapshot_test.go`
  (SNAP-008): the core records a client's snapshot only for a tree its mirror holds
- `internal/client/mirrorbehind_test.go`, `internal/commitpath/mirrordiverged_test.go`,
  `cmd/innsegl/mirrorbehind_test.go` (SNAP-009): a refused rewrite is recorded once,
  shown by `innsegl status`, and cleared by the next push the mirror takes
- `internal/api/mirrorsnapshot_test.go`, `test/deploy/coremirror_test.go` (API-038):
  the run page's step diffs read the mirror
- `cmd/innsegl/hooklinked_test.go` (CMT-019, CMT-020): an unlinked repository is left alone;
  a linked one and its worktrees are rewritten as before
- `cmd/innsegl/hookoffswitch_test.go` (CMT-021, JRN-011): every way of turning signing off
  is refused; the refusal names a signing outage and stops only that command
- `cmd/innsegl/hookreftx_test.go` (CMT-022): the ref backstop refuses an agent session's
  unsigned commit from a script and from a rebase with signing off, and passes signed
  updates and the operator's own commits
- `cmd/innsegl/init*_test.go` (INIT-001 to INIT-010)
- `internal/commitpath/*_test.go` (CMT-006, TLS-001, TLS-002)
- `internal/mcp/signpayload_test.go`, `signpayload_crash_test.go` (CMT-007 to CMT-012)
- `internal/mcp/commitadopt_test.go`, `commitadopt_ledger_test.go`, `adopt_gateway_test.go`
  (ADP-008, ADP-009 and ADP-014 on the commit path; ADP-019, ADP-021),
  `internal/ledger/deadruns_test.go` (ADP-020, real Postgres),
  `internal/reconciler/adoption_commitpath_integration_test.go` (ADP-015 on a real stack),
  `cmd/innsegl/githookadopt_test.go`
- `internal/signing/*_test.go` (SIG-001 to SIG-012), `signpayload_test.go` (GH-006)
- `cmd/innsegl/hookauthor_test.go` (ENF-010), `authorcli_test.go` and `internal/client/authors_test.go` (ENF-011)
- `cmd/innsegl/hookauthorauto_test.go` (ENF-013): the repository's noreply address, never `user.name`
- `internal/client/operatorauthor_test.go` (ENF-017): the machine's report to the core
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
- [ADR-0065](../docs/adr/0065-a-per-repository-mirror-on-the-core-is-the-evidence-store.md) the mirror clients push to
- [ADR-0051](../docs/adr/0051-let-a-live-run-adopt-a-dead-runs-work-and-record-the-handover.md) adoption
- [ADR-0079](../docs/adr/0079-adoption-runs-on-the-commit-path.md) adoption runs on the commit path
- [ADR-0071](../docs/adr/0071-the-projects-mount-tools-are-deprecated-and-their-implementation-removed.md) mount tools removed

## Runbooks

- [orchestrated-run.md](../runbooks/orchestrated-run.md)
- [commit-author.md](../runbooks/commit-author.md)
