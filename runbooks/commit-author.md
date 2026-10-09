# Agent commits authored as the operator, per repository

Agent commits are authored as `Innsegl <agent@innsegl.invalid>` by default.
No GitHub account can hold that address, so no contributor ever appears (I6).

Some repositories cannot use it. A private repository whose deploy host builds
only commits authored by a member of its team never deploys agent work. For
those, I6 allows the other author it names: the human operator. Set the
repository to **operator** mode and its agent commits are authored as your
GitHub account. The agent is still named where innsegl records it: the
`Agent-Identity`, `Agent-Run` and `Agent-Task` trailers and the signature.

Keep public repositories in agent mode. Operator mode puts your GitHub account
on every agent commit in that repository.

"Machine" below is the operator's machine, enrolled with `innsegl connect`.
"Core" is the host running the stack.

## Before you start

The repository's `git config user.email` must be your GitHub noreply address
(`<id>+<login>@users.noreply.github.com`, from GitHub → Settings → Emails).
That is what the deploy host matches. The author name is that `<login>`.
`git config user.name` is never read and never published.

**Machine:** set it, if it is not already:

```sh
git -C <path-to-repository> config user.email '<id>+<login>@users.noreply.github.com'
```

## Turn it on

**Machine:**

```sh
innsegl author repo <path-to-repository> operator
```

That is the whole step. It reads the address, reports it to the core over
this machine's certificate, and prints one result line. The core pins the
first pair a machine reports; from then on it signs agent commits from this
machine authored as that pair, or as the agent address, and nothing else
(GH-008, GH-009, GH-010).

| Result line | Exit | What happened |
|---|---|---|
| `pinned on the core for this machine: <login> <address>` | 0 | pinned now; the repository is in operator mode |
| `already pinned on the core for this machine (same pair): …` | 0 | nothing changed on the core; the repository is in operator mode |
| `refused: the core holds a different pair for this machine … docker exec innsegl-api innsegl accounts author-reset <installation-id>` | 29 | the repository stays in agent mode. If the new pair is right, run the printed command on the core, then run this again |
| `core unreachable: <error>` | 30 | nothing changed; the repository stays in agent mode. Check `innsegl status`, then run this again |
| `not pinned: … not a GitHub noreply address …` | 31 | set the address (above), then run this again |

Run it again any time: a second run prints `already pinned` and changes
nothing.

## Check

**Machine:**

```sh
innsegl author
```

It lists each repository's mode, and the last line is the pair the core holds
for this machine: the pair, `none`, or `unknown (core unreachable: …)`.

The next agent commit in that repository shows your login and noreply address
as author and committer, and still carries the three trailers:

```sh
git -C <path-to-repository> log -1 --format='%an <%ae>%n%(trailers)'
```

## Change the pinned pair

Only on the core. A machine's git config is within an agent's reach; the pin
on the core is not, so a machine cannot change its own pin.

**Core:** run the command the `refused` line printed:

```sh
docker exec innsegl-api innsegl accounts author-reset <installation-id>
```

**Machine:** then run `innsegl author repo <path-to-repository> operator`
again.

To see every machine and its pin, **Core:**

```sh
docker exec innsegl-api innsegl accounts installations
```

The last column is each machine's pinned pair, `-` for none. `--account <id>`
narrows it to one account.

## Turn it off

**Machine:**

```sh
innsegl author repo <path-to-repository> agent
```

New agent commits there are authored as the agent address again. Commits
already made keep their author: history is not rewritten. The pin on the core
stays until `author-reset`; it admits nothing a machine does not use.

## Refusals at commit time

| Where | Message | What to do |
|---|---|---|
| the commit hook (stderr) | `this repository is in operator mode, but …; this commit is authored as the agent` | the repository lost its noreply `user.email`; the commit went through as the agent. Set the address back |
| `git commit` (signing) | `author … is not admitted (I6) … this installation has no operator author pinned` | the pin was reset. Run `innsegl author repo … operator` again |
| `git commit` (signing) | `author … is not admitted (I6) … it is not the operator author this installation pinned` | the repository's address differs from the pin. Fix `user.email`, or reset the pin on the core |

## A fixed pair instead (override)

A deployment can also admit fixed pairs in its own configuration. This is the
manual path, for an address that is not a GitHub noreply address, or a pair
shared by several machines. The name in such a pair is published on every
commit it authors.

**Core:** add the pair, then `make update`:

```sh
cd <repo> && echo "INNSEGL_SIGN_AUTHOR_OPERATORS='<name> <<address>>'" >> deploy/compose/.env && make update
```

**Machine:** use it instead of the repository's address:

```sh
innsegl author operator '<name> <<address>>'
```

`innsegl author repo … operator` then reports this pair instead. A noreply
pair named by its own login is pinned like any other. Any other pair prints
`not pinned` (exit 31) and sets the repository anyway: it is signed only
because the core's configuration lists it.

More than one pair is comma-separated. The core admits each address only with
its own name (GH-006).
