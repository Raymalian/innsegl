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
"Core" is the host running the stack; `innsegl` runs there inside the
`innsegl-api` container, which holds the accounts credential.

## How the identity is found

Nothing is typed. In operator mode innsegl reads one value: the repository's
`git config user.email`. It must be your GitHub noreply address
(`<id>+<login>@users.noreply.github.com`, from GitHub → Settings → Emails),
which is what the deploy host matches. The author name is that `<login>`.
`git config user.name` is never read and never published.

So the author of an agent commit there is `<login> <<id>+<login>@users.noreply.github.com>`.

**Machine:** check the address the repository uses:

```sh
git -C <path-to-repository> config user.email
```

**Machine:** set it, if it is not the noreply address:

```sh
git -C <path-to-repository> config user.email '<id>+<login>@users.noreply.github.com'
```

## Turn it on

**Machine:**

```sh
innsegl author repo <path-to-repository> operator
```

It reads the address, and reports it to the core over this machine's
certificate. On the first report the core **pins** it for this machine: from
then on the core signs agent commits from this machine authored as that pair,
or as the agent address, and nothing else (GH-008, GH-009, GH-010). The
repository is set to operator mode only once the core holds the pin.

**Machine:** see the setting:

```sh
innsegl author
```

**Machine:** check the next agent commit there. It shows your login and
noreply address as author and committer, and still carries the three
trailers:

```sh
git -C <path-to-repository> log -1 --format='%an <%ae>%n%(trailers)'
```

## See what the core pinned

**Core:** your account's id (first column):

```sh
docker exec innsegl-api innsegl accounts list
```

**Core:** its machines. The last column is each machine's pinned operator
author, `-` for none:

```sh
docker exec innsegl-api innsegl accounts installations --account <account-id>
```

## Change the pinned address

The core keeps the first address a machine reported. A different one later is
refused: the machine's git config is within an agent's reach, the pin on the
core is not. To pin another:

**Core:**

```sh
docker exec innsegl-api innsegl accounts author-reset <installation-id>
```

**Machine:** then report again:

```sh
innsegl author repo <path-to-repository> operator
```

## Turn it off

**Machine:**

```sh
innsegl author repo <path-to-repository> agent
```

New agent commits there are authored as the agent address again. Commits
already made keep their author: history is not rewritten. The pin on the core
stays until `author-reset`; it admits nothing a machine does not use.

## What a refusal means

| Where | Message | What to do |
|---|---|---|
| `innsegl author repo … operator` | `this repository's git user.email is not a GitHub noreply address` | set it (above), then run the command again |
| `innsegl author repo … operator` | `the core did not pin … already pinned to a different identity … innsegl accounts author-reset <id>` | the core holds another address for this machine. If the new one is right, reset on the core and run again |
| `innsegl author repo … operator` | `the core did not pin … ` followed by a connection error | the core was not reached; nothing changed. Check `innsegl status`, then run again |
| the commit hook (stderr) | `this repository is in operator mode, but …; this commit is authored as the agent` | the repository lost its noreply `user.email`; the commit went through as the agent. Set the address back |
| `git commit` (signing) | `author … is not admitted (I6) … this installation has no operator author pinned` | operator mode was set before this feature, or the pin was reset. Run `innsegl author repo … operator` again |
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

More than one pair is comma-separated. The core admits each address only with
its own name (GH-006).
