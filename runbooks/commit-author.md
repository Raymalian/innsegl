# Agent commits authored as the operator, per repository

Agent commits are authored as `Innsegl <agent@innsegl.invalid>` by default.
No GitHub account can hold that address, so no contributor ever appears (I6).

Some repositories cannot use it. A private repository whose deploy host builds
only commits authored by a member of its team never deploys agent work. For
those, I6 allows the other author it names: the human operator. Set the
repository to **operator** mode and its agent commits are authored as you. The
agent is still named where innsegl records it: the `Agent-Identity`,
`Agent-Run` and `Agent-Task` trailers and the signature.

Keep public repositories in agent mode. Operator mode puts your GitHub account
on every agent commit in that repository.

## 1. The core admits your identity

On the core, add one line to `<repo>/deploy/compose/.env`, with your GitHub
noreply address (GitHub → Settings → Emails):

```sh
INNSEGL_SIGN_AUTHOR_OPERATORS='<Your Name> <<id>+<login>@users.noreply.github.com>'
```

More than one pair is comma-separated. Then `make update`.

The core admits that address only with that display name (GH-006). Without the
line, a commit in operator mode is refused, and nothing is signed.

## 2. Your machine uses it for one repository

On the operator's machine, once:

```sh
innsegl author operator '<Your Name> <<id>+<login>@users.noreply.github.com>'
```

Then per repository:

```sh
innsegl author repo <path-to-repository> operator
```

`innsegl author` lists the setting. The identity must match the core's pair
exactly, name included.

**Check:** the next agent commit in that repository shows you as author and
committer, and still carries the three trailers:

```sh
git -C <path-to-repository> log -1 --format='%an <%ae>%n%(trailers)'
```

## Rollback

```sh
innsegl author repo <path-to-repository> agent
```

New agent commits there are authored as the agent address again. Commits
already made keep their author: history is not rewritten.
