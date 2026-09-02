# `namespace/` — the names Innsegl claims, and the evidence it holds them

Innsegl's product is that you can check who produced an artifact without
trusting whoever handed it to you. A package published under Innsegl's own name
by someone else is that claim inverted, and the developer reaching for an
attribution tool is the developer least likely to expect it. Doc 04 records the
namespace as asset **A6** and typosquatting as abuse case **AB-09**; doc 08 §4
requires "genuine stubs linking to the repo, not empty shells". This directory
is that work, and RM-059 (#67) is the issue.

Nothing here is shipped Go code. It is the source of the artifacts that hold
the project's names on public registries, the gate that keeps them honest, and
the procedure for the parts only a human with the accounts can do.

## Layout

| Path | What it is |
|---|---|
| `canonical-names.txt` | **The** enumeration of the names. One place, machine-readable, so there is a single thing to defend. |
| `verify-namespace.sh` | Offline gate. Asserts the repository and both stubs agree with that enumeration. Proposed test-catalog ID **REL-003**. |
| `build.sh` | Builds both stub artifacts locally and publishes nothing. |
| `npm/` | Source of the npm distribution that holds `innsegl`. |
| `pypi/` | Source of the PyPI distribution that holds `innsegl`. |
| `PROCEDURE.md` | The human steps: registrar hardening, registry 2FA, and the exact publish commands. |
| `dist/` | Build output. Gitignored. |

Read `canonical-names.txt` for the names themselves. They are deliberately not
restated here: two copies of a list are two lists, and the second one is the one
that goes stale.

## Why the stub is not an empty shell

A reservation that installs and prints nothing is squatting performed by the
project instead of by an attacker — the name is denied to others and given to
no one. Both stubs therefore state, in metadata and on stdout, the source
repository, the home page, the Go module path, and the licence; and both say
what a package that is *not* the project's looks like, with the address to
report one. That last line is the only part of this that a developer who has
already installed the wrong thing can act on.

The Go module path is the load-bearing string. It is the one identifier in the
stub that leads to installable code, and it is rooted at the same domain whose
lapse `PROCEDURE.md` treats as an incident.

## State of the registrations

Verified 2026-09-02 by the commands shown. Re-run them; do not trust this table
on its own.

| Name | State | How it was checked |
|---|---|---|
| PyPI `innsegl` | held, 0.0.1 live, `Apache-2.0`, owner `kodymike` | `curl -sS https://pypi.org/pypi/innsegl/json` |
| npm `innsegl` | held, 0.0.1 live, `Apache-2.0`, maintainer `kodymike` | `npm view innsegl --json` |
| npm `@innsegl` scope | **operator-asserted, not independently verified** | npm org membership is not publicly readable; `npm org ls innsegl` (authenticated) is the proof |
| `innsegl.dev` | registered 2026-08-28, expires **2027-08-28**, registrar Cloudflare, `clientTransferProhibited` set, **DNSSEC delegation unsigned**, no apex A record yet | `curl -sS https://rdap.org/domain/innsegl.dev` |
| GitHub `Raymalian/innsegl` | public | `gh repo view Raymalian/innsegl --json visibility` |

Both live registrations execute and point at this repository:

```
$ npx -y innsegl@0.0.1
Innsegl — non-repudiable identity and attribution for AI agents.
This is a name-reservation stub; the implementation is in development.
Project: https://innsegl.dev
Source:  https://github.com/Raymalian/innsegl
```

`uv run --no-project --with innsegl==0.0.1 innsegl` prints the same.

A sweep of 18 near-miss spellings and prefixed forms on both registries on
2026-09-02 found **no** squatted variant: every one returned 404. The canonical
name is the only one taken, and the project takes it.

### The 0.0.1 artifacts were built from a source that is not in this repository

The live 0.0.1 packages were built from an untracked directory on one machine.
That was itself a small instance of A6: a published artifact carrying the
project's name, with no reviewable origin, recoverable only from one laptop.
This directory is the fix. The sources here are **0.0.2** — a superset of what
is live, adding the Go module path, the licence file, and the report-a-fake
line — and `PROCEDURE.md` is how they become the published artifacts.

## Build and check, locally

```
namespace/verify-namespace.sh   # offline, no build, CI-safe
namespace/build.sh              # builds into namespace/dist/, publishes nothing
```

`build.sh` runs the gate first, then stages each package with the repository's
own `LICENSE` and packs it. Both packages build reproducibly: two consecutive
runs on 2026-09-02 produced byte-identical tarballs, sdist and wheel. That
matters because it is what lets the operator prove, after publishing, that the
bytes the registry serves are the bytes in this repository — `npm view innsegl
dist.shasum` against `shasum -a 1` of the local tarball, and PyPI's reported
`sha256` against the local one.

Publishing is not automated and is not done from here. See `PROCEDURE.md`.

`verify-namespace.sh` is not yet wired into CI: `.github/` belongs to another
workstream. It needs no Go, no Docker and no network, so it belongs beside
`scripts/spdx-check.sh` in the lint job whenever that file is next touched. Until
then it is run by hand and by `build.sh`.
