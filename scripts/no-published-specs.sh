#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# The eight numbered specifications are local only. This refuses to let them be
# tracked by the repository that publishes.
#
# WHY A GATE AND NOT THE .gitignore THAT ALREADY EXISTS. The root .gitignore
# holds `docs/*` and `!docs/adr/`, and it is the whole of the protection. It was
# measured on 2026-09-17 and it is one line with nothing behind it:
#
#   git add -f docs/07-...        stages a spec, gitignore does not apply
#   comment out `docs/*`, git add -A   stages all thirty-four
#
# Neither is exotic and neither is caught. `scripts/no-operator-paths.sh` passed
# with a spec staged, because it asks whether a tracked file NAMES an operator
# path — not whether a document that must never ship has become tracked.
#
# WHY IT IS A GATE AND NOT A HOOK. Hooks are not version controlled and do not
# travel: a subagent on another checkout, or a clone made tomorrow, has none. A
# gate runs in CI on whatever was actually pushed, which is the only place the
# question can be answered for everyone rather than for whoever installed
# something locally. The hook is worth having as well, for the fast answer, and
# `make install-hooks` puts it in — but the gate is the enforcement.
#
# WHAT IS ALLOWED, and why exactly one thing is. doc 03's ADRs ship on purpose:
# the root .gitignore un-ignores `docs/adr/`, CLAUDE.md says "docs/adr/, which
# is the one docs directory that does ship", and fifty-one of them are tracked
# today. Everything else under docs/ — the implementation prompt, the event
# schema, the threat model, the deployment topology, the frontend design, the
# test catalogue, the governance document, and the working notes in
# docs/decisions/ — is local.
#
# THE THREAT IS NOT MALICE. It is an agent that force-adds a directory to be
# helpful, or "fixes" a gitignore that seemed to be hiding files. A threat model
# in a public repository is a map of where to look, and it cannot be unpublished.
#
# USAGE
#   scripts/no-published-specs.sh [repo]

# POSIX sh, NOT bash, and that is load-bearing rather than tidiness. This
# repository sets core.hooksPath, so the pre-commit hook that calls this runs
# WHEREVER git runs in this repository — including inside the MCP's container,
# which is Alpine and has no bash. Measured the hard way on 2026-09-17: the
# first version was `#!/usr/bin/env bash`, and every signed commit began failing
# with `gitsign refused to sign` and `env: can't execute 'bash'`. A gate that
# breaks signing is worse than the hole it closes.
#
# `set -u` without `pipefail`: pipefail is not POSIX, and the pipelines below
# are greps whose failure is a normal "found nothing".
set -u

ROOT="${1:-$(cd -- "$(dirname -- "$0")/.." && pwd -P)}"

tracked="$(git -C "${ROOT}" ls-files -- 'docs/' 2>/dev/null |
  grep -v '^docs/adr/' || true)"

# STAGED BUT NOT YET COMMITTED COUNTS TOO. A gate that only read the committed
# tree would pass the moment before the commit that publishes, which is the
# moment someone is most likely to run it.
staged="$(git -C "${ROOT}" diff --cached --name-only -- 'docs/' 2>/dev/null |
  grep -v '^docs/adr/' || true)"

offenders="$(printf '%s\n%s\n' "${tracked}" "${staged}" | grep . | sort -u || true)"

if [ -n "${offenders}" ]; then
  count="$(printf '%s\n' "${offenders}" | grep -c .)"
  printf '\nno-published-specs: BREACHED — %s local-only document(s) are tracked or staged\n' "${count}" >&2
  printf '%s\n' "${offenders}" | sed 's/^/    /' >&2
  cat >&2 <<'MSG'

  These are the normative specifications and they are local only. They carry the
  threat model, the deployment topology, hosting decisions and the test
  catalogue — the material the public-issue rules exist to keep out of a public
  repository, and a threat model that ships is a map of where to look.

  If this was `git add -f`, unstage it:      git rm --cached <path>
  If the .gitignore was changed, restore it: docs/* and !docs/adr/

  If something here genuinely belongs in the open, move that content into an ADR
  under docs/adr/ — the one docs directory that ships — and let it go through
  review as an ADR rather than arriving as a spec nobody meant to publish.
MSG
  exit 1
fi

n_adr="$(git -C "${ROOT}" ls-files -- 'docs/adr/' 2>/dev/null | grep -c . || true)"
printf 'no-published-specs: OK (%s ADRs ship; no other docs/ file is tracked or staged)\n' "${n_adr}"
