#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Operator-path gate for Innsegl.
#
# CLAUDE.md: nothing that ships may name any directory on the operator's
# machine. This enforces that as a hard failure rather than a convention.
#
# WHY IT EXISTS. On 2026-09-12 two tracked files named the operator's home
# directory and both had already reached main: one occurrence in a compose
# comment, four in captured gate output. Neither was careless — both sat inside
# MEASURED EVIDENCE, which is the trap CLAUDE.md names out loud: a comment that
# says "measured on this machine" is exactly where a real path gets written
# down. The rule had no gate, so it relied on remembering, and was forgotten
# twice. Every other rule in this repository that matters has a script.
#
# WHAT IT LOOKS FOR. An absolute path under a user home directory: a home root,
# then a user name, then a further segment. That is the shape a real checkout
# has and an anonymised example does not — `<repo>`, `<host-checkout>` and
# `<org>/<name>` all pass, because `<` and `>` fall outside the name class.
#
# This comment names no example path on purpose, and the first draft of it did
# — twice, and then once more inside the sentence explaining why it must not.
# The gate reads git-tracked files and its own file is one of them, so an
# illustrative path here fails the build. That is not a limitation to work
# around: a gate that cannot describe a violation without committing one is
# telling you the rule is real. PATTERN below is the precise statement anyway.
#
# WHAT IT DELIBERATELY ALLOWS.
#
#   * /home/innsegl — the container image's OWN user. Both Dockerfiles set
#     HOME and WORKDIR to it. A gate that called those violations would be
#     switched off within a week, and a gate nobody runs protects nothing.
#   * docs/, EXCEPT docs/adr/ — the eight numbered specifications are
#     local-only and never pushed (CLAUDE.md), so they carry no obligation.
#     ADRs are the exception and are excluded FROM the exception.
#
# WHY docs/adr/ IS CARVED BACK OUT, and it is the same class of mistake this
# gate exists to catch. The skip was written as `docs/*` with the comment
# "local-only, never pushed". That was TRUE of docs/ when it was written and
# stopped being true when ADRs started shipping: docs/adr/ is tracked, is in
# every clone, and CLAUDE.md names it — "That includes `docs/adr/`, which is
# the one docs directory that does ship." So the one docs directory that
# reaches the public repository was the one directory the gate skipped.
#
# Measured before the fix: a file carrying an operator home path inside
# docs/adr/ produced "none names an operator path". A false pass, in the gate
# whose whole job is to prevent one. Case 7 of the selftest holds it, and case
# 6 holds the other direction, because an exclusion with only one test beside
# it gets widened back by the next person who finds it inconvenient.
#
# The lesson is in the comment that was wrong rather than in the code: a
# comment stating a FACT goes stale silently, while one stating the REASON
# fails out loud when the reason stops holding. That is why the paragraph
# above gives the reason.
#
# Scope is git-tracked files only, for the same reason spdx-check.sh uses it:
# anything gitignored is not published.
#
# USAGE
#   scripts/no-operator-paths.sh
#
# EXIT
#   0  no shipped file names an operator path
#   1  at least one does; every occurrence is printed with its file and line

set -uo pipefail

cd "$(cd "$(dirname "$0")/.." && pwd)"

# The container's own user, which is not an operator path. Written as a pattern
# so `/home/innsegluser` is NOT covered by it.
ALLOWED='^/home/innsegl$'

# A user home directory followed by a name and a further segment. The trailing
# slash is what separates a real path from the bare words "/Users" or "/home",
# which carry nothing.
PATTERN='(/Users|/home)/[A-Za-z0-9._-]+/'

findings=""
nfindings=0
scanned=0

while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in
    # docs/adr/ SHIPS — it is tracked and in every clone, so it is scanned like
    # any other shipped file. The header says why this line is two cases and
    # not one.
    docs/adr/*) : ;;
    docs/*) continue ;;          # local-only, never pushed (CLAUDE.md)
  esac
  [ -f "$f" ] || continue
  # Skip anything that is not text: a binary match is noise, not a leak we can
  # read, and `grep -I` decides that the same way git does.
  scanned=$((scanned + 1))
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    # hit is "<line>:<text>". Drop the allowed container user before judging.
    text=${hit#*:}
    stripped=$(printf '%s' "$text" | sed -E 's#/home/innsegl([^A-Za-z0-9._-]|$)#\1#g')
    if printf '%s' "$stripped" | grep -qE "$PATTERN"; then
      findings="$findings  $f:$hit
"
      nfindings=$((nfindings + 1))
    fi
  done <<EOT
$(grep -InE "$PATTERN" -- "$f" 2>/dev/null || true)
EOT
done <<EOT
$(git ls-files 2>/dev/null || true)
EOT

: "$ALLOWED"  # documented above; the stripping above is what applies it

if [ "$nfindings" -eq 0 ]; then
  echo "no-operator-paths: $scanned shipped files, none names an operator path"
  exit 0
fi

echo "no-operator-paths: $nfindings occurrence(s) name a directory on the operator's machine" >&2
echo >&2
printf '%s' "$findings" >&2
echo >&2
echo "  CLAUDE.md: nothing that ships may name any directory on the operator's" >&2
echo "  machine. Anonymise it — <repo>, <host-checkout>, <org>/<name> — and keep" >&2
echo "  the measurement. Measured evidence is exactly where this gets written" >&2
echo "  down, which is why this gate exists." >&2
exit 1
