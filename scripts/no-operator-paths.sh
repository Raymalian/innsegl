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
# WHAT IT LOOKS FOR. An absolute path under a user home directory — `/Users/x/`
# or `/home/x/`. That is the shape a real checkout has and an anonymised example
# does not: `<repo>`, `<host-checkout>` and `<org>/<name>` all pass.
#
# WHAT IT DELIBERATELY ALLOWS.
#
#   * /home/innsegl — the container image's OWN user. Both Dockerfiles set
#     HOME and WORKDIR to it. A gate that called those violations would be
#     switched off within a week, and a gate nobody runs protects nothing.
#   * docs/ — the eight numbered specifications are local-only and never
#     pushed (CLAUDE.md). They are not shipped, so they carry no obligation.
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
    docs/*) continue ;;          # local-only, never pushed
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
