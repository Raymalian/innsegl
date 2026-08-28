#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# SPDX header gate for Innsegl.
#
# Doc 08 §1: "Every source file gets the SPDX header." This enforces that as a
# hard failure rather than a convention, so a file cannot reach main without one.
#
# Scope is deliberately git-tracked files only: anything gitignored is not
# published and carries no licence obligation.

set -euo pipefail

IDENT="SPDX-License-Identifier: Apache-2.0"
# How many leading lines may precede the header (shebang, build tags, BOM).
HEAD_LINES=6

# Extensions that must carry a header. A read loop rather than mapfile, which is
# a bash 4+ builtin and absent from the bash 3.2 that ships with macOS.
FILES=""
while IFS= read -r line; do
  FILES="$FILES$line
"
done <<EOT
$(git ls-files '*.go' '*.sh' '*.ts' '*.tsx' '*.js' '*.mjs' 2>/dev/null || true)
EOT

count=0
missing=""
nmissing=0

if [ -z "$(printf '%s' "$FILES" | tr -d '[:space:]')" ]; then
  echo "spdx: no source files tracked yet — nothing to check"
  exit 0
fi

for f in $FILES; do
  count=$((count + 1))
  # Generated files are exempt; they carry their generator's own notice.
  if head -n "$HEAD_LINES" "$f" | grep -qE '^(//|#) Code generated .* DO NOT EDIT\.$'; then
    continue
  fi
  if ! head -n "$HEAD_LINES" "$f" | grep -qF "$IDENT"; then
    missing="$missing  $f
"
    nmissing=$((nmissing + 1))
  fi
done

printf '%s\n' "==> SPDX headers — doc 08 §1"
printf '    checked %d tracked source files, first %d lines each\n' "$count" "$HEAD_LINES"

if [ "$nmissing" -gt 0 ]; then
  printf '\n'
  printf 'FAIL: %d file(s) missing "%s":\n' "$nmissing" "$IDENT"
  printf '%s' "$missing"
  printf '\nAdd it as the first line (after any shebang) of each file listed.\n'
  exit 1
fi

printf '    all %d files carry the header\n' "$count"
printf '\nSPDX headers: OK\n'
