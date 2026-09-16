#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Is the tree the deployment pinned still there? — OPS-034.
#
# WHY THIS EXISTS. Rekor mints a NEW Trillian tree whenever tlog_id is 0, so
# deploy/compose/.rekor-tlog-id remembers which tree this deployment's entries
# are in and every boot passes it back (see the Makefile's REKOR_TLOG_FILE).
# That pin is only as good as the tree it names.
#
# On 2026-09-16 Trillian's database was recreated. The pin still named a tree
# and the tree no longer existed, so Rekor came up, stayed up, reported healthy
# to docker — and answered HTTP 500 to every request. Nothing anywhere said
# why. An operator reading `{"code":500,"message":"unexpected server error"}`
# has been told that something is wrong and nothing about what.
#
# So this asks the one question that separates "Rekor is broken" from "Rekor is
# fine and is serving a tree this deployment has never written to": it requests
# THE PINNED TREE BY ID, and reports its absence in those words.
#
# doc 06 P2 and AB-08: "unavailable" is never "verified". This reports; it does
# not repair. Recovering from a lost tree is scripts/rekor-reindex.sh's
# territory and a decision for a person.
#
# USAGE
#   scripts/rekor-tlog-health.sh [--url URL] [--pin-file FILE] [--quiet]
#
#   --url        Rekor's base URL. Default $INNSEGL_REKOR_URL, else
#                http://127.0.0.1:$INNSEGL_REKOR_PORT (default port 23000).
#   --pin-file   the pin. Default deploy/compose/.rekor-tlog-id.
#
# EXIT
#   0  the pinned tree is present; its size is printed
#   2  the command line was not understood
#   4  Rekor could not be reached at all — inconclusive, not a verdict
#   6  THE PINNED TREE IS ABSENT: Rekor is answering and does not serve it
#
# Portability: the bash 3.2 that ships with macOS.

set -uo pipefail

readonly EXIT_OK=0
readonly EXIT_USAGE=2
readonly EXIT_UNREACHABLE=4
readonly EXIT_TREE_ABSENT=6

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

URL="${INNSEGL_REKOR_URL:-http://127.0.0.1:${INNSEGL_REKOR_PORT:-23000}}"
PIN_FILE="${REPO_ROOT}/deploy/compose/.rekor-tlog-id"
QUIET=""

usage() { sed -n '/^# USAGE/,/^# EXIT/p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --url)      URL="${2-}"; shift 2 ;;
    --pin-file) PIN_FILE="${2-}"; shift 2 ;;
    --quiet)    QUIET=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "rekor-tlog-health: unknown option: $1" >&2; usage >&2; exit "$EXIT_USAGE" ;;
  esac
done

say() { [ -n "$QUIET" ] || printf '  %s\n' "$*"; }

# A deployment that has never booted has no pin, and that is not a fault: the
# first boot passes 0, gets a tree and records it.
if [ ! -f "$PIN_FILE" ]; then
  say "transparency log  no tree pinned yet (first boot records one)"
  exit "$EXIT_OK"
fi
PIN="$(tr -d '[:space:]' < "$PIN_FILE")"
if [ -z "$PIN" ] || [ "$PIN" = "0" ]; then
  say "transparency log  no tree pinned yet (first boot records one)"
  exit "$EXIT_OK"
fi

# Ask for the PINNED tree by id. `/api/v1/log` with no treeID answers about
# whatever tree Rekor is serving now, which is exactly the question that hid
# the fault: a fresh empty tree answers 200 while every earlier entry is
# stranded in a tree nothing can reach.
body="$(curl -sS --max-time 10 "${URL}/api/v1/log?treeID=${PIN}" 2>/dev/null)"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        "${URL}/api/v1/log?treeID=${PIN}" 2>/dev/null)"

if [ -z "$code" ] || [ "$code" = "000" ]; then
  {
    echo "transparency log  UNREACHABLE at ${URL}"
    echo "                  Nothing was proved either way (doc 06 P2, AB-08)."
  } >&2
  exit "$EXIT_UNREACHABLE"
fi

if [ "$code" != "200" ]; then
  {
    echo
    echo "transparency log  the pinned tree is absent."
    echo
    echo "  ${PIN_FILE##*/} pins tree ${PIN}, and Rekor at ${URL} does not serve it"
    echo "  (HTTP ${code})."
    echo
    echo "  This is what a recreated Trillian database looks like from the outside:"
    echo "  Rekor comes up, stays up, and answers 500 to every request because the"
    echo "  tree it was told to serve no longer exists. Every entry written to that"
    echo "  tree is unreachable, and every commit anchored in it cannot be shown to"
    echo "  be anchored anywhere."
    echo
    echo "  This says what is wrong. It does not repair it: see"
    echo "  scripts/rekor-reindex.sh, and doc 05 §2 on why the four volumes that"
    echo "  hold the trust root are declared outside the compose project."
    echo
  } >&2
  exit "$EXIT_TREE_ABSENT"
fi

size="$(printf '%s' "$body" | sed -n 's/.*"treeSize":\([0-9]*\).*/\1/p')"
served="$(printf '%s' "$body" | sed -n 's/.*"treeID":"\([0-9]*\)".*/\1/p')"

if [ -n "$served" ] && [ "$served" != "$PIN" ]; then
  {
    echo
    echo "transparency log  the pinned tree is absent."
    echo
    echo "  ${PIN_FILE##*/} pins tree ${PIN} and Rekor answered about tree ${served}."
    echo "  Entries written under the pinned tree are not in the one being served."
    echo
  } >&2
  exit "$EXIT_TREE_ABSENT"
fi

if [ "${size:-0}" = "1" ]; then
  say "transparency log  tree ${PIN} present, 1 entry"
else
  say "transparency log  tree ${PIN} present, ${size:-?} entries"
fi
exit "$EXIT_OK"
