#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Check a rebuilt ledger index against the sealed segments (PROPOSED SEG-007).
#
# WHAT THIS IS FOR
# ----------------
# Doc 05 s2: "losing Postgres loses *convenience* (the index), not *proof* --
# sealed segments + Rekor anchors allow rebuild verification." This is the
# rebuild verification. It answers one question and refuses to answer any
# other:
#
#   For every chain position a sealed segment covers, does the index I just
#   rebuilt hold the same event_hash the segment sealed?
#
# It is deliberately the *other* direction from trust. The segments are the
# authority; the index is the thing on trial. Nothing here writes to a segment,
# a bucket or a database, and there is no flag with which to make it do so.
#
# WHY IT IS SHELL AND NOT THE INNSEGL BINARY
# ------------------------------------------
# Same reason `innsegl verify` takes no ledger DSN (I5). A check that only our
# Go can perform is a check the reader has to take on trust. This re-derives
# doc 02 s4.6 from the document, in a third language, with tools already on
# the machine -- and its self-test pins the answer against the constants the Go
# sealer commits, so a disagreement between the two is loud (doc 04 s5.4).
#
# It is also the check an operator can run at 3am from a laptop with nothing
# installed, against objects pulled out of a bucket, with the database still
# down.
#
# WHAT IT DOES NOT DO
# -------------------
#   * It does not check the Rekor anchor. That is `innsegl verify`'s and the
#     anchorer's material, and it needs the log. See runbooks/index-rebuild.md
#     step 7 for the manual query.
#   * It does not check event *bodies*. A sealed segment carries event hashes
#     and nothing else (ADR-0006), so it can prove a restored body is the one
#     that was sealed only if you hash the body yourself and compare -- which
#     is what the position-by-position comparison here does, given an index
#     whose event_hash column was recomputed rather than trusted. See the
#     runbook's step 5.
#   * It does not verify the hash chain. The database's own INSERT trigger does
#     that, on every row, and a second implementation of the chain rule here
#     would be a second thing that can disagree with it.
#
# COST
# ----
# A segment of N events costs about 2N SHA-256 invocations. Fourteen events is
# instant; a hundred thousand is a coffee. That is the price of not depending
# on a toolchain.
#
# Portability: bash 3.2 (macOS). No mapfile, no arrays, no ${var,,}.

set -euo pipefail

# Exit status, following cmd/innsegl's contract so a scheduled job can treat
# this the way it treats `innsegl canary`.
readonly EXIT_OK=0
readonly EXIT_USAGE=2
readonly EXIT_FAILED=3        # a check ran and did not hold
readonly EXIT_INCONCLUSIVE=4  # nothing was checked, so nothing is proved

# The object format this gate reads (internal/segment/object.go).
readonly OBJECT_FORMAT_VERSION="1"

usage() {
  cat <<'USAGE'
verify-rebuilt-index.sh - check a rebuilt ledger index against sealed segments

Usage:
  runbooks/verify-rebuilt-index.sh --segments DIR [options]

Options:
  --segments DIR       directory of sealed segment objects, each file named by
                       its segment_id -- which is the object key in the bucket,
                       so `mc cp --recursive` produces this layout unchanged
  --index-hashes FILE  event_hash values from the rebuilt index, one per line,
                       in ascending chain_position order. Produce it with:
                         psql "$DSN" -Atc \
                           'SELECT event_hash FROM innsegl.events
                             ORDER BY chain_position' > index.hashes
                       Omit to check the segment objects alone.
  --index-first N      chain_position of the first line of --index-hashes
                       (default 1)
  --quiet              print nothing on success; failures are always reported
  -h, --help           this text

Exit status:
  0  every segment verified, and every position they cover matches the index
  2  the command line was not understood
  3  a check failed -- do not put this index into service
  4  the check could not run; nothing was proved, so it fails closed
USAGE
}

# ---------------------------------------------------------------------------
# Primitives.
# ---------------------------------------------------------------------------

if command -v sha256sum >/dev/null 2>&1; then
  sha256_stdin() { sha256sum | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_stdin() { shasum -a 256 | cut -d' ' -f1; }
elif command -v openssl >/dev/null 2>&1; then
  sha256_stdin() { openssl dgst -sha256 | awk '{print $NF}'; }
else
  printf 'verify-rebuilt-index: no sha256sum, shasum or openssl on PATH\n' >&2
  exit 4
fi

# hash_of_hex prints SHA-256 of the bytes the hex argument decodes to.
#
# The binary never passes through a command substitution -- a NUL byte would be
# stripped there, and every leaf hash starts with one. Only the printf FORMAT
# is substituted, and that is ASCII.
hash_of_hex() {
  # shellcheck disable=SC2059 # the format string IS the payload here: the
  # substitution produces \xNN escapes, and printf decoding them is the whole
  # mechanism. It is ASCII throughout, built from a hex string this function
  # only ever receives from a validated digest.
  printf "$(printf '%s' "$1" | sed 's/../\\x&/g')" | sha256_stdin
}

# doc 02 s4.6: leaf = SHA-256(0x00 || raw), node = SHA-256(0x01 || left || right).
merkle_leaf() { hash_of_hex "00$1"; }
merkle_node() { hash_of_hex "01$1$2"; }

is_digest() { printf '%s' "$1" | grep -Eq '^sha256:[0-9a-f]{64}$'; }

# ---------------------------------------------------------------------------
# Arguments.
# ---------------------------------------------------------------------------

segments_dir=""
index_file=""
index_first=1
quiet=0

while [ $# -gt 0 ]; do
  case "$1" in
    --segments)      segments_dir="${2-}"; shift 2 || true ;;
    --index-hashes)  index_file="${2-}";   shift 2 || true ;;
    --index-first)   index_first="${2-}";  shift 2 || true ;;
    --quiet)         quiet=1; shift ;;
    -h|--help)       usage; exit "${EXIT_OK}" ;;
    *)
      printf 'verify-rebuilt-index: unknown argument %s\n\n' "$1" >&2
      usage >&2
      exit "${EXIT_USAGE}"
      ;;
  esac
done

if [ -z "${segments_dir}" ]; then
  printf 'verify-rebuilt-index: --segments is required\n\n' >&2
  usage >&2
  exit "${EXIT_USAGE}"
fi
if ! printf '%s' "${index_first}" | grep -Eq '^[0-9]+$' || [ "${index_first}" -lt 1 ]; then
  printf 'verify-rebuilt-index: --index-first must be a chain position (>= 1)\n' >&2
  exit "${EXIT_USAGE}"
fi
if [ -n "${index_file}" ] && [ ! -r "${index_file}" ]; then
  printf 'verify-rebuilt-index: cannot read %s\n' "${index_file}" >&2
  exit "${EXIT_INCONCLUSIVE}"
fi
if [ ! -d "${segments_dir}" ]; then
  printf 'verify-rebuilt-index: %s is not a directory; nothing was checked\n' \
    "${segments_dir}" >&2
  exit "${EXIT_INCONCLUSIVE}"
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/innsegl-rebuilt-index.XXXXXX")"
trap 'rm -rf "${work}"' EXIT

failures=0
say()  { [ "${quiet}" -eq 1 ] || printf '%s\n' "$*"; }
bad()  { printf 'FAIL: %s\n' "$*" >&2; failures=$((failures + 1)); }

# ---------------------------------------------------------------------------
# One segment object.
#
# On success it appends "<first> <last> <count> <root> <leaffile> <name>" to
# ${work}/segments and returns 0. It is called in the current shell, never in a
# command substitution: `bad` increments a counter, and a counter incremented
# in a subshell is a failure that exits zero.
# ---------------------------------------------------------------------------
check_object() {
  file="$1"
  name="$(basename -- "${file}")"

  # 1. Content address. The id is SHA-256 of these exact bytes, so a segment
  #    that has been edited in the bucket cannot keep its name (SEG-006).
  actual="sha256:$(sha256_stdin <"${file}")"
  if ! is_digest "${name}"; then
    bad "${name}: the file name is not a sha256: digest, so it is not a segment_id;
      store each object under its content address, which is the bucket key"
    return 1
  fi
  if [ "${actual}" != "${name}" ]; then
    bad "${name}: the bytes are not the object this content address names --
      they hash to ${actual} (SEG-006, doc 02 s4.6)"
    return 1
  fi

  raw="$(cat -- "${file}")"

  # 2. Canonical form. Parse the five members ADR-0006 fixes, re-encode them by
  #    concatenation, and require the result to hash to the same address. That
  #    one comparison subsumes unknown members, duplicates, member order,
  #    whitespace and number spelling: for a content-addressed object there is
  #    exactly one byte string that means a given segment.
  leaves="$(printf '%s' "${raw}" |
    sed -n 's/^{"event_hashes":\[\(.*\)\],"first_position":.*$/\1/p')"
  first="$(printf '%s' "${raw}" |
    sed -n 's/^.*"first_position":\([0-9][0-9]*\),.*$/\1/p')"
  last="$(printf '%s' "${raw}" |
    sed -n 's/^.*"last_position":\([0-9][0-9]*\),.*$/\1/p')"
  version="$(printf '%s' "${raw}" |
    sed -n 's/^.*"segment_format_version":"\([^"]*\)".*$/\1/p')"
  root="$(printf '%s' "${raw}" |
    sed -n 's/^.*"segment_merkle_root":"\([^"]*\)".*$/\1/p')"

  if [ -z "${leaves}" ] || [ -z "${first}" ] || [ -z "${last}" ] ||
     [ -z "${version}" ] || [ -z "${root}" ]; then
    bad "${name}: these bytes are not the canonical encoding of a segment object
      (ADR-0006); a member is missing, misspelled or out of place"
    return 1
  fi

  reencoded='{"event_hashes":['"${leaves}"'],"first_position":'"${first}"',"last_position":'"${last}"',"segment_format_version":"'"${version}"'","segment_merkle_root":"'"${root}"'"}'
  if [ "sha256:$(printf '%s' "${reencoded}" | sha256_stdin)" != "${actual}" ]; then
    bad "${name}: these bytes are not the canonical encoding of what they say
      (ADR-0006) -- whitespace, member order or an extra member. A segment has
      exactly one encoding; anything else is corruption or a second preimage"
    return 1
  fi

  # 3. Format version. Refusing beats guessing: a later object format may hash
  #    a different way, and a confident wrong answer is the worst outcome here.
  if [ "${version}" != "${OBJECT_FORMAT_VERSION}" ]; then
    bad "${name}: segment_format_version is \"${version}\"; this gate reads \"${OBJECT_FORMAT_VERSION}\""
    return 1
  fi

  # 4. Leaves.
  #
  # printf '%s\n' rather than '%s': a final line with no newline is a line
  # `while read` silently drops, which would hash a tree one leaf short and
  # report a mismatch against the wrong construction. BSD sed does not add the
  # newline back, so it is added here, once, deliberately.
  leaffile="${work}/leaves.$(printf '%s' "${name}" | tr -c 'a-zA-Z0-9' '_')"
  printf '%s\n' "${leaves}" | tr ',' '\n' | tr -d '"' | grep . >"${leaffile}" || true
  count="$(grep -c . "${leaffile}" || true)"
  if [ "${count}" -eq 0 ]; then
    bad "${name}: the object carries no events"
    return 1
  fi
  while read -r h; do
    if ! is_digest "${h}"; then
      bad "${name}: ${h} is not a doc 02 s1 event_hash"
      return 1
    fi
  done <"${leaffile}"

  if [ "$((last - first + 1))" -ne "${count}" ]; then
    bad "${name}: positions ${first}..${last} span $((last - first + 1)) events, the object holds ${count}"
    return 1
  fi
  if [ "${first}" -lt 1 ]; then
    bad "${name}: first_position is ${first}; positions are 1-based (doc 02 s2)"
    return 1
  fi

  # 5. The root, re-derived. Content addressing cannot see a lie the sealer
  #    told about its own root, so the root is never read and believed.
  sed 's/^sha256://' "${leaffile}" | grep . >"${work}/level"
  : >"${work}/next"
  while read -r hex; do merkle_leaf "${hex}"; done <"${work}/level" >"${work}/next"
  mv -- "${work}/next" "${work}/level"
  while [ "$(grep -c . "${work}/level")" -gt 1 ]; do
    # Pairs are hashed; an odd node is PROMOTED, never duplicated (doc 02 s4.6).
    while read -r a; do
      if read -r b; then merkle_node "${a}" "${b}"; else printf '%s\n' "${a}"; fi
    done <"${work}/level" >"${work}/next"
    mv -- "${work}/next" "${work}/level"
  done
  derived="sha256:$(cat -- "${work}/level")"
  if [ "${derived}" != "${root}" ]; then
    bad "${name}: the recorded Merkle root is not the root of the events in the object
      recorded  ${root}
      derived   ${derived}   (doc 02 s4.6, re-derived here)"
    return 1
  fi

  printf '%s %s %s %s %s %s\n' \
    "${first}" "${last}" "${count}" "${root}" "${leaffile}" "${name}" \
    >>"${work}/segments"
  say "    ok  positions ${first}..${last} (${count} events)  ${name}"
  say "        root ${root}"
  return 0
}

# ---------------------------------------------------------------------------
# Every object in the directory.
# ---------------------------------------------------------------------------

say "==> sealed segments in ${segments_dir}"

: >"${work}/segments"
objects=0
for f in "${segments_dir}"/*; do
  [ -f "${f}" ] || continue
  objects=$((objects + 1))
  check_object "${f}" || true
done

if [ "${objects}" -eq 0 ]; then
  printf 'verify-rebuilt-index: %s holds no segment objects; nothing was checked\n' \
    "${segments_dir}" >&2
  exit "${EXIT_INCONCLUSIVE}"
fi

# An object that failed its own checks proves nothing about the index, so the
# coverage and index comparisons below run over the ones that held. If none
# held, the run is already a failure and there is nothing left to compare.
if [ ! -s "${work}/segments" ]; then
  printf 'rebuilt index vs sealed segments: FAIL (%d finding(s); no segment verified)\n' \
    "${failures}" >&2
  exit "${EXIT_FAILED}"
fi

# ---------------------------------------------------------------------------
# Coverage. Segments must tile a contiguous range: a hole is an object that is
# not here, and an object that is not here is a range nothing proves.
# ---------------------------------------------------------------------------
sort -n -k1,1 "${work}/segments" >"${work}/sorted"
covered_from=""
covered_to=""
prev_last=""
while read -r first last count root leaffile name; do
  if [ -z "${covered_from}" ]; then
    covered_from="${first}"
  elif [ "${first}" -ne "$((prev_last + 1))" ]; then
    if [ "${first}" -gt "$((prev_last + 1))" ]; then
      bad "no segment covers positions $((prev_last + 1))..$((first - 1));
      those events are in no sealed object here -- fetch the missing segment
      before trusting this range"
    else
      bad "segments overlap at position ${first}: $((prev_last)) is already sealed
      by an earlier object. Two objects claiming one position is drift, not a rebuild"
    fi
  fi
  prev_last="${last}"
  covered_to="${last}"
done <"${work}/sorted"

say ""
say "    ${objects} object(s), positions ${covered_from}..${covered_to} covered by a sealed segment"

# ---------------------------------------------------------------------------
# The index, if one was given.
# ---------------------------------------------------------------------------
if [ -n "${index_file}" ]; then
  index_lines="$(grep -c . "${index_file}" || true)"
  index_last="$((index_first + index_lines - 1))"
  say ""
  say "==> rebuilt index: ${index_lines} event(s), positions ${index_first}..${index_last}"

  if [ "${index_first}" -gt "${covered_from}" ]; then
    bad "the index starts at position ${index_first}, inside the sealed range that begins at ${covered_from};
      positions ${covered_from}..$((index_first - 1)) were sealed and are not in this index"
  fi

  while read -r first last count root leaffile name; do
    lo="$((first - index_first + 1))"
    hi="$((last - index_first + 1))"
    if [ "${lo}" -lt 1 ]; then
      continue  # already reported above
    fi
    sed -n "${lo},${hi}p" "${index_file}" | grep . >"${work}/slice" || true
    have="$(grep -c . "${work}/slice" || true)"
    if [ "${have}" -ne "${count}" ]; then
      bad "the index stops at position ${index_last}, inside the range ${first}..${last} that
      segment ${name} sealed: it holds ${have} of ${count} events. A partial restore is
      not a rebuilt index"
      continue
    fi
    off="$(awk 'NR==FNR{a[FNR]=$0;next} {if($0!=a[FNR]){print FNR; exit}}' \
      "${leaffile}" "${work}/slice")"
    if [ -n "${off}" ]; then
      p="$((first + off - 1))"
      bad "the index disagrees with a sealed segment at chain position ${p}
      sealed  $(sed -n "${off}p" "${leaffile}")
      index   $(sed -n "${off}p" "${work}/slice")
      segment ${name}
      This index is not a rebuild of that ledger. Do not put it into service (I4)"
    fi
  done <"${work}/sorted"

  # The tail past the last sealed position is normal -- those events have not
  # been sealed yet -- but it is unproved, and saying so is the difference
  # between a rebuild you can defend and one you merely performed.
  if [ "${index_last}" -gt "${covered_to}" ]; then
    say ""
    say "    positions $((covered_to + 1))..${index_last} are not covered by any segment here."
    say "    They are restored, not proved: nothing in this directory can confirm them."
    say "    Either they were never sealed (normal -- the tail of a live ledger), or"
    say "    their segments were not fetched. Check the ledger's segment_sealed events."
  fi
fi

say ""
if [ "${failures}" -gt 0 ]; then
  printf 'rebuilt index vs sealed segments: FAIL (%d finding(s))\n' "${failures}" >&2
  exit "${EXIT_FAILED}"
fi
say "rebuilt index vs sealed segments: OK"
exit "${EXIT_OK}"
