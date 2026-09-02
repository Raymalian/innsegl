#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for the rebuilt-index gate (runbooks/verify-rebuilt-index.sh).
#
# A gate nobody has watched fail is not a gate. This script builds a segment
# object from material the repository already commits, asserts the gate passes
# on it, then injects one defect at a time and asserts the gate's exit status.
#
# WHERE THE EXPECTED VALUES COME FROM
# -----------------------------------
# Not from the gate. Sealing golden fixtures 01-14 is pinned in Go, in
# internal/segment/fixtures_test.go, against a Python oracle written from
# doc 02 s4.6:
#
#   goldenMerkleRoot = sha256:1a3a08ee2021f778d13e8356740245621b1ea3ecc761a4e42714c42ce86dd14b
#   goldenSegmentID  = sha256:86c80ddc52dda7c1b4db79204e677005893e9a5f1cd0f5ff8042de45fd518dc2
#
# Those two constants are asserted below. The gate is a third, independent
# implementation of the same construction, in shell; if it disagrees with the
# Go sealer and the Python oracle, this test says so. Doc 04 s5.4 is the reason
# that matters: divergent verifiers are a divergence in what "verified" means.
#
# The fixtures are read read-only. Nothing here writes to internal/.
#
# Portability: bash 3.2 (macOS). No mapfile, no arrays, no ${var,,}.
#
# Usage: runbooks/verify-rebuilt-index-selftest.sh

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
GATE="${SCRIPT_DIR}/verify-rebuilt-index.sh"
REPO="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
FIX="${REPO}/internal/event/testdata/fixtures/v1"

readonly GOLDEN_ROOT="sha256:1a3a08ee2021f778d13e8356740245621b1ea3ecc761a4e42714c42ce86dd14b"
readonly GOLDEN_ID="sha256:86c80ddc52dda7c1b4db79204e677005893e9a5f1cd0f5ff8042de45fd518dc2"

if [ ! -x "${GATE}" ]; then
  printf 'FAIL: %s is missing or not executable\n' "${GATE}" >&2
  exit 1
fi
if [ ! -d "${FIX}" ]; then
  printf 'FAIL: golden fixtures not found at %s\n' "${FIX}" >&2
  exit 1
fi

workdir="$(mktemp -d "${TMPDIR:-/tmp}/innsegl-rebuild-selftest.XXXXXX")"
trap 'rm -rf "${workdir}"' EXIT

pass=0
fail=0

# expect <want-status> <name> -- <command...>
# Runs the command, compares its exit status, and prints its output on a
# surprise so a failure is diagnosable rather than merely red.
expect() {
  want="$1"; name="$2"; shift 3
  out="$("$@" 2>&1)" && got=0 || got=$?
  if [ "${got}" -eq "${want}" ]; then
    printf '  ok    %-46s exit %d\n' "${name}" "${got}"
    pass=$((pass + 1))
  else
    printf '  FAIL  %-46s exit %d, want %d\n' "${name}" "${got}" "${want}"
    printf '%s\n' "${out}" | sed 's/^/        | /'
    fail=$((fail + 1))
  fi
}

# expect_says <substring> <name> -- <command...>
# A failing gate has to name what failed. Asserting only the status would let
# the gate fail for the wrong reason and still look correct.
expect_says() {
  want="$1"; name="$2"; shift 3
  out="$("$@" 2>&1)" || true
  if printf '%s' "${out}" | grep -qF -- "${want}"; then
    printf '  ok    %-46s said %s\n' "${name}" "${want}"
    pass=$((pass + 1))
  else
    printf '  FAIL  %-46s did not say %s\n' "${name}" "${want}"
    printf '%s\n' "${out}" | sed 's/^/        | /'
    fail=$((fail + 1))
  fi
}

# ---------------------------------------------------------------------------
# Build the golden segment object out of the committed .hash files.
#
# The object's canonical form is fixed (ADR-0006): RFC 8785 over five members,
# whose names sort into exactly this order and whose values need no escaping.
# So it is built by concatenation, which is also how the gate re-encodes it.
# ---------------------------------------------------------------------------
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 | cut -d' ' -f1; }
else
  printf 'FAIL: neither sha256sum nor shasum is available\n' >&2
  exit 1
fi

hashes=""
for f in "${FIX}"/0[1-9]-*.hash "${FIX}"/1[0-4]-*.hash; do
  [ -f "${f}" ] || continue
  hashes="${hashes}$(cat -- "${f}")
"
done
n=0
leaves=""
for h in ${hashes}; do
  n=$((n + 1))
  if [ -z "${leaves}" ]; then leaves="\"${h}\""; else leaves="${leaves},\"${h}\""; fi
done
if [ "${n}" -ne 14 ]; then
  printf 'FAIL: found %d chain fixtures in %s, want 14\n' "${n}" "${FIX}" >&2
  exit 1
fi

object='{"event_hashes":['"${leaves}"'],"first_position":1,"last_position":14,"segment_format_version":"1","segment_merkle_root":"'"${GOLDEN_ROOT}"'"}'

good="${workdir}/good"
mkdir -p "${good}"
printf '%s' "${object}" >"${good}/${GOLDEN_ID}"

# The object's content address must be the name it is stored under, or the
# fixture is wrong and every assertion below is meaningless.
built="sha256:$(sha256 <"${good}/${GOLDEN_ID}")"
if [ "${built}" != "${GOLDEN_ID}" ]; then
  printf 'FAIL: built object hashes to %s, not the committed %s\n' "${built}" "${GOLDEN_ID}" >&2
  exit 1
fi

# The index side: the event_hash column of a rebuilt ledger, one per line in
# ascending chain_position order. This is what the runbook's psql query emits.
index="${workdir}/index.hashes"
: >"${index}"
for h in ${hashes}; do printf '%s\n' "${h}" >>"${index}"; done

printf '==> rebuilt-index gate self-test\n'
printf '    gate      %s\n' "${GATE}"
printf '    fixtures  %s (14 events, one sealed segment)\n' "${FIX}"
printf '\n-- the gate passes on good material --\n'

expect 0 "objects only" -- "${GATE}" --segments "${good}" --quiet
expect 0 "objects and a matching index" -- \
  "${GATE}" --segments "${good}" --index-hashes "${index}" --quiet
expect_says "${GOLDEN_ID}" "accepts the committed segment id" -- \
  "${GATE}" --segments "${good}"

# The derivation itself, pinned. The object below records a root that is a
# well-formed digest and is not the root of its leaves, so the gate must refuse
# it AND print what it derived -- and what it derived must be the constant the
# Go sealer and the Python oracle agree on. This is the assertion that would
# catch a shell Merkle that duplicated the odd node instead of promoting it:
# that construction also produces a plausible 32-byte root.
wrongroot="${workdir}/wrongroot"; mkdir -p "${wrongroot}"
printf '%s' '{"event_hashes":['"${leaves}"'],"first_position":1,"last_position":14,"segment_format_version":"1","segment_merkle_root":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}' \
  >"${workdir}/wrongroot.bytes"
cp -- "${workdir}/wrongroot.bytes" \
  "${wrongroot}/sha256:$(sha256 <"${workdir}/wrongroot.bytes")"
expect_says "derived   ${GOLDEN_ROOT}" "re-derives doc 02 s4.6 to the committed root" -- \
  "${GATE}" --segments "${wrongroot}"

printf '\n-- the gate bites --\n'

# 1. The object is stored under a name that is not its content address. This is
#    SEG-006 at the file level: the bytes are not the object the id names.
misnamed="${workdir}/misnamed"; mkdir -p "${misnamed}"
cp -- "${good}/${GOLDEN_ID}" \
  "${misnamed}/sha256:0000000000000000000000000000000000000000000000000000000000000000"
expect 3 "name is not the content address" -- "${GATE}" --segments "${misnamed}" --quiet
expect_says "content address" "says the address did not match" -- \
  "${GATE}" --segments "${misnamed}"

# 2. One leaf altered. The bytes still parse, the object is still canonical for
#    what it now says, and the root no longer follows from the leaves.
flipped="${workdir}/flipped"; mkdir -p "${flipped}"
printf '%s' "${object}" | sed 's/sha256:809304a5/sha256:809304a6/' >"${workdir}/flipped.bytes"
cp -- "${workdir}/flipped.bytes" \
  "${flipped}/sha256:$(sha256 <"${workdir}/flipped.bytes")"
expect 3 "a leaf was altered" -- "${GATE}" --segments "${flipped}" --quiet
expect_says "Merkle root" "says the root does not follow" -- "${GATE}" --segments "${flipped}"

# 3. Not the canonical encoding. One space, nothing else. DecodeObject refuses
#    this for a content-addressed object and so must the gate.
spaced="${workdir}/spaced"; mkdir -p "${spaced}"
printf '%s' "${object}" | sed 's/{"event_hashes"/{ "event_hashes"/' >"${workdir}/spaced.bytes"
cp -- "${workdir}/spaced.bytes" \
  "${spaced}/sha256:$(sha256 <"${workdir}/spaced.bytes")"
expect 3 "not the canonical encoding" -- "${GATE}" --segments "${spaced}" --quiet
expect_says "canonical" "says the encoding is not canonical" -- "${GATE}" --segments "${spaced}"

# 4. The declared range does not span the leaves it carries.
span="${workdir}/span"; mkdir -p "${span}"
printf '%s' '{"event_hashes":['"${leaves}"'],"first_position":1,"last_position":13,"segment_format_version":"1","segment_merkle_root":"'"${GOLDEN_ROOT}"'"}' \
  >"${workdir}/span.bytes"
cp -- "${workdir}/span.bytes" "${span}/sha256:$(sha256 <"${workdir}/span.bytes")"
expect 3 "range does not span the leaves" -- "${GATE}" --segments "${span}" --quiet

# 5. A format version this gate does not read. Refusing beats guessing: a later
#    object format may hash differently.
ver="${workdir}/ver"; mkdir -p "${ver}"
printf '%s' '{"event_hashes":['"${leaves}"'],"first_position":1,"last_position":14,"segment_format_version":"2","segment_merkle_root":"'"${GOLDEN_ROOT}"'"}' \
  >"${workdir}/ver.bytes"
cp -- "${workdir}/ver.bytes" "${ver}/sha256:$(sha256 <"${workdir}/ver.bytes")"
expect 3 "unknown segment_format_version" -- "${GATE}" --segments "${ver}" --quiet

# 6. The rebuilt index disagrees with the sealed segment at one position. This
#    is the whole point of the gate: the segment is the authority, the index is
#    the thing being checked, and the operator needs the position.
badindex="${workdir}/index-bad.hashes"
sed '7s/sha256:d5/sha256:d6/' "${index}" >"${badindex}"
expect 3 "index disagrees with a sealed leaf" -- \
  "${GATE}" --segments "${good}" --index-hashes "${badindex}" --quiet
expect_says "position 7" "names the position that disagrees" -- \
  "${GATE}" --segments "${good}" --index-hashes "${badindex}"

# 7. The index stops short of the sealed range. A rebuild that restored only
#    part of the chain must not read as complete.
short="${workdir}/index-short.hashes"
head -n 10 "${index}" >"${short}"
expect 3 "index stops inside the sealed range" -- \
  "${GATE}" --segments "${good}" --index-hashes "${short}" --quiet

# 8. Positions the segments do not cover. The tail of the chain is not sealed
#    yet; that is normal, and it must be reported rather than counted as proved.
tail="${workdir}/index-tail.hashes"
cp -- "${index}" "${tail}"
printf 'sha256:%s\n' \
  "1111111111111111111111111111111111111111111111111111111111111111" >>"${tail}"
expect 0 "an unsealed tail is not a failure" -- \
  "${GATE}" --segments "${good}" --index-hashes "${tail}" --quiet
expect_says "not covered by any segment" "reports the unproved tail" -- \
  "${GATE}" --segments "${good}" --index-hashes "${tail}"

# 9. A hole between segments. Two objects covering 1..14 and 20..33 leave
#    15..19 unaccounted for, which is a missing object, not a tail.
holed="${workdir}/holed"; mkdir -p "${holed}"
cp -- "${good}/${GOLDEN_ID}" "${holed}/${GOLDEN_ID}"
printf '%s' '{"event_hashes":['"${leaves}"'],"first_position":20,"last_position":33,"segment_format_version":"1","segment_merkle_root":"'"${GOLDEN_ROOT}"'"}' \
  >"${workdir}/hole.bytes"
cp -- "${workdir}/hole.bytes" "${holed}/sha256:$(sha256 <"${workdir}/hole.bytes")"
expect 3 "a hole between segments" -- "${GATE}" --segments "${holed}" --quiet
expect_says "15..19" "names the missing range" -- "${GATE}" --segments "${holed}"

# 10. Nothing to check is not a pass. Fail closed, the way `innsegl canary`
#     does when it cannot run.
empty="${workdir}/empty"; mkdir -p "${empty}"
expect 4 "no segments is inconclusive, not green" -- "${GATE}" --segments "${empty}" --quiet
expect 4 "an absent directory is inconclusive" -- "${GATE}" --segments "${workdir}/nope" --quiet
expect 2 "no --segments at all is a usage error" -- "${GATE}" --quiet

printf '\n%d passed, %d failed\n' "${pass}" "${fail}"
if [ "${fail}" -gt 0 ]; then
  printf '\nrebuilt-index gate self-test: FAIL\n'
  exit 1
fi
printf '\nrebuilt-index gate self-test: OK\n'
