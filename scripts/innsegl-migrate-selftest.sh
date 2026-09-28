#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for scripts/innsegl-migrate.sh — RM-218 (#352).
#
# EVERY DOCKER RESOURCE THIS CREATES CARRIES A PREFIX UNIQUE TO THIS RUN
# (INNSEGL_MIGRATE_VOLUME_PREFIX=innsegl-migtest-$$-), and this file is the
# only caller anywhere that sets that variable. With it set,
# innsegl-migrate.sh's own volume_table() answers a table of two throwaway
# volume names under the prefix instead of the real eighteen — so every
# export, import and check below runs against volumes this run created
# itself, never against the real deployment's.
#
# This script REFUSES TO RUN AT ALL if the prefix comes out empty (case 0,
# below), before it creates or removes a single thing. The cleanup trap is a
# second, independent check of the same fact: it only ever removes a
# container or volume whose name it can see starts with this run's own
# prefix, re-derived from `docker ... ls`, not from a variable the rest of
# this script already touched.
#
# NOTHING HERE STARTS, STOPS, OR TOUCHES THE REAL STACK. No `docker compose`
# command appears below, and no container or volume this script did not
# create is ever named.
#
# Needs: bash, docker (a daemon that can pull or already holds
# alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce),
# tar, dd, jq, python3, and sha256sum or shasum.
#
# Usage: scripts/innsegl-migrate-selftest.sh

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
MIGRATE="${SCRIPT_DIR}/innsegl-migrate.sh"
IMG="alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"

if [ ! -x "${MIGRATE}" ]; then
  printf 'FAIL: %s is missing or not executable\n' "${MIGRATE}" >&2
  exit 1
fi
for t in docker tar dd jq python3; do
  command -v "${t}" >/dev/null 2>&1 || { printf 'FAIL: %s is required\n' "${t}" >&2; exit 1; }
done

# --- case 0: refuse to run at all if the prefix would be empty -------------
# This is not a case in the pass/fail table below: it runs before anything
# else exists to clean up, and a failure here must stop the file cold.
PREFIX="innsegl-migtest-$$-"
export INNSEGL_MIGRATE_VOLUME_PREFIX="${PREFIX}"
if [ -z "${INNSEGL_MIGRATE_VOLUME_PREFIX}" ]; then
  echo "FAIL: refusing to run with an empty INNSEGL_MIGRATE_VOLUME_PREFIX" >&2
  exit 1
fi
case "${PREFIX}" in
  innsegl-migtest-*) : ;;
  *) echo "FAIL: refusing to run — the prefix does not look like a test prefix" >&2; exit 1 ;;
esac

VOL_A="${PREFIX}ledger-data"
VOL_B="${PREFIX}trillian-db"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/innsegl-migrate-selftest.XXXXXX")"

# THE PIN FILE OVERRIDE IS GLOBAL AND MANDATORY, for every case below,
# without exception. innsegl-migrate.sh's default pin path resolves through
# scripts/repo-main-worktree.sh, which answers the repository's MAIN
# worktree regardless of which checkout this runs from — so a case that
# forgot to set INNSEGL_MIGRATE_PIN_FILE would read and, on import, WRITE
# the real deployment's transparency-log pin at
# deploy/compose/.rekor-tlog-id. Exporting it once here, before any case
# runs, means no case can forget.
printf '42' >"${WORK}/pin.txt"
export INNSEGL_MIGRATE_PIN_FILE="${WORK}/pin.txt"

cleanup() {
  status=$?
  # Independent of anything above: ask docker itself for what carries this
  # run's prefix, and remove only that.
  for c in $(docker ps -aq --filter "name=${PREFIX}" 2>/dev/null); do
    docker rm -f "${c}" >/dev/null 2>&1 || true
  done
  for v in $(docker volume ls -q --filter "name=${PREFIX}" 2>/dev/null); do
    case "${v}" in
      "${PREFIX}"*) docker volume rm -f "${v}" >/dev/null 2>&1 || true ;;
    esac
  done
  rm -rf "${WORK}"
  exit "${status}"
}
trap cleanup EXIT

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/        | /'; }

archive_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null
}

mkvol() { docker volume create "$1" >/dev/null; }

# mkvol_labeled VOLUME — a throwaway volume carrying the exact shape of
# labels a real trust volume does: dev.innsegl.trust-root is a full
# sentence with spaces AND a colon in it, which is what
# scripts/teardown-guard.sh reads to refuse deleting the volume.
mkvol_labeled() {
  docker volume create \
    --label "dev.innsegl.trust-root=the ledger: the hash chain and every event body" \
    --label "dev.innsegl.deployment=abc" \
    "$1" >/dev/null
}

labels_of() { docker volume inspect -f '{{json .Labels}}' "$1" 2>/dev/null; }

# write_fixture VOLUME — content with a non-default uid/gid and mode, and a
# symlink, so a round trip has something worth losing.
write_fixture() {
  docker run --rm -v "$1:/v" "${IMG}" sh -c '
    printf "hello\n" > /v/f.txt
    mkdir -p /v/sub
    printf "nested\n" > /v/sub/g.txt
    chown 1234:5678 /v/f.txt
    chmod 640 /v/f.txt
    ln -s f.txt /v/link.txt
  '
}

# fixture_signature VOLUME — one comparable blob describing ownership, mode,
# content and the symlink target, so two volumes compare with one diff.
fixture_signature() {
  docker run --rm -v "$1:/v:ro" "${IMG}" sh -c '
    stat -c "f.txt %u %g %a" /v/f.txt
    stat -c "sub/g.txt %u %g %a" /v/sub/g.txt
    cat /v/f.txt
    cat /v/sub/g.txt
    readlink /v/link.txt
  '
}

repack() {
  # repack SRC_DIR DEST_ARCHIVE — rebuild an outer archive from an extracted
  # (and possibly tampered) tree, the same way innsegl-migrate.sh assembled it.
  local src="$1" dest="$2" files="manifest.txt volumes"
  [ -f "${src}/manifest.sha256" ] && files="${files} manifest.sha256"
  [ -d "${src}/pin" ] && files="${files} pin"
  ( cd "${src}" && tar -cf "${dest}" ${files} )
  chmod 0600 "${dest}"
}

echo "RM-218 — innsegl-migrate.sh"
echo "  test prefix: ${PREFIX}"
echo

# --- case: missing prerequisite (docker) refuses, cleanly -----------------
TOOLBIN="${WORK}/toolbin-no-docker"
mkdir -p "${TOOLBIN}"
for t in bash sh tar awk sed grep cut mktemp dirname basename cat rm mkdir chmod mv cp id tr wc date head sha256sum shasum env; do
  p="$(command -v "${t}" 2>/dev/null)" || continue
  ln -sf "${p}" "${TOOLBIN}/${t}"
done
out="$(PATH="${TOOLBIN}" INNSEGL_MIGRATE_VOLUME_PREFIX="${PREFIX}" "${MIGRATE}" export "${WORK}/never.tar" 2>&1)"; rc=$?
if [ "${rc}" -ne 0 ] && [ ! -e "${WORK}/never.tar" ] && printf '%s' "${out}" | grep -qi 'docker'; then
  ok "a missing prerequisite (docker) is refused and writes nothing"
else
  bad "a missing prerequisite was not refused cleanly" "exit=${rc}
${out}"
fi

# --- case: round trip is byte-for-byte, including uid/gid and mode --------
# VOL_A is labelled the way a real trust volume is: teardown-guard.sh reads
# dev.innsegl.trust-root to refuse deleting it, and a label can only be set
# AT CREATION — Docker will not add one to a volume that already exists. So
# a moved volume that came back unlabelled would come back unprotected.
mkvol_labeled "${VOL_A}"; mkvol "${VOL_B}"
write_fixture "${VOL_A}"; write_fixture "${VOL_B}"
sig_a_before="$(fixture_signature "${VOL_A}")"
sig_b_before="$(fixture_signature "${VOL_B}")"
labels_a_before="$(labels_of "${VOL_A}")"
labels_b_before="$(labels_of "${VOL_B}")"

rt_archive="${WORK}/roundtrip.tar"
out="$("${MIGRATE}" export "${rt_archive}" 2>&1)"; rc=$?
if [ "${rc}" -eq 0 ] && [ -f "${rt_archive}" ]; then
  ok "export succeeds against throwaway volumes"
else
  bad "export failed against throwaway volumes" "exit=${rc}
${out}"
fi

# Remove the sources so import must recreate them from the archive alone.
docker volume rm "${VOL_A}" "${VOL_B}" >/dev/null 2>&1

out="$("${MIGRATE}" import "${rt_archive}" 2>&1)"; rc=$?
if [ "${rc}" -eq 0 ]; then
  ok "import succeeds into freshly created volumes"
else
  bad "import failed into freshly created volumes" "exit=${rc}
${out}"
fi

sig_a_after="$(fixture_signature "${VOL_A}" 2>/dev/null)"
sig_b_after="$(fixture_signature "${VOL_B}" 2>/dev/null)"
if [ "${sig_a_before}" = "${sig_a_after}" ] && [ "${sig_b_before}" = "${sig_b_after}" ]; then
  ok "the round trip reproduces every file byte-for-byte, including uid/gid and mode"
else
  bad "the round trip changed something" "before A: ${sig_a_before}
after  A: ${sig_a_after}
before B: ${sig_b_before}
after  B: ${sig_b_after}"
fi

labels_a_after="$(labels_of "${VOL_A}" 2>/dev/null)"
labels_b_after="$(labels_of "${VOL_B}" 2>/dev/null)"
if [ "${labels_a_before}" = "${labels_a_after}" ] && [ "${labels_b_before}" = "${labels_b_after}" ]; then
  ok "labels round-trip through export and import (fresh-create path), teardown-guard.sh's label included"
else
  bad "labels did not round-trip on the fresh-create path" "before A: ${labels_a_before}
after  A: ${labels_a_after}
before B: ${labels_b_before}
after  B: ${labels_b_after}"
fi

# --- case: the archive is written mode 0600 --------------------------------
mode="$(archive_mode "${rt_archive}")"
if [ "${mode}" = "600" ]; then
  ok "the archive is written mode 0600"
else
  bad "archive mode is ${mode}, want 600"
fi

# --- case: a running container is refused on export ------------------------
mkvol "${VOL_A}"; mkvol "${VOL_B}"
holder1="${PREFIX}holder-export"
docker run -d --name "${holder1}" -v "${VOL_A}:/data" "${IMG}" sleep 300 >/dev/null
out="$("${MIGRATE}" export "${WORK}/never-running.tar" 2>&1)"; rc=$?
if [ "${rc}" -ne 0 ] && [ ! -e "${WORK}/never-running.tar" ] && printf '%s' "${out}" | grep -qi 'running\|held by\|in use'; then
  ok "export refuses while a container is using one of its volumes"
else
  bad "export did not refuse against a running container" "exit=${rc}
${out}"
fi
docker rm -f "${holder1}" >/dev/null 2>&1

# --- case: a running container is refused on import -------------------------
holder2="${PREFIX}holder-import"
docker run -d --name "${holder2}" -v "${VOL_B}:/data" "${IMG}" sleep 300 >/dev/null
touch "${WORK}/dummy.tar"
out="$("${MIGRATE}" import "${WORK}/dummy.tar" 2>&1)"; rc=$?
if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -qi 'running\|held by\|in use'; then
  ok "import refuses while a container is using a target volume"
else
  bad "import did not refuse against a running container" "exit=${rc}
${out}"
fi
docker rm -f "${holder2}" >/dev/null 2>&1
docker volume rm "${VOL_A}" "${VOL_B}" >/dev/null 2>&1

# --- case: a corrupted archive is refused before any volume is written ----
# VOL_A is labelled here too: good_archive is reused below by the
# corrupted-LABELS-field case, which needs a real label to corrupt.
mkvol_labeled "${VOL_A}"; mkvol "${VOL_B}"
write_fixture "${VOL_A}"; write_fixture "${VOL_B}"
good_archive="${WORK}/good.tar"
"${MIGRATE}" export "${good_archive}" >/dev/null 2>&1
docker volume rm "${VOL_A}" "${VOL_B}" >/dev/null 2>&1

corrupt_dir="${WORK}/corrupt"
mkdir -p "${corrupt_dir}"
tar -xf "${good_archive}" -C "${corrupt_dir}"
# Flip a few bytes inside volume A's inner tar, well past its header, so the
# outer archive still extracts cleanly and only the inner checksum disagrees.
printf 'XXXX' | dd of="${corrupt_dir}/volumes/${VOL_A}.tar" bs=1 seek=300 conv=notrunc 2>/dev/null
bad_archive="${WORK}/bad.tar"
repack "${corrupt_dir}" "${bad_archive}"

out="$("${MIGRATE}" import "${bad_archive}" 2>&1)"; rc=$?
a_created=0; docker volume inspect "${VOL_A}" >/dev/null 2>&1 && a_created=1
b_created=0; docker volume inspect "${VOL_B}" >/dev/null 2>&1 && b_created=1
if [ "${rc}" -ne 0 ] && [ "${a_created}" -eq 0 ] && [ "${b_created}" -eq 0 ] \
   && printf '%s' "${out}" | grep -qi 'checksum\|verif\|corrupt'; then
  ok "a corrupted archive is refused before any volume is written"
else
  bad "a corrupted archive was not refused cleanly" "exit=${rc} vol_a_created=${a_created} vol_b_created=${b_created}
${out}"
fi

# --- case: a corrupted LABELS field (manifest.txt itself, tar untouched) --
# The label lives as text inside manifest.txt, not inside a volume's tar, so
# the per-volume tar checksum above cannot see this kind of damage. This
# does not merely garble the base64 -- a truncated/invalid base64 tail, or
# bytes that fail to parse as JSON, would be caught by simpler structural
# checks and would prove nothing about a MANIFEST checksum specifically. It
# decodes volume A's label field, changes dev.innsegl.deployment from "abc"
# to "xyz" -- still perfectly valid base64 of still perfectly valid JSON --
# and re-encodes it. Only a checksum over the whole manifest can catch this.
label_corrupt_dir="${WORK}/corrupt-labels"
mkdir -p "${label_corrupt_dir}"
tar -xf "${good_archive}" -C "${label_corrupt_dir}"
python3 - "${label_corrupt_dir}/manifest.txt" "${VOL_A}" <<'PY'
import base64, json, sys
path, name = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as f:
    lines = f.read().split("\n")
prefix = "volume\t" + name + "\t"
changed = False
for i, ln in enumerate(lines):
    if not ln.startswith(prefix):
        continue
    fields = ln.split("\t")
    labels = json.loads(base64.b64decode(fields[4]))
    assert labels["dev.innsegl.deployment"] == "abc", labels
    labels["dev.innsegl.deployment"] = "xyz"
    fields[4] = base64.b64encode(json.dumps(labels).encode()).decode()
    lines[i] = "\t".join(fields)
    changed = True
    break
assert changed, "volume A's manifest line was not found"
with open(path, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))
PY
label_bad_archive="${WORK}/bad-labels.tar"
repack "${label_corrupt_dir}" "${label_bad_archive}"

out="$("${MIGRATE}" import "${label_bad_archive}" 2>&1)"; rc=$?
la_created=0; docker volume inspect "${VOL_A}" >/dev/null 2>&1 && la_created=1
lb_created=0; docker volume inspect "${VOL_B}" >/dev/null 2>&1 && lb_created=1
if [ "${rc}" -ne 0 ] && [ "${la_created}" -eq 0 ] && [ "${lb_created}" -eq 0 ] \
   && printf '%s' "${out}" | grep -qi 'checksum\|verif\|corrupt\|manifest'; then
  ok "a corrupted labels field is refused before any volume is written"
else
  bad "a corrupted labels field was not refused cleanly" "exit=${rc} vol_a_created=${la_created} vol_b_created=${lb_created}
${out}"
fi

# --- case: a non-empty target is refused without --replace, accepted with it
mkvol_labeled "${VOL_A}"; mkvol "${VOL_B}"
write_fixture "${VOL_A}"; write_fixture "${VOL_B}"
labels_a_replace_before="$(labels_of "${VOL_A}")"
ne_archive="${WORK}/nonempty.tar"
"${MIGRATE}" export "${ne_archive}" >/dev/null 2>&1

out="$("${MIGRATE}" import "${ne_archive}" 2>&1)"; rc=$?
if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -qi 'replace\|not empty\|non-empty'; then
  ok "import refuses a non-empty target without --replace"
else
  bad "import did not refuse a non-empty target" "exit=${rc}
${out}"
fi

# Dirty the target with something the archive does NOT contain, so a
# --replace that merely overlaid files instead of replacing the volume would
# still leave evidence.
docker run --rm -v "${VOL_A}:/v" "${IMG}" sh -c 'printf junk > /v/should-not-survive.txt'

out="$("${MIGRATE}" import --replace "${ne_archive}" 2>&1)"; rc=$?
survived=1
docker run --rm -v "${VOL_A}:/v:ro" "${IMG}" sh -c '[ -f /v/should-not-survive.txt ]' >/dev/null 2>&1 && survived=0
if [ "${rc}" -eq 0 ] && [ "${survived}" -eq 1 ]; then
  ok "import --replace overwrites a non-empty target and leaves none of the old data"
else
  bad "import --replace did not cleanly replace the target" "exit=${rc} old_file_survived=$((1 - survived))
${out}"
fi

# A --replace removes the volume and creates it again, which is the path
# Docker's "cannot relabel an existing volume" rule bites hardest: the label
# has to be supplied on THIS recreate, from the manifest, not carried over
# from the volume this just deleted.
labels_a_replace_after="$(labels_of "${VOL_A}" 2>/dev/null)"
if [ "${labels_a_replace_before}" = "${labels_a_replace_after}" ]; then
  ok "labels round-trip through import --replace (remove-and-recreate path)"
else
  bad "labels did not round-trip on the --replace path" "before: ${labels_a_replace_before}
after:  ${labels_a_replace_after}"
fi
docker volume rm "${VOL_A}" "${VOL_B}" >/dev/null 2>&1

# --- case: check prints the running stack's numbers with no archive -------
out="$(INNSEGL_MIGRATE_LEDGER_COUNT_CMD='echo 7' "${MIGRATE}" check 2>&1)"; rc=$?
if [ "${rc}" -eq 0 ] && printf '%s' "${out}" | grep -q '7' && printf '%s' "${out}" | grep -q '42'; then
  ok "check with no archive prints the running stack's ledger count and tree id"
else
  bad "check with no archive did not print the expected numbers" "exit=${rc}
${out}"
fi

# --- case: check reports MATCH, then MISMATCH -------------------------------
mkvol "${VOL_A}"; mkvol "${VOL_B}"
write_fixture "${VOL_A}"; write_fixture "${VOL_B}"
check_archive="${WORK}/check.tar"
"${MIGRATE}" export --event-count 7 "${check_archive}" >/dev/null 2>&1
docker volume rm "${VOL_A}" "${VOL_B}" >/dev/null 2>&1

out="$(INNSEGL_MIGRATE_LEDGER_COUNT_CMD='echo 7' "${MIGRATE}" check "${check_archive}" 2>&1)"; rc=$?
# "MATCH" is also a substring of "MISMATCH", so require the word AND the
# absence of "MISMATCH" — a run that printed the wrong verdict must not read
# as this one passing.
if [ "${rc}" -eq 0 ] && printf '%s' "${out}" | grep -q 'MATCH' \
   && ! printf '%s' "${out}" | grep -q 'MISMATCH'; then
  ok "check reports MATCH when the running stack agrees with the manifest"
else
  bad "check did not report MATCH on agreement" "exit=${rc}
${out}"
fi

out="$(INNSEGL_MIGRATE_LEDGER_COUNT_CMD='echo 999' "${MIGRATE}" check "${check_archive}" 2>&1)"; rc=$?
if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -q 'MISMATCH'; then
  ok "check reports MISMATCH and exits non-zero when the count disagrees"
else
  bad "check did not report MISMATCH on disagreement" "exit=${rc}
${out}"
fi

# --- case: a STOPPED container holding a target volume is refused BEFORE
#     any write, including a target earlier in the manifest than the held
#     one — RM-219 --------------------------------------------------------
mkvol_labeled "${VOL_A}"; mkvol "${VOL_B}"
write_fixture "${VOL_A}"; write_fixture "${VOL_B}"
sig_a_stopped_before="$(fixture_signature "${VOL_A}")"
sig_b_stopped_before="$(fixture_signature "${VOL_B}")"
labels_a_stopped_before="$(labels_of "${VOL_A}")"
stopped_archive="${WORK}/stopped.tar"
"${MIGRATE}" export "${stopped_archive}" >/dev/null 2>&1

# VOL_B (later in volume_table than VOL_A) gets the stopped holder: this is
# what proves the check runs for every volume before PASS 2 writes any of
# them, not just the one a naive per-volume check happens to reach first.
holder_stopped="${PREFIX}holder-stopped"
docker run --name "${holder_stopped}" -v "${VOL_B}:/data" "${IMG}" true >/dev/null 2>&1
# "true" exits immediately, so by the time the assertion below runs the
# container is STOPPED, not running — but `docker ps -a` still lists it, and
# `docker volume rm` still refuses it exactly as it would a running one.

out="$("${MIGRATE}" import --replace "${stopped_archive}" 2>&1)"; rc=$?
sig_a_stopped_after="$(fixture_signature "${VOL_A}" 2>/dev/null)"
sig_b_stopped_after="$(fixture_signature "${VOL_B}" 2>/dev/null)"
labels_a_stopped_after="$(labels_of "${VOL_A}" 2>/dev/null)"
if [ "${rc}" -ne 0 ] \
   && printf '%s' "${out}" | grep -q "${holder_stopped}" \
   && [ "${sig_a_stopped_before}" = "${sig_a_stopped_after}" ] \
   && [ "${sig_b_stopped_before}" = "${sig_b_stopped_after}" ] \
   && [ "${labels_a_stopped_before}" = "${labels_a_stopped_after}" ]; then
  ok "import --replace refuses a STOPPED container holding a target volume, naming it, before any target volume is touched (RM-219)"
else
  bad "import did not refuse a stopped container's volume cleanly, or touched a target volume anyway" "exit=${rc}
before A: ${sig_a_stopped_before}
after  A: ${sig_a_stopped_after}
before B: ${sig_b_stopped_before}
after  B: ${sig_b_stopped_after}
${out}"
fi
docker rm -f "${holder_stopped}" >/dev/null 2>&1
docker volume rm "${VOL_A}" "${VOL_B}" >/dev/null 2>&1

# --- case: export still succeeds with a stopped (not running) container
#     holding a volume — RM-219 -------------------------------------------
mkvol_labeled "${VOL_A}"; mkvol "${VOL_B}"
write_fixture "${VOL_A}"; write_fixture "${VOL_B}"
holder_export_stopped="${PREFIX}holder-export-stopped"
docker run --name "${holder_export_stopped}" -v "${VOL_A}:/data" "${IMG}" true >/dev/null 2>&1
export_stopped_archive="${WORK}/export-stopped-ok.tar"
out="$("${MIGRATE}" export "${export_stopped_archive}" 2>&1)"; rc=$?
if [ "${rc}" -eq 0 ] && [ -f "${export_stopped_archive}" ]; then
  ok "export still succeeds with a stopped (not running) container holding a volume (RM-219)"
else
  bad "export refused a stopped container's volume, and should not have" "exit=${rc}
${out}"
fi
docker rm -f "${holder_export_stopped}" >/dev/null 2>&1
docker volume rm "${VOL_A}" "${VOL_B}" >/dev/null 2>&1

# --- case: a leftover helper container from an earlier, interrupted run is
#     refused by the preflight, naming it and the exact removal ------------
mkvol "${VOL_A}"; mkvol "${VOL_B}"
fake_helper="${PREFIX}fake-leftover-helper"
docker run -d --label "dev.innsegl.migrate-helper=1" --name "${fake_helper}" "${IMG}" sleep 300 >/dev/null
out="$("${MIGRATE}" export "${WORK}/never-helper.tar" 2>&1)"; rc=$?
if [ "${rc}" -ne 0 ] && [ ! -e "${WORK}/never-helper.tar" ] \
   && printf '%s' "${out}" | grep -q "${fake_helper}" \
   && printf '%s' "${out}" | grep -qi 'docker rm'; then
  ok "a leftover helper container is refused by the preflight, naming it and the exact removal"
else
  bad "a leftover helper container was not refused cleanly" "exit=${rc}
${out}"
fi
docker rm -f "${fake_helper}" >/dev/null 2>&1
docker volume rm "${VOL_A}" "${VOL_B}" >/dev/null 2>&1

# --- case: Ctrl-C mid-import removes the helper container it was using ----
mkvol "${VOL_A}"; mkvol "${VOL_B}"
write_fixture "${VOL_A}"; write_fixture "${VOL_B}"
int_archive="${WORK}/interrupt.tar"
"${MIGRATE}" export "${int_archive}" >/dev/null 2>&1
docker volume rm "${VOL_A}" "${VOL_B}" >/dev/null 2>&1

set -m
INNSEGL_MIGRATE_HELPER_SLEEP=6 "${MIGRATE}" import "${int_archive}" >"${WORK}/int.out" 2>"${WORK}/int.err" &
int_pid=$!
set +m
sleep 2
mid_flight="$(docker ps -q --filter 'label=dev.innsegl.migrate-helper=1' 2>/dev/null)"
kill -INT "-${int_pid}" 2>/dev/null || kill -INT "${int_pid}" 2>/dev/null
wait "${int_pid}" 2>/dev/null; int_rc=$?
leftover=""
for _ in 1 2 3 4 5 6; do
  leftover="$(docker ps -aq --filter 'label=dev.innsegl.migrate-helper=1' 2>/dev/null)"
  [ -z "${leftover}" ] && break
  sleep 1
done
if [ -n "${mid_flight}" ] && [ "${int_rc}" -ne 0 ] && [ -z "${leftover}" ]; then
  ok "Ctrl-C mid-import removes the helper container it was using"
else
  bad "Ctrl-C mid-import left a helper container behind, or did not interrupt cleanly" \
"mid_flight=[${mid_flight}] int_rc=${int_rc} leftover=[${leftover}]
$(cat "${WORK}/int.out" 2>/dev/null)
$(cat "${WORK}/int.err" 2>/dev/null)"
fi
[ -n "${leftover}" ] && docker rm -f ${leftover} >/dev/null 2>&1
docker volume rm "${VOL_A}" "${VOL_B}" >/dev/null 2>&1

# --- case: import prints a per-volume progress line to stderr as it goes --
mkvol "${VOL_A}"; mkvol "${VOL_B}"
write_fixture "${VOL_A}"; write_fixture "${VOL_B}"
prog_archive="${WORK}/progress.tar"
"${MIGRATE}" export "${prog_archive}" >/dev/null 2>&1
docker volume rm "${VOL_A}" "${VOL_B}" >/dev/null 2>&1
progress_err="$("${MIGRATE}" import "${prog_archive}" 2>&1 1>/dev/null)"
if printf '%s' "${progress_err}" | grep -q "${VOL_A}" && printf '%s' "${progress_err}" | grep -q "${VOL_B}"; then
  ok "import prints a per-volume progress line to stderr as it goes"
else
  bad "import did not print a per-volume progress line to stderr" "${progress_err}"
fi
docker volume rm "${VOL_A}" "${VOL_B}" >/dev/null 2>&1

printf '\n%d passed, %d failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]
