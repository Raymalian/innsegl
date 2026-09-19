#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPS-082, OPS-083 and OPS-084 — the readiness report names every service the
# deployment runs, keeps naming them as compose grows, and says so when one of
# them is unhealthy (RM-168, #272).
#
# WHY THIS EXISTS. `scripts/innsegl-start.sh` is the command an operator runs to
# ask whether a deployment is all right. Its service list was seven names typed
# into the script, and the backup was not among them: the backup sat `unhealthy`
# for eighteen hours with a full day of ledger standing above the last usable
# dump, and this report answered `ok` throughout. Eleven further services were
# unreported for the same reason and nobody had noticed those either. #267 fixed
# the backup's retry. This is the other half — the control that was supposed to
# make a fault visible and did not act.
#
# WHAT IS ASSERTED, and why none of it needs a deployment:
#
#   OPS-082  every long-running service the three compose files declare is in
#            the report, and every name in the report is declared by one of
#            them. The accounting is total: a declared container that is
#            neither reported nor excluded for a stated reason FAILS, which is
#            what catches a service that acquires its container_name through a
#            YAML anchor rather than a line of its own.
#   OPS-083  drift. The script is copied into a fixture tree over fixture
#            compose files, a service is planted, and the report has to grow a
#            row without the script being edited. The negative controls matter
#            as much: a `profiles:` service and a `restart: "no"` one-shot must
#            NOT appear, or the report cries wolf on every completed initialiser
#            and gets ignored — which is how it came to be ignored before.
#   OPS-084  an unhealthy backup is reported as unhealthy AND fails the command.
#            Driven through a fake `docker` on PATH inside the fixture tree: the
#            real deployment is not read, not stopped and not restarted, and the
#            unhealthy path is provable on a machine whose backup is healthy.
#
# THE LAST NEGATIVE CONTROL IS WHAT KEEPS THE REST HONEST: the same fake docker
# reporting every service healthy must exit 0. A report that failed on
# everything would pass every unhealthy case here and would teach an operator to
# stop reading it, which is the original defect wearing different clothes.

set -uo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
START="${ROOT}/scripts/innsegl-start.sh"
COMPOSE_FILES="${ROOT}/deploy/compose/spire.yml ${ROOT}/deploy/compose/sigstore.yml ${ROOT}/deploy/compose/innsegl.yml"

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; return 0; }

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

# ---------------------------------------------------------------------------
# A fixture tree: the REAL script, over whichever compose files a case plants,
# with its sibling gate stubbed and `docker` and `curl` faked on PATH. The
# script resolves both the compose files and rekor-tlog-health.sh relative to
# its own location, so a copy in a temp tree reads the temp tree and touches
# nothing that is running.
# ---------------------------------------------------------------------------
fixture() {                       # fixture <dir>
  local d="$1"
  mkdir -p "${d}/scripts" "${d}/deploy/compose" "${d}/bin"
  cp "${START}" "${d}/scripts/innsegl-start.sh"
  printf '#!/bin/sh\nexit 0\n' > "${d}/scripts/rekor-tlog-health.sh"
  chmod +x "${d}/scripts/rekor-tlog-health.sh"

  # `docker inspect <name> --format ...` answers from states.txt; a name with no
  # line there is absent, exactly as docker reports it.
  cat > "${d}/bin/docker" <<'SHIM'
#!/bin/sh
case "$1" in
  info) exit 0 ;;
  inspect)
    line=$(grep "^$2|" "${INNSEGL_FAKE_STATES}" 2>/dev/null) || exit 1
    printf '%s\n' "${line#*|}"
    ;;
  *) exit 0 ;;
esac
SHIM
  printf '#!/bin/sh\nprintf 200\n' > "${d}/bin/curl"
  chmod +x "${d}/bin/docker" "${d}/bin/curl"
}

# ---------------------------------------------------------------------------
echo "OPS-082 — the report names what the deployment declares, and only that"

reported="$("${START}" --services 2>/dev/null | cut -d'|' -f1 | sort)"

if [ -z "${reported}" ]; then
  bad "the report has a service list at all" "--services printed nothing"
else
  ok "the report has a service list at all"
fi

# The service named in #272. Asserted by name and not only by the accounting
# below, because this is the row whose absence cost eighteen hours.
if printf '%s\n' "${reported}" | grep -qx 'innsegl-backup'; then
  ok "the backup is one of the reported services"
else
  bad "the backup is one of the reported services" "innsegl-backup is not in --services"
fi

# Every service in the report is declared by a compose file. Catches a name
# that outlived the service it named.
stale=""
for name in ${reported}; do
  grep -qhE "^ +container_name: ${name}\$" ${COMPOSE_FILES} 2>/dev/null ||
    stale="${stale} ${name}"
done
if [ -n "${stale}" ]; then
  bad "every reported name is declared by a compose file" "not declared:${stale}"
else
  ok "every reported name is declared by a compose file"
fi

# The total accounting, computed HERE rather than by the script: walk every
# container_name the three files declare and require each to be reported, or
# excluded for one of the two stated reasons. Unaccounted is a failure, which
# is the case that catches a service the script's parse cannot see.
unaccounted=""
gated=0
oneshot=0
while IFS='|' read -r svc cname prof rest; do
  [ -n "${cname}" ] || continue
  if printf '%s\n' "${reported}" | grep -qx "${cname}"; then
    continue
  elif [ -n "${prof}" ]; then
    gated=$((gated + 1))
  elif [ "${rest}" = "no" ]; then
    oneshot=$((oneshot + 1))
  else
    unaccounted="${unaccounted} ${cname}(${svc})"
  fi
done <<EOT
$(awk '
  function flush() {
    if (name != "" && cname != "") printf "%s|%s|%s|%s\n", name, cname, prof, restart
    name = ""; cname = ""; prof = ""; restart = ""
  }
  FNR == 1 { flush(); insvc = 0 }
  /^[^[:space:]#]/ { flush(); insvc = ($0 ~ /^services:[[:space:]]*$/) ? 1 : 0; next }
  insvc && /^  [A-Za-z0-9_.-]+:[[:space:]]*(&[A-Za-z0-9_.-]+)?[[:space:]]*(#.*)?$/ {
    flush(); sub(":.*", "", $1); name = $1; next
  }
  insvc && name != "" && /^    container_name:/ { cname = $2; next }
  insvc && name != "" && /^    profiles:/       { prof = "gated"; next }
  insvc && name != "" && /^    restart:/        { r = $2; gsub(/"/, "", r); restart = r; next }
  END { flush() }
' ${COMPOSE_FILES})
EOT

if [ -n "${unaccounted}" ]; then
  bad "every declared container is reported or excluded for a stated reason" \
      "neither reported nor excluded:${unaccounted}"
else
  ok "every declared container is reported or excluded for a stated reason"
  printf '        %s reported, %s behind a profile, %s one-shot\n' \
    "$(printf '%s\n' "${reported}" | grep -c .)" "${gated}" "${oneshot}"
fi

# The same accounting again, computed WITHOUT parsing blocks at all: every
# `container_name:` value that appears anywhere in the three files, flat. This
# is the arm that does not share the script's blind spots — a service that took
# its container_name from a YAML anchor is invisible to both block parses above
# and visible here, as the anchor's own line.
declared_flat="$(grep -hE '^ +container_name: [A-Za-z0-9_.-]+$' ${COMPOSE_FILES} 2>/dev/null |
  awk '{ print $2 }' | sort -u)"
accounted=$((  $(printf '%s\n' "${reported}" | grep -c .) + gated + oneshot ))
declared_n="$(printf '%s\n' "${declared_flat}" | grep -c .)"
if [ "${declared_n}" = "${accounted}" ]; then
  ok "the flat count of declared containers matches the accounting"
else
  bad "the flat count of declared containers matches the accounting" \
      "${declared_n} container_name lines, ${accounted} accounted for"
fi
missing=""
for name in ${reported}; do
  printf '%s\n' "${declared_flat}" | grep -qx "${name}" || missing="${missing} ${name}"
done
if [ -n "${missing}" ]; then
  bad "every reported name appears as a container_name line" "not found:${missing}"
else
  ok "every reported name appears as a container_name line"
fi

# A row nobody can read is most of the way back to a row nobody sees.
undescribed="$("${START}" --services 2>/dev/null | grep -F '|(undescribed)' | cut -d'|' -f1)"
if [ -n "${undescribed}" ]; then
  bad "every reported service says what it is for" \
      "no purpose for: $(printf '%s' "${undescribed}" | tr '\n' ' ')"
else
  ok "every reported service says what it is for"
fi

# ---------------------------------------------------------------------------
echo
echo "OPS-083 — a service added to compose is reported without editing the script"

D="${TMP}/drift"
fixture "${D}"
cat > "${D}/deploy/compose/spire.yml" <<'EOT'
services:
  spire-server:
    container_name: innsegl-spire-server
    restart: unless-stopped
EOT
cat > "${D}/deploy/compose/sigstore.yml" <<'EOT'
services:
  sigstore-bootstrap:
    container_name: innsegl-sigstore-bootstrap
    restart: "no"
  fulcio:
    container_name: innsegl-sigstore-fulcio
    restart: unless-stopped
EOT
cat > "${D}/deploy/compose/innsegl.yml" <<'EOT'
services:
  postgres:
    container_name: innsegl-postgres
    restart: unless-stopped
  innsegl-canary:
    profiles: ["canary"]
    container_name: innsegl-canary
    restart: unless-stopped
  innsegl-something-new:
    container_name: innsegl-something-new
    restart: unless-stopped
networks:
  innsegl-ledger:
volumes:
  innsegl-not-a-service:
EOT

drift="$("${D}/scripts/innsegl-start.sh" --services 2>/dev/null | cut -d'|' -f1)"

if printf '%s\n' "${drift}" | grep -qx 'innsegl-something-new'; then
  ok "a service added to compose appears in the report"
else
  bad "a service added to compose appears in the report" \
      "got: $(printf '%s' "${drift}" | tr '\n' ' ')"
fi

if printf '%s\n' "${drift}" | grep -qx 'innsegl-canary'; then
  bad "a profile-gated service is not reported" "innsegl-canary was reported"
else
  ok "a profile-gated service is not reported"
fi

if printf '%s\n' "${drift}" | grep -qx 'innsegl-sigstore-bootstrap'; then
  bad "a completed one-shot is not reported" "innsegl-sigstore-bootstrap was reported"
else
  ok "a completed one-shot is not reported"
fi

if printf '%s\n' "${drift}" | grep -qE 'innsegl-ledger|innsegl-not-a-service'; then
  bad "networks and volumes are not mistaken for services" \
      "got: $(printf '%s' "${drift}" | tr '\n' ' ')"
else
  ok "networks and volumes are not mistaken for services"
fi

# Undescribed is a row, not a silence: the new service is reported even though
# nothing has told the script what it is for.
if "${D}/scripts/innsegl-start.sh" --services 2>/dev/null |
     grep -qx 'innsegl-something-new|(undescribed)'; then
  ok "an undescribed service still gets a row"
else
  bad "an undescribed service still gets a row"
fi

# An empty list must be a fault. A readiness report of nothing looks like a
# healthy one at a glance, and that is the whole defect.
E="${TMP}/empty"
fixture "${E}"
: > "${E}/deploy/compose/spire.yml"
: > "${E}/deploy/compose/sigstore.yml"
: > "${E}/deploy/compose/innsegl.yml"
out="$("${E}/scripts/innsegl-start.sh" --services 2>&1)"; rc=$?
if [ "${rc}" = 0 ]; then
  bad "an unreadable compose set is a fault, not an empty green report" \
      "exit 0 with: ${out}"
elif printf '%s' "${out}" | grep -q 'no services could be read'; then
  ok "an unreadable compose set is a fault, not an empty green report"
else
  bad "an unreadable compose set is a fault, not an empty green report" \
      "exit ${rc} but said: ${out}"
fi

# ---------------------------------------------------------------------------
echo
echo "OPS-084 — an unhealthy backup is reported, and fails the command"

S="${TMP}/status"
fixture "${S}"
for f in spire sigstore innsegl; do
  cp "${ROOT}/deploy/compose/${f}.yml" "${S}/deploy/compose/${f}.yml"
done

# Every service healthy, written from the list the script itself reports, so
# this stays true as the deployment grows.
healthy="${S}/healthy.txt"
"${START}" --services 2>/dev/null | cut -d'|' -f1 |
  sed 's/$/|running (healthy)/' > "${healthy}"

run_status() {                    # run_status <states-file>
  PATH="${S}/bin:${PATH}" INNSEGL_FAKE_STATES="$1" \
    "${S}/scripts/innsegl-start.sh" --status 2>&1
}

out="$(run_status "${healthy}")"; rc=$?
if [ "${rc}" = 0 ]; then
  ok "a wholly healthy deployment passes"
else
  bad "a wholly healthy deployment passes" "exit ${rc}"
fi
if printf '%s' "${out}" | grep -qE '^ +innsegl-backup +the ledger.s backup +ok$'; then
  ok "a healthy backup is reported ok"
else
  bad "a healthy backup is reported ok" \
      "row was: $(printf '%s' "${out}" | grep innsegl-backup || echo '<no row>')"
fi

# The measured incident, reproduced: everything else healthy, the backup not.
sick="${S}/unhealthy.txt"
sed 's/^innsegl-backup|.*/innsegl-backup|running (unhealthy)/' "${healthy}" > "${sick}"
out="$(run_status "${sick}")"; rc=$?
if [ "${rc}" != 0 ]; then
  ok "an unhealthy backup fails the readiness command"
else
  bad "an unhealthy backup fails the readiness command" "exit 0"
fi
if printf '%s' "${out}" | grep -qE '^ +innsegl-backup +.*unhealthy'; then
  ok "an unhealthy backup is named, with its state"
  printf '        %s\n' "$(printf '%s' "${out}" | grep innsegl-backup | sed 's/^ *//')"
else
  bad "an unhealthy backup is named, with its state" \
      "row was: $(printf '%s' "${out}" | grep innsegl-backup || echo '<no row>')"
fi

# Gone entirely is a third state and must not read as healthy.
absent="${S}/absent.txt"
grep -v '^innsegl-backup|' "${healthy}" > "${absent}"
out="$(run_status "${absent}")"; rc=$?
if [ "${rc}" != 0 ] && printf '%s' "${out}" | grep -qE '^ +innsegl-backup +.*ABSENT'; then
  ok "a backup container that is gone is reported ABSENT and fails"
else
  bad "a backup container that is gone is reported ABSENT and fails" \
      "exit ${rc}, row: $(printf '%s' "${out}" | grep innsegl-backup || echo '<no row>')"
fi

# ---------------------------------------------------------------------------
echo
printf 'innsegl-start-selftest: %s passed, %s failed\n' "${pass}" "${fail}"
[ "${fail}" = 0 ] || exit 1
