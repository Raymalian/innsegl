#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Self-test for scripts/test-suite.sh.
#
# The gate passes on this repository and is meant to, which is exactly when a
# gate can be worthless. So each way a wrapper reached a destructive package is
# reproduced in a fixture and the gate is required to go red — and the two cases
# that keep it honest, an ordinary package and a quiet host, are required to
# leave it green.
#
# THE CASE THAT MATTERS MOST IS THE LAST ONE. A gate that refused everything
# would pass every red case here and be indistinguishable from a working one
# until somebody tried to run the suite. #275 is not "stop the tests"; it is
# "stop reaching two of them while there is something to destroy".
#
# POSIX sh, for scripts/no-published-specs.sh's reason: the gate it tests runs
# from a Makefile, from CI and from a Go TestMain, and a selftest that needed a
# shell the gate does not need would be testing a different thing.

set -u

GATE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)/test-suite.sh"
REPO="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"

pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"
        [ -n "${2:-}" ] && printf '        %s\n' "$2"; return 0; }

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

# ---------------------------------------------------------------------------
# A HOST WITH NOTHING RUNNING. Both packages stay reachable, and the suite is
# the tree it always was.
# ---------------------------------------------------------------------------
printf '\nno deployment running\n'

out="$(INNSEGL_SUITE_STACK=absent "${GATE}" packages 2>/dev/null)"
[ "${out}" = "./..." ] && ok "the suite is \`./...\`, unchanged" \
  || bad "the suite is \`./...\`, unchanged" "got: ${out}"

INNSEGL_SUITE_STACK=absent "${GATE}" guard ./test/smoke >/dev/null 2>&1
[ $? -eq 0 ] && ok "test/smoke is not refused" \
  || bad "test/smoke is not refused" "this would be a ban, not a gate"

INNSEGL_SUITE_STACK=absent "${GATE}" guard ./test/failure >/dev/null 2>&1
[ $? -eq 0 ] && ok "test/failure is not refused" \
  || bad "test/failure is not refused" "this would be a ban, not a gate"

[ "$(INNSEGL_SUITE_STACK=absent "${GATE}" state)" = "absent" ] \
  && ok "state answers \`absent\`" \
  || bad "state answers \`absent\`" "got: $(INNSEGL_SUITE_STACK=absent "${GATE}" state)"

# ---------------------------------------------------------------------------
# A HOST WITH THE DEPLOYMENT UP. The three occurrences of #275, each as the
# command that produced it.
# ---------------------------------------------------------------------------
printf '\ndeployment up\n'

for pkg in test/smoke test/failure; do
  out="$(INNSEGL_SUITE_STACK=up "${GATE}" guard "./${pkg}" 2>&1)"; rc=$?
  if [ "${rc}" -eq 9 ] && printf '%s' "${out}" | grep -q "REFUSED"; then
    ok "${pkg} is refused, exit 9"
  else
    bad "${pkg} is refused, exit 9" "exit ${rc}: $(printf '%s' "${out}" | head -2)"
  fi

  # A REFUSAL THAT OFFERS NOTHING STRANDS THE WORK. scripts/hooks/subagent-identity.sh
  # carries this project's own measurement of that: a gate whose message named
  # the wrong command left nineteen finished files unsigned.
  if printf '%s' "${out}" | grep -q "TO RUN IT PROPERLY" &&
     printf '%s' "${out}" | grep -q "make innsegl-down" &&
     printf '%s' "${out}" | grep -q "INNSEGL_ALLOW_DESTRUCTIVE_TESTS=${pkg}"; then
    ok "  and it says how to run ${pkg} properly, and how to mean it"
  else
    bad "  and it says how to run ${pkg} properly, and how to mean it" \
        "a gate that blocks and offers nothing is worse than no gate"
  fi

  # And it names what is at risk rather than leaving the reader to remember.
  printf '%s' "${out}" | grep -q "What is running" \
    && ok "  and it names what is running" \
    || bad "  and it names what is running" "the refusal is unevidenced"
done

# THE WHOLE TREE AS ONE OPERAND — the shape every one of the five call sites had.
out="$(INNSEGL_SUITE_STACK=up "${GATE}" guard ./... 2>&1)"; rc=$?
if [ "${rc}" -eq 9 ] &&
   printf '%s' "${out}" | grep -q "test/smoke" &&
   printf '%s' "${out}" | grep -q "test/failure"; then
  ok "\`./...\` is refused, and names BOTH packages"
else
  bad "\`./...\` is refused, and names BOTH packages" "exit ${rc}"
fi

# THE CONTROL. An ordinary package must run with the deployment up, or this is a
# gate against testing rather than against two packages.
INNSEGL_SUITE_STACK=up "${GATE}" guard ./internal/ledger >/dev/null 2>&1
[ $? -eq 0 ] && ok "an ordinary package still runs with the deployment up" \
  || bad "an ordinary package still runs with the deployment up" \
         "the gate refuses the suite, not the two packages"

# THE NAMED OPT-OUT RELEASES EXACTLY WHAT IT NAMES. teardown-guard.sh measured
# the opposite on a real teardown: an opt-out listing three volumes released
# only one of them.
out="$(INNSEGL_SUITE_STACK=up INNSEGL_ALLOW_DESTRUCTIVE_TESTS=test/smoke \
  "${GATE}" guard ./test/smoke 2>&1)"; rc=$?
[ "${rc}" -eq 0 ] && ok "naming test/smoke releases test/smoke" \
  || bad "naming test/smoke releases test/smoke" "exit ${rc}: $(printf '%s' "${out}" | head -2)"

out="$(INNSEGL_SUITE_STACK=up INNSEGL_ALLOW_DESTRUCTIVE_TESTS=test/smoke \
  "${GATE}" guard ./test/failure 2>&1)"; rc=$?
[ "${rc}" -eq 9 ] && ok "and it does NOT release test/failure" \
  || bad "and it does NOT release test/failure" \
         "exit ${rc} — one keystroke would destroy the other package's target"

out="$(INNSEGL_SUITE_STACK=up INNSEGL_ALLOW_DESTRUCTIVE_TESTS='test/smoke,test/failure' \
  "${GATE}" guard ./... 2>&1)"; rc=$?
[ "${rc}" -eq 0 ] && ok "naming both releases both" \
  || bad "naming both releases both" "exit ${rc}"

# THE PACKAGE LIST. With the deployment up the suite is explicit and the two are
# gone — and everything else is still there, which is the half a `grep -v` gets
# wrong quietly.
listed="$(INNSEGL_SUITE_STACK=up "${GATE}" packages "${REPO}" 2>/dev/null)"
if printf '%s\n' "${listed}" | grep -qE '/test/smoke$|/test/failure$'; then
  bad "the explicit suite drops test/smoke and test/failure" "one of them is still in the list"
else
  ok "the explicit suite drops test/smoke and test/failure"
fi
if printf '%s\n' "${listed}" | grep -q '/internal/ledger$' &&
   printf '%s\n' "${listed}" | grep -q '/test/contract$'; then
  ok "  and keeps internal/ledger and test/contract"
else
  bad "  and keeps internal/ledger and test/contract" \
      "an exclusion that takes the suite with it is the worse failure"
fi

# Every destructive row explains itself, or the refusal prints a blank reason.
for pkg in $("${GATE}" destructive); do
  out="$(INNSEGL_SUITE_STACK=up "${GATE}" guard "${pkg}" 2>&1)"
  printf '%s' "${out}" | grep -q "^      [A-Za-z]" \
    && ok "${pkg} says what it does to a deployment" \
    || bad "${pkg} says what it does to a deployment" "the refusal has no reason in it"
done

# ---------------------------------------------------------------------------
# THE GATE ON WRAPPERS. The half that stops the sixth call site: documenting the
# rule did not work twice, so a wrapper that decides for itself fails a build.
# ---------------------------------------------------------------------------
printf '\nwrappers\n'

wrapper_fixture() {
  d="${TMP}/$1"; mkdir -p "${d}/scripts" "${d}/.github/workflows"
  printf '#!/bin/sh\n# a gate of its own\nexit 0\n' >"${d}/scripts/something.sh"
  printf 'all:\n\techo hi\n' >"${d}/Makefile"
  printf '%s' "${d}"
}

# A NEW WRAPPER THAT FORGETS — the exact line coverage-floors.sh carried.
d="$(wrapper_fixture forgot)"
printf '#!/bin/sh\ngo test ./... -race\n' >"${d}/scripts/new-gate.sh"
out="$("${GATE}" gate "${d}" 2>&1)"; rc=$?
if [ "${rc}" -eq 10 ] && printf '%s' "${out}" | grep -q "new-gate.sh"; then
  ok "a wrapper with a bare \`go test ./...\` is caught, and named"
else
  bad "a wrapper with a bare \`go test ./...\` is caught, and named" \
      "exit ${rc}: $(printf '%s' "${out}" | head -3)"
fi

# AND IT SAYS WHAT TO WRITE INSTEAD.
printf '%s' "${out}" | grep -q "scripts/test-suite.sh packages" \
  && ok "  and it says what to write instead" \
  || bad "  and it says what to write instead" "a gate that blocks and offers nothing"

# A MAKEFILE TARGET — the second and third occurrences were here.
d="$(wrapper_fixture makefile)"
printf 'test:\n\tgo test ./... -race\n' >"${d}/Makefile"
"${GATE}" gate "${d}" >/dev/null 2>&1
[ $? -eq 10 ] && ok "a Makefile target is caught too" \
  || bad "a Makefile target is caught too" "two of the five call sites were here"

# A CI WORKFLOW.
d="$(wrapper_fixture workflow)"
printf 'jobs:\n  test:\n    steps:\n      - run: go test ./... -race\n' \
  >"${d}/.github/workflows/ci.yml"
"${GATE}" gate "${d}" >/dev/null 2>&1
[ $? -eq 10 ] && ok "a CI workflow step is caught too" \
  || bad "a CI workflow step is caught too" "a runner is safe; the line gets copied"

# A COMMENT IS NOT A CALL SITE. If explaining the rule tripped the gate, nobody
# would explain the rule — and this file, and every header above, is explanation.
d="$(wrapper_fixture comment)"
printf '#!/bin/sh\n# this used to be `go test ./...` and that was the bug\nexit 0\n' \
  >"${d}/scripts/explained.sh"
"${GATE}" gate "${d}" >/dev/null 2>&1
[ $? -eq 0 ] && ok "a comment about \`go test ./...\` does NOT fire" \
  || bad "a comment about \`go test ./...\` does NOT fire" \
         "the gate would forbid its own documentation"

# A WRAPPER THAT ASKS. The shape every wrapper in this repository now has.
d="$(wrapper_fixture asks)"
cat >"${d}/scripts/good-gate.sh" <<'EOF'
#!/bin/sh
INNSEGL_SUITE_STACK="$(scripts/test-suite.sh state)"; export INNSEGL_SUITE_STACK
PKGS="$(scripts/test-suite.sh packages)" || exit 1
go test ${PKGS} -race
EOF
"${GATE}" gate "${d}" >/dev/null 2>&1
[ $? -eq 0 ] && ok "a wrapper that asks passes" \
  || bad "a wrapper that asks passes" "the gate would refuse the fix it demands"

# -coverpkg=./... SELECTS WHAT IS INSTRUMENTED, NOT WHAT RUNS.
d="$(wrapper_fixture coverpkg)"
printf '#!/bin/sh\ngo test ${PKGS} -coverpkg=./... -race\n' >"${d}/scripts/cov.sh"
"${GATE}" gate "${d}" >/dev/null 2>&1
[ $? -eq 0 ] && ok "\`-coverpkg=./...\` does NOT fire" \
  || bad "\`-coverpkg=./...\` does NOT fire" "it instruments packages; it does not run them"

# THE CONTROL THAT KEEPS ALL OF THE ABOVE HONEST: this repository passes.
out="$("${GATE}" gate "${REPO}" 2>&1)"; rc=$?
[ "${rc}" -eq 0 ] && ok "this repository has no wrapper that decides for itself" \
  || bad "this repository has no wrapper that decides for itself" \
         "$(printf '%s' "${out}" | head -6)"

printf '\n%d passed, %d failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]
