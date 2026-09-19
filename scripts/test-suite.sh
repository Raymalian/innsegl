#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# What "the whole suite" means, in one place — RM-170 (#275).
#
# WHY THIS FILE EXISTS
# ====================
#
# Two packages in this repository destroy a running deployment, and both are
# correct on a clean host:
#
#   test/failure   brings up the shipped Sigstore stack under a per-process
#                  project name. Its compose file resolves the transparency
#                  log's database from INNSEGL_TRUST_TRILLIAN_DB_VOLUME and
#                  passes `--trillian_log_server.tlog_id=${INNSEGL_REKOR_TLOG_ID:-0}`.
#                  0 means MINT A NEW TREE. Measured on 2026-09-16: a log of 74
#                  entries became a log of 1, and every commit ever signed
#                  answered `unavailable` for its inclusion proof. It recovered
#                  only because the pin was put back by hand.
#
#   test/smoke     is OPS-004, the fresh-clone contract, and it earns its clean
#                  slate the only way that proves anything: both shipped compose
#                  projects `down -v`, volumes included. On a host that is
#                  running the deployment those volumes are the ledger, the
#                  Fulcio CA key and the transparency log (#168).
#
# The rule — never run them while the stack is up — was written down after the
# first incident. It was broken twice more within two days, each time by someone
# who knew it, because five wrapper call sites reached the packages without ever
# saying so:
#
#   scripts/coverage-floors.sh   two bare `go test ./...`
#   scripts/test-no-skips.sh     one
#   Makefile                     two
#
# The trap is not in the knowledge. It is in a script whose name promises
# something harmless: nobody reads a coverage tool expecting it to tear down
# their deployment. So the knowledge moved here, where a wrapper has to ask for
# it rather than remember it, and the packages themselves refuse.
#
# ONE PLACE DECIDES, and that is the whole design. Five call sites each making
# the same judgement is how this happened; a sixth would have made it again.
# A wrapper now asks `packages` what to run and gets an answer, and
# `scripts/test-suite.sh gate` fails a wrapper that went back to deciding for
# itself.
#
# WHAT THIS IS NOT. It is not a ban. Both packages are the only proof of two
# invariants and they must stay runnable: with nothing from the deployment
# running, `packages` returns `./...` unchanged and both run exactly as before.
# What is refused is reaching them while there is something to destroy, and the
# refusal says how to run them properly — scripts/hooks/subagent-identity.sh
# carries the reason in its own words: "a gate that blocks and offers nothing is
# worse than no gate, because the work is stranded rather than merely unsigned."
#
# POSIX sh, NOT bash, and it is load-bearing rather than tidiness. This file is
# called from a Go TestMain, from a Makefile and from other gates, and
# scripts/no-published-specs.sh carries the measurement that settled it: a
# sibling gate written `#!/usr/bin/env bash` broke signing machine-wide with
# `env: can't execute 'bash'` inside an Alpine container that had no bash.
#
# `set -u` without `pipefail`: pipefail is not POSIX, and the pipelines below
# are greps and docker queries whose failure is a normal "found nothing".
#
# USAGE
#   scripts/test-suite.sh state              print `up` or `absent`
#   scripts/test-suite.sh stack              describe what is running; exit 0 if up
#   scripts/test-suite.sh destructive        print the destructive package dirs
#   scripts/test-suite.sh packages           print the package operands to test
#   scripts/test-suite.sh guard PKG...       refuse a destructive package, or exit 0
#   scripts/test-suite.sh run [go-test-args] guard, then run the suite
#   scripts/test-suite.sh gate [root]        refuse a wrapper that decides for itself
#
# ENVIRONMENT
#   INNSEGL_SUITE_STACK            `up` or `absent`, when the question has
#                                  already been answered for this process tree.
#                                  WRITTEN BY THIS SCRIPT and by the wrappers
#                                  that call it — not by hand. It exists so that
#                                  a suite run does not re-ask docker once per
#                                  package, and so that a package started by
#                                  another package's harness is not mistaken for
#                                  a deployment.
#   INNSEGL_ALLOW_DESTRUCTIVE_TESTS
#                                  comma- or space-separated package dirs the
#                                  operator has decided to run anyway, e.g.
#                                  `test/smoke`. The naming IS the decision:
#                                  scripts/teardown-guard.sh takes the same
#                                  shape for the same reason — a yes, or a 1, is
#                                  what an accident looks like from the inside.
#
# EXIT
#   0   safe, or the question does not apply
#   2   this script's own command line was not understood
#   9   REFUSED: a destructive package was reached with the deployment up
#  10   the gate found a wrapper that runs the whole tree on its own judgement

set -u

EXIT_USAGE=2
EXIT_REFUSED=9
EXIT_GATE=10

HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
ROOT="$(CDPATH= cd -- "${HERE}/.." && pwd -P)"

# ---------------------------------------------------------------------------
# THE DESTRUCTIVE PACKAGES. "<dir>|<what it does to a live deployment>"
#
# One row per package, and the second field is what the refusal prints. Somebody
# reading "test/smoke" at 09:41 needs to be told what it removes, not left to
# remember.
# ---------------------------------------------------------------------------
DESTRUCTIVE='test/failure|brings the shipped Sigstore stack up with INNSEGL_REKOR_TLOG_ID unset, which mints a NEW transparency-log tree in the log database this deployment already has
test/smoke|earns its clean slate with `docker compose down -v` on both shipped projects, which removes the ledger, the Fulcio CA key and the transparency log'

# The compose projects this repository ships — the `name:` of each file under
# deploy/compose/. A container running in one of these is the deployment; the
# test harnesses all namespace their projects per process (ADR-0022), so their
# own stacks never look like one. test/smoke is the single exception and it
# takes a lock before it starts, which is why it is on the list above rather
# than expected to recognise itself here.
DEPLOYMENT_PROJECTS='innsegl-core innsegl-sigstore innsegl-spire'

# The log database volume, under the name the durable path gives it. Same
# default as scripts/rekor-tlog-pin.sh, deliberately: two gates disagreeing
# about which volume holds the log is the next version of this bug.
TRILLIAN_DB_VOLUME="${INNSEGL_TRUST_TRILLIAN_DB_VOLUME:-innsegl-trust-trillian-db}"

# ---------------------------------------------------------------------------
# Detection.
# ---------------------------------------------------------------------------

have_docker() { command -v docker >/dev/null 2>&1; }

# running_projects echoes "<project> <n> <first few names>" for each shipped
# compose project that has a container running.
running_projects() {
  have_docker || return 0
  for p in ${DEPLOYMENT_PROJECTS}; do
    names="$(docker ps --filter "label=com.docker.compose.project=${p}" \
      --format '{{.Names}}' 2>/dev/null | sort | tr '\n' ' ')"
    case "${names}" in
      '' ) continue ;;
    esac
    n="$(printf '%s' "${names}" | tr ' ' '\n' | grep -c .)"
    printf '%s %s %s\n' "${p}" "${n}" "${names}"
  done
}

# pinned_tree echoes the transparency log's pinned tree id, or nothing.
#
# This is scripts/rekor-tlog-pin.sh's answer and not a second reading of the
# same file: RM-150 already settled that the pin is read from the REPOSITORY
# rather than from whichever worktree the command runs in, and re-deriving it
# here would be the second place that can be wrong.
pinned_tree() {
  id="$(sh "${HERE}/rekor-tlog-pin.sh" read "${ROOT}" 2>/dev/null)"
  case "${id:-0}" in
    ''|0) return 0 ;;
    *) printf '%s' "${id}" ;;
  esac
}

# durable_log_attached reports whether THIS environment would hand the real log
# database to a test stack.
#
# The compose file resolves `sigstore-trillian-db-data` to
# ${INNSEGL_TRUST_TRILLIAN_DB_VOLUME} and marks it external when
# INNSEGL_TRUST_VOLUMES_EXTERNAL is true. test/failure's harness runs compose
# with `append(os.Environ(), ...)`, so an ambient trust environment reaches it —
# and then the "isolated" stack mints its new tree inside the real log.
#
# It is deliberately conditioned on the CALLER'S environment rather than on the
# volume merely existing. A volume that exists on a quiet host is not a hazard,
# and treating it as one would turn this gate into the permanent ban it must not
# become.
durable_log_attached() {
  case "${INNSEGL_TRUST_VOLUMES_EXTERNAL:-false}" in
    true|TRUE|1|yes) : ;;
    *) return 1 ;;
  esac
  have_docker || return 1
  docker volume inspect "${TRILLIAN_DB_VOLUME}" >/dev/null 2>&1 || return 1
  [ -n "$(pinned_tree)" ]
}

# describe_stack writes the signals to stdout and returns 0 when a deployment is
# up. Both signals are printed whenever either fires, because the refusal has to
# name what is at risk and the pinned tree is the thing nobody can put back.
describe_stack() {
  up=1
  projects="$(running_projects)"
  if [ -n "${projects}" ]; then
    up=0
    printf '%s\n' "${projects}" | while IFS=' ' read -r p n names; do
      [ -n "${p}" ] || continue
      printf '    %s: %s container(s) running — %s\n' "${p}" "${n}" "${names}"
    done
  fi
  if durable_log_attached; then
    up=0
    printf '    the durable trust volumes are in this environment: %s holds the log\n' \
      "${TRILLIAN_DB_VOLUME}"
  fi
  tree="$(pinned_tree)"
  if [ -n "${tree}" ] && [ "${up}" -eq 0 ]; then
    printf '    the transparency log is pinned to tree %s — nothing puts that back\n' "${tree}"
  fi
  return "${up}"
}

# stack_state echoes `up` or `absent`, answering once and honouring an answer
# already given for this process tree.
stack_state() {
  case "${INNSEGL_SUITE_STACK:-}" in
    up|absent) printf '%s' "${INNSEGL_SUITE_STACK}"; return 0 ;;
  esac
  if describe_stack >/dev/null 2>&1; then printf 'up'; else printf 'absent'; fi
}

# ---------------------------------------------------------------------------
# The package list.
# ---------------------------------------------------------------------------

destructive_dirs() {
  printf '%s\n' "${DESTRUCTIVE}" | while IFS='|' read -r d _; do
    [ -n "${d}" ] && printf '%s\n' "${d}"
  done
}

what_it_does() {
  want="$1"
  printf '%s\n' "${DESTRUCTIVE}" | while IFS='|' read -r d what; do
    [ "${d}" = "${want}" ] && printf '%s' "${what}"
  done
}

# normalise turns a `go test` package operand into a repository-relative dir:
#   ./test/smoke  test/smoke  innsegl.dev/innsegl/test/smoke  ./test/smoke/...
# all become test/smoke. A pattern is returned with its `/...` intact so the
# caller can tell a package from a tree.
normalise() {
  p="$1"
  p="${p#innsegl.dev/innsegl/}"
  p="${p#./}"
  p="${p%/}"
  printf '%s' "${p}"
}

# reaches reports whether a package operand would run the given directory.
reaches() {
  operand="$(normalise "$1")"
  dir="$2"
  case "${operand}" in
    "${dir}") return 0 ;;
    '...'|'all') return 0 ;;
    */...)
      prefix="${operand%/...}"
      case "${dir}" in
        "${prefix}"|"${prefix}"/*) return 0 ;;
      esac
      ;;
  esac
  return 1
}

allowed_by_operator() {
  want="$1"
  saved="$IFS"
  IFS=', '
  # shellcheck disable=SC2086 # deliberate: the list is split on commas/spaces.
  set -- ${INNSEGL_ALLOW_DESTRUCTIVE_TESTS:-}
  IFS="$saved"
  for a in "$@"; do
    [ "$(normalise "${a}")" = "${want}" ] && return 0
  done
  return 1
}

# suite_packages prints the operands a wrapper should hand `go test`.
#
# On a quiet host that is `./...`, byte for byte what every wrapper said before
# this file existed — so CI, which never has a deployment, runs exactly the tree
# it always ran, destructive packages included.
#
# With the deployment up it is the explicit list `go list ./...` gives, minus the
# destructive rows. Explicit rather than clever: `go test` has no exclusion
# syntax, and a wrapper that tried to invent one is the failure mode this file
# is here to remove.
suite_packages() {
  # The module root is an argument because scripts/coverage-floors.sh runs
  # against a throwaway fixture module in its own self-test, and a list of THIS
  # repository's packages handed to another module is a failure that would only
  # show up on a host with a deployment running — which is to say, once, badly.
  sroot="${1:-}"
  [ -n "${sroot}" ] || sroot="${ROOT}"
  if [ "$(stack_state)" = "absent" ]; then
    printf './...\n'
    return 0
  fi
  listed="$(cd -- "${sroot}" && go list ./... 2>/dev/null)"
  if [ -z "${listed}" ]; then
    printf 'test-suite: `go list ./...` said nothing in %s; cannot name the suite.\n' "${sroot}" >&2
    printf '  The deployment is up, so `./...` would reach the destructive packages.\n' >&2
    return 1
  fi
  # Matched on the directory suffix rather than on this module's import prefix,
  # so the answer is right in a fixture module too. Anchored, so a future
  # `test/smoketest` is not swept up by a package it has nothing to do with.
  excl="$(destructive_dirs | sed 's#^#/#' | tr '\n' '|' | sed 's/|$//')"
  printf '%s\n' "${listed}" | grep -vE "(${excl})\$"
  {
    printf 'test-suite: the deployment is up; the suite excludes'
    destructive_dirs | tr '\n' ' ' | sed 's/ $//' | sed 's/^/ /'
    printf '.\n'
    printf '  They are correct tests, not banned ones: stop the deployment and they\n'
    printf '  run again. `scripts/test-suite.sh guard test/smoke` says how.\n'
  } >&2
}

# ---------------------------------------------------------------------------
# The refusal.
# ---------------------------------------------------------------------------

refuse() {
  dir="$1"
  {
    echo
    echo "REFUSED: ${dir} destroys a running deployment, and this one is up."
    echo
    echo "  ${dir}"
    printf '      %s.\n' "$(what_it_does "${dir}")"
    echo
    echo "  What is running:"
    describe_stack
    echo
    echo "  Nothing was run, nothing was stopped and nothing was removed."
    echo
    echo "  TO RUN IT PROPERLY — it is a correct test and it must keep running:"
    echo
    printf '    %-26s %s\n' "make innsegl-down"  "stop the deployment; the volumes survive"
    printf '    %-26s %s\n' "make sigstore-down" "stop Sigstore and SPIRE"
    printf '    %-26s %s\n' "go test ./${dir}"   "now it has nothing to destroy"
    printf '    %-26s %s\n' "make innsegl-up"    "bring the deployment back"
    echo
    echo "  TO RUN THE REST OF THE SUITE, which is the default and needs no flag:"
    echo
    echo "    scripts/test-suite.sh run -race"
    echo
    echo "  IF YOU MEAN IT, name the package — the naming IS the decision:"
    echo
    echo "    INNSEGL_ALLOW_DESTRUCTIVE_TESTS=${dir} go test ./${dir}"
    echo
  } >&2
}

# guard_operands refuses if any operand reaches a destructive package while the
# deployment is up.
guard_operands() {
  [ "$(stack_state)" = "up" ] || return 0
  rc=0
  for dir in $(destructive_dirs); do
    for operand in "$@"; do
      if reaches "${operand}" "${dir}"; then
        if allowed_by_operator "${dir}"; then
          printf 'test-suite: running %s against a live deployment, because you named it.\n' \
            "${dir}" >&2
        else
          refuse "${dir}"
          rc="${EXIT_REFUSED}"
        fi
        break
      fi
    done
  done
  return "${rc}"
}

# ---------------------------------------------------------------------------
# The gate: a wrapper that went back to deciding for itself.
#
# This is the half that stops the sixth call site. Documenting the rule did not
# work twice; a grep that fails the build is not a better memory, it is the
# absence of one.
# ---------------------------------------------------------------------------
gate() {
  groot="${1:-${ROOT}}"
  found=0
  for f in "${groot}"/scripts/*.sh "${groot}"/Makefile "${groot}"/.github/workflows/*.yml; do
    [ -f "${f}" ] || continue
    case "${f}" in
      */test-suite.sh|*/test-suite-selftest.sh) continue ;;
    esac
    # `go test` with the whole tree as its operand. -coverpkg=./... is a
    # different flag and carries no risk: it instruments packages, it does not
    # select which ones run.
    hits="$(grep -n 'go test[[:space:]][[:space:]]*\./\.\.\.' "${f}" 2>/dev/null |
      grep -v '^[0-9]*:[[:space:]]*#' || true)"
    [ -n "${hits}" ] || continue
    found=1
    printf '%s\n' "${hits}" | while IFS= read -r h; do
      printf '  %s:%s\n' "${f#"${groot}"/}" "${h}"
    done
  done
  if [ "${found}" -ne 0 ]; then
    {
      echo
      echo "REFUSED: a wrapper runs the whole tree on its own judgement."
      echo
      echo "  \`go test ./...\` reaches test/failure and test/smoke, and both destroy a"
      echo "  running deployment. That is how #275 happened three times in two days:"
      echo "  five call sites each deciding what the suite is, and a script whose name"
      echo "  promises something harmless."
      echo
      echo "  Ask instead, and the answer is right everywhere at once:"
      echo
      echo "    INNSEGL_SUITE_STACK=\"\$(scripts/test-suite.sh state)\"; export INNSEGL_SUITE_STACK"
      echo "    PKGS=\"\$(scripts/test-suite.sh packages)\" || exit 1"
      echo "    go test \${PKGS} -race"
      echo
      echo "  On a host with no deployment \`packages\` prints \`./...\`, so nothing about"
      echo "  CI changes. With one up it prints the tree without the two."
      echo
    } >&2
    return "${EXIT_GATE}"
  fi
  printf 'test-suite: no wrapper decides what the suite is on its own\n'
  return 0
}

# ---------------------------------------------------------------------------
# Dispatch.
# ---------------------------------------------------------------------------

cmd="${1:-}"
[ $# -gt 0 ] && shift

case "${cmd}" in
  state) stack_state; printf '\n' ;;

  stack)
    if describe_stack; then
      printf 'the deployment is up\n'
      exit 0
    fi
    printf 'no deployment is running\n'
    exit 1
    ;;

  destructive) destructive_dirs ;;

  packages) suite_packages "${1:-}" ;;

  guard)
    [ $# -gt 0 ] || { echo "test-suite: guard needs a package" >&2; exit "${EXIT_USAGE}"; }
    guard_operands "$@"
    exit $?
    ;;

  run)
    INNSEGL_SUITE_STACK="$(stack_state)"
    export INNSEGL_SUITE_STACK
    pkgs="$(suite_packages "${ROOT}")" || exit 1
    guard_operands ${pkgs} || exit $?
    # shellcheck disable=SC2086 # deliberate: the list is one operand per line.
    cd -- "${ROOT}" && exec go test ${pkgs} "$@"
    ;;

  gate) gate "${1:-}" ; exit $? ;;

  -h|--help|help)
    sed -n '/^# USAGE/,/^# EXIT/p' "$0" | sed 's/^# \{0,1\}//'
    ;;

  *)
    printf 'test-suite: unknown command: %s\n' "${cmd:-<none>}" >&2
    sed -n '/^# USAGE/,/^# EXIT/p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit "${EXIT_USAGE}"
    ;;
esac
