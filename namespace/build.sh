#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Build the Innsegl namespace stub artifacts locally, and publish nothing.
#
# There is exactly one definition of each artifact and it is this script, so
# that the tarball a human inspects before publishing is byte-identical to the
# tarball the publish command uploads. Both packages are staged into
# namespace/dist/stage/ first, because both must carry the repository's own
# LICENSE and that file is not duplicated inside namespace/ — a second copy of
# a licence is a second thing that can drift from the first.
#
# Nothing here touches a registry, reads a credential, or needs a login. The
# publish step is a human's, and it is written out in namespace/PROCEDURE.md.
#
# Usage:
#   namespace/build.sh          build both, print digests
#   namespace/build.sh npm      build only the npm tarball
#   namespace/build.sh pypi     build only the sdist and wheel
#
# Requires: npm (for the npm tarball) and uv (for the Python distributions).
# uv rather than `python -m build` because it needs no pre-installed backend:
# it fetches hatchling into a throwaway environment.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
DIST="${SCRIPT_DIR}/dist"

what="${1:-all}"
case "${what}" in
  all|npm|pypi) ;;
  -h|--help) sed -n '3,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) printf 'usage: %s [all|npm|pypi]\n' "$(basename "$0")" >&2; exit 2 ;;
esac

# The gate first. Building an artifact whose metadata contradicts the repository
# is how a wrong first version gets published, and a wrong first version of an
# attribution tool's package is permanent: npm and PyPI have no real unpublish.
"${SCRIPT_DIR}/verify-namespace.sh"
printf '\n'

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
else
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
fi

mkdir -p "${DIST}"
# Stage outside the repository. Hatchling's sdist picks up an ancestor
# .gitignore, and `uv build` writes one into its own output directory, so a
# stage directory nested under dist/ silently ships that file inside the sdist.
# A temporary directory makes the artifact depend on the staged inputs alone.
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/innsegl-namespace.XXXXXX")"
trap 'rm -rf "${STAGE}"' EXIT

if [ "${what}" = all ] || [ "${what}" = npm ]; then
  printf '==> npm\n'
  command -v npm >/dev/null 2>&1 || { printf 'FAIL: npm is not installed\n' >&2; exit 1; }
  cp -R "${SCRIPT_DIR}/npm" "${STAGE}/npm"
  cp "${REPO_ROOT}/LICENSE" "${STAGE}/npm/LICENSE"
  ( cd "${STAGE}/npm" && npm pack --pack-destination "${DIST}" >/dev/null )
  tgz="$(ls -t "${DIST}"/innsegl-*.tgz | head -1)"
  printf '    %s\n' "${tgz#"${REPO_ROOT}"/}"
  printf '    sha256   %s\n' "$(sha256 "${tgz}")"
  printf '    shasum   %s   <- npm dist.shasum is SHA-1; this is what `npm view innsegl dist.shasum` returns\n' \
    "$(shasum -a 1 "${tgz}" | cut -d' ' -f1)"
  printf '    contents:\n'
  tar -tzf "${tgz}" | sed 's/^/      /'
  printf '\n'
fi

if [ "${what}" = all ] || [ "${what}" = pypi ]; then
  printf '==> PyPI\n'
  command -v uv >/dev/null 2>&1 || { printf 'FAIL: uv is not installed (https://docs.astral.sh/uv/)\n' >&2; exit 1; }
  cp -R "${SCRIPT_DIR}/pypi" "${STAGE}/pypi"
  cp "${REPO_ROOT}/LICENSE" "${STAGE}/pypi/LICENSE"
  ( cd "${STAGE}/pypi" && uv build --out-dir "${DIST}" >/dev/null 2>&1 )
  for art in "${DIST}"/innsegl-*.tar.gz "${DIST}"/innsegl-*.whl; do
    [ -f "${art}" ] || continue
    printf '    %s\n' "${art#"${REPO_ROOT}"/}"
    printf '    sha256   %s\n' "$(sha256 "${art}")"
  done
  whl="$(ls -t "${DIST}"/innsegl-*.whl 2>/dev/null | head -1 || true)"
  if [ -n "${whl}" ]; then
    printf '    wheel contents:\n'
    unzip -Z1 "${whl}" | sed 's/^/      /'
  fi
  printf '\n'
fi

printf 'Built into %s. Nothing was published.\n' "${DIST#"${REPO_ROOT}"/}"
printf 'The publish step is a human step: see namespace/PROCEDURE.md.\n'
