#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Signs a freshly built innsegl binary with a Developer ID on macOS, so the
# system keeps its Local Network permission across rebuilds. `make build`
# runs it after `go build`.
#
# WHY. macOS asks for Local Network permission per binary, and recognises a
# binary across rebuilds only by its code signature. An unsigned (ad hoc)
# binary is a new one after every build: the permission is asked for again,
# and until it is granted the binary cannot reach a host on the LAN ("no
# route to host"). Signed with the same Developer ID and identifier, a
# rebuild keeps it.
#
# WHAT IT DOES.
#   - Not macOS: nothing, and says nothing. Never on Linux.
#   - $INNSEGL_CODESIGN_IDENTITY=none: leaves the binary unsigned, says so.
#   - $INNSEGL_CODESIGN_IDENTITY set: signs with that identity, a SHA-1 hash
#     or a name `security find-identity` lists. A name several identities
#     share is narrowed to the newest-issued of them.
#   - Otherwise: the newest-issued "Developer ID Application" identity.
#     Several can share one name (a renewed certificate); the hash, not the
#     name, says which one is used.
#   - None: leaves the binary unsigned, and says so once.
#   The signature: codesign -f -s <SHA-1> -i dev.innsegl.cli <binary>.
#
# USAGE
#   scripts/codesign-cli.sh <binary>
#
# EXIT STATUS
#   0  signed, or left unsigned on purpose (not macOS, none asked, none held)
#   1  the identity asked for is not held, or codesign failed
#   2  usage
set -uo pipefail

IDENTIFIER="dev.innsegl.cli"
KIND="Developer ID Application"

bin="${1:-}"
if [ -z "${bin}" ] || [ "$#" -ne 1 ]; then
  echo "usage: scripts/codesign-cli.sh <binary>" >&2
  exit 2
fi
[ "$(uname -s)" = "Darwin" ] || exit 0

if [ "${INNSEGL_CODESIGN_IDENTITY:-}" = "none" ]; then
  echo "codesign: INNSEGL_CODESIGN_IDENTITY=none; ${bin} is unsigned, and macOS will ask for Local Network permission again"
  exit 0
fi

# Every valid code-signing identity: "<SHA-1> <name>", one per line.
identities="$(security find-identity -v -p codesigning 2>/dev/null |
  sed -nE 's/^ *[0-9]+\) ([0-9A-Fa-f]{40}) "(.*)"$/\1 \2/p')"

# not_before HASH NAME — the certificate's notBefore as "YYYY-MM-DD HH:MM:SS",
# so that a plain sort orders them. Empty when it cannot be read.
not_before() {
  security find-certificate -a -Z -p -c "$2" 2>/dev/null |
    awk -v want="$1" '
      /^SHA-1 hash:/ { take = (toupper($3) == toupper(want)); next }
      take { print }
      /-----END CERTIFICATE-----/ { if (take) exit }' |
    openssl x509 -noout -startdate 2>/dev/null |
    awk -F= '/^notBefore=/ {
      split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " ")
      n = split($2, f, " ")
      for (i = 1; i <= 12; i++) if (m[i] == f[1]) mon = i
      if (n >= 4 && mon) printf "%04d-%02d-%02d %s\n", f[4], mon, f[2], f[3]
    }'
}

# newest "<SHA-1> <name>" lines on stdin: the newest-issued of them.
newest() {
  local hash name when best="" best_when=""
  while read -r hash name; do
    [ -n "${hash}" ] || continue
    when="$(not_before "${hash}" "${name}")"
    if [ -z "${best}" ] || [[ "${when}" > "${best_when}" ]]; then
      best="${hash} ${name}"
      best_when="${when}"
    fi
  done
  printf '%s\n' "${best}"
}

want="${INNSEGL_CODESIGN_IDENTITY:-}"
if [ -n "${want}" ]; then
  matches="$(printf '%s\n' "${identities}" | awk -v w="${want}" '
    toupper($1) == toupper(w) { print; next }
    { name = $0; sub(/^[^ ]+ /, "", name); if (name == w) print }')"
  if [ -z "${matches}" ]; then
    echo "codesign: INNSEGL_CODESIGN_IDENTITY=${want} is not a code-signing identity this keychain holds" \
      "(security find-identity -v -p codesigning); ${bin} is not signed" >&2
    exit 1
  fi
else
  matches="$(printf '%s\n' "${identities}" | awk -v k="${KIND}: " 'index($0, " " k) == 41')"
  if [ -z "${matches}" ]; then
    echo "codesign: no ${KIND} identity in the keychain; ${bin} is unsigned, and macOS will ask for" \
      "Local Network permission again after each rebuild"
    exit 0
  fi
fi

chosen="$(printf '%s\n' "${matches}" | newest)"
hash="${chosen%% *}"
name="${chosen#* }"
if ! out="$(codesign -f -s "${hash}" -i "${IDENTIFIER}" "${bin}" 2>&1)"; then
  echo "codesign: signing ${bin} with ${name} (${hash}) failed: ${out}" >&2
  exit 1
fi
echo "codesign: signed ${bin} as ${IDENTIFIER} with ${name} (${hash})"
