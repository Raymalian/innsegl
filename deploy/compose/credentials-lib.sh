#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Every service credential, generated per host and kept in a file (ADR-0078).
#
# Sourced by the two one-shots that run first in each project:
# innsegl/credentials-init.sh in the core, and sigstore/bootstrap.sh in the
# Sigstore project. POSIX sh: both run in the pinned alpine/openssl image.
#
# A credential is one file in the project's trust credentials volume, holding
# one line: 64 hex characters, 32 bytes from openssl's CSPRNG. It is written
# once and kept. No shipped file holds a value for one, and nothing here ever
# prints one.
#
# Functions:
#   cred_ensure STORE NAME...       generate each NAME that is missing; keep
#                                   the rest; refuse one that is malformed
#   cred_value STORE NAME           print the value (to a pipe or a file only)
#   cred_put FILE MODE              write stdin to FILE atomically, with MODE

cred_log()  { printf '%s: %s\n' "${CRED_WHO:-credentials}" "$*"; }
cred_fail() { printf '%s: FAIL: %s\n' "${CRED_WHO:-credentials}" "$*" >&2; exit 1; }

# cred_valid reports whether a file holds one usable credential: a single
# line of 16 or more characters that need no quoting in a DSN, a URL, SQL,
# YAML, JSON or a pgpass line. What this release writes is 64 hex characters;
# a value restored from elsewhere may be any such string.
cred_valid() {
  [ -f "$1" ] || return 1
  [ "$(wc -l < "$1" | tr -d ' ')" -le 1 ] || return 1
  v=$(head -n 1 "$1")
  [ "${#v}" -ge 16 ] || return 1
  case "${v}" in
    *[!A-Za-z0-9._~-]*) return 1 ;;
  esac
  return 0
}

cred_put() {
  put_file=$1; put_mode=$2
  put_tmp="${put_file}.tmp.$$"
  (umask 077 && cat > "${put_tmp}") || cred_fail "could not write ${put_file}"
  chmod "${put_mode}" "${put_tmp}" || cred_fail "could not set the mode of ${put_file}"
  mv -f "${put_tmp}" "${put_file}" || cred_fail "could not move ${put_file} into place"
}

cred_ensure() {
  store=$1; shift
  [ -d "${store}" ] || cred_fail "${store} is not a directory; check the trust credentials volume is mounted"
  for name in "$@"; do
    f="${store}/${name}"
    if [ -e "${f}" ]; then
      cred_valid "${f}" \
        || cred_fail "${f} is not one line of 16 or more of [A-Za-z0-9._~-]. Restore it from the trust-key backup; nothing was changed"
      cred_log "${name}: kept"
      continue
    fi
    v=$(openssl rand -hex 32) || cred_fail "openssl rand failed"
    [ "${#v}" -eq 64 ] || cred_fail "openssl rand returned ${#v} characters, not 64"
    printf '%s\n' "${v}" | cred_put "${f}" 0400
    v=''
    cred_valid "${f}" || cred_fail "${f} did not read back as a credential"
    cred_log "${name}: generated"
  done
}

cred_value() {
  cred_valid "$1/$2" || cred_fail "$1/$2 is missing or malformed"
  head -n 1 "$1/$2"
}
