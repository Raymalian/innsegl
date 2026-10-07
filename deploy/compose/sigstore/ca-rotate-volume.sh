# SPDX-License-Identifier: Apache-2.0
#
# The rotation's hands inside the Fulcio CA's trust volume (#533, ADR-0075).
#
# Not run on its own. scripts/ca-rotate.sh pipes ca-lib.sh and then this file
# into `sh -s` in the pinned openssl image, with the volume at /pki, no
# network and /tmp on tmpfs: nothing is bind-mounted from the checkout, and a
# key in the clear only ever touches memory. Logs go to stderr; the one thing
# on stdout is a certificate, when a verb prints one.
#
#   show            print the root on the volume
#   archive STAMP   copy ca.crt, ca.key, ca.pass and serve.yaml to
#                   archive/STAMP, check every byte, and check the archived
#                   key opens with the archived password. Never overwrites.
#   stage STAMP     make the next CA in staging/, the way the bootstrap makes
#                   the first (ca-lib.sh), with a new generated password;
#                   print its root
#   swap STAMP      move the staged CA into place
#   restore STAMP   put archive/STAMP back in place
#   discard STAMP   remove staging/ and archive/STAMP: only for a rotation that
#                   never reached the switch, whose archive is a copy of what
#                   is still in place
#
# Archives are never deleted otherwise. Each keeps its key with its own
# password, so an old CA can be put back, or handed to a forensic look, as
# it was.

set -eu

PKI=/pki
log()  { printf 'ca-rotate-volume: %s\n' "$*" >&2; }
fail() { printf 'ca-rotate-volume: FAIL: %s\n' "$*" >&2; exit 1; }

FILES='ca.crt ca.key ca.pass serve.yaml'
verb="${1:-}"
stamp="${2:-}"

need_stamp() {
  case "${stamp}" in
    ''|*/*|.*) fail "${verb} needs a STAMP of letters, digits and dashes, got '${stamp}'" ;;
  esac
}

# copy_set FROM TO copies the CA files and checks each byte.
copy_set() {
  for f in ${FILES}; do
    [ -s "$1/${f}" ] || fail "$1/${f} is missing"
    cp -p "$1/${f}" "$2/${f}.tmp"
    cmp -s "$1/${f}" "$2/${f}.tmp" || fail "the copy of $1/${f} differs"
    mv "$2/${f}.tmp" "$2/${f}"
  done
}

case "${verb}" in
  show)
    cat "${PKI}/ca.crt"
    ;;
  archive)
    need_stamp
    a="${PKI}/archive/${stamp}"
    [ ! -e "${a}" ] || fail "${a} exists already; an archive is never overwritten"
    mkdir -p "${PKI}/archive"
    chmod 0700 "${PKI}/archive"
    mkdir "${a}"
    copy_set "${PKI}" "${a}"
    ca_opens "${a}/ca.key" "file:${a}/ca.pass" \
      || { rm -rf "${a}"; fail 'the archived key does not open with the archived password'; }
    log "archived the CA as archive/${stamp}"
    ;;
  stage)
    need_stamp
    s="${PKI}/staging"
    rm -rf "${s}"
    mkdir -m 0700 "${s}"
    ca_new_password "${s}/ca.pass"
    ca_generate "${s}" "${s}/ca.pass"
    ca_opens "${s}/ca.key" "file:${s}/ca.pass" || fail 'the new key does not open with its password'
    ca_render_serve_config "${s}/ca.pass" "${s}/serve.yaml"
    ca_own "${s}"
    log 'staged a new CA'
    cat "${s}/ca.crt"
    ;;
  swap)
    need_stamp
    s="${PKI}/staging"
    for f in ${FILES}; do [ -s "${s}/${f}" ] || fail "nothing staged: ${s}/${f} is missing"; done
    # Key and password first, then the config that names the password, then
    # the root: Fulcio is restarted only after all four are in place.
    for f in ca.key ca.pass serve.yaml ca.crt; do mv "${s}/${f}" "${PKI}/${f}"; done
    rmdir "${s}"
    log 'the new CA is in place'
    ;;
  restore)
    need_stamp
    a="${PKI}/archive/${stamp}"
    [ -d "${a}" ] || fail "no archive ${stamp}"
    ca_opens "${a}/ca.key" "file:${a}/ca.pass" || fail "archive ${stamp}'s key does not open with its password"
    copy_set "${a}" "${PKI}"
    ca_own "${PKI}"
    log "archive ${stamp} is back in place"
    ;;
  discard)
    need_stamp
    rm -rf "${PKI}/staging" "${PKI}/archive/${stamp}"
    log "discarded staging/ and archive/${stamp}"
    ;;
  *)
    fail "unknown verb '${verb}'"
    ;;
esac
