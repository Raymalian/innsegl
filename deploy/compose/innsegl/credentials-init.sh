#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# innsegl-credentials — the core's credentials, generated per host (ADR-0078).
#
# Runs first, with no network. Two jobs:
#
#   1. Make sure the trust credentials volume holds one file per credential
#      (credentials-lib.sh, cred_ensure). A file already there is kept.
#   2. Render each credential into its own small volume, in the form its
#      readers take. Rewritten on every start, so a credential restored into
#      the trust volume reaches every reader on the next bring-up.
#
# The per-credential volumes are the grant: a service mounts exactly the ones
# it uses (test/deploy/credentials_test.go). Their files are 0444 because the
# readers run as four different users; the mount is the control, as it is
# for the CA password beside its key (ADR-0075 decision 2).
#
# Layout, as every reader sees it under /run/innsegl/credentials/<name>/:
#   ledger-owner/password                        postgres (POSTGRES_PASSWORD_FILE)
#   <role>/password, <role>/pgpass                the five service roles; a DSN
#                                                names pgpass with passfile=
#   objects-root/secret, objects-sealer/secret    the two object-store identities
#
# Nothing here prints a value.

set -eu

CRED_WHO=innsegl-credentials
. "${INNSEGL_CREDENTIALS_LIB:-/innsegl/credentials-lib.sh}"

STORE="${INNSEGL_CREDENTIALS_STORE:-/run/innsegl/credentials-store}"
RENDER="${INNSEGL_CREDENTIALS_RENDER:-/run/innsegl/render}"

LEDGER_ROLES='appender reader authwriter resolver backup'

cred_ensure "${STORE}" ledger-owner \
  ledger-appender ledger-reader ledger-authwriter ledger-resolver ledger-backup \
  objects-root objects-sealer

render_dir() {
  [ -d "${RENDER}/$1" ] || cred_fail "${RENDER}/$1 is not mounted; innsegl.yml gives this one-shot every per-credential volume"
}

render_dir ledger-owner
v=$(cred_value "${STORE}" ledger-owner) || exit 1
printf '%s\n' "${v}" | cred_put "${RENDER}/ledger-owner/password" 0444

for role in ${LEDGER_ROLES}; do
  render_dir "${role}"
  v=$(cred_value "${STORE}" "ledger-${role}") || exit 1
  printf '%s\n' "${v}" | cred_put "${RENDER}/${role}/password" 0444
  # host:port:database:user:password. The DSN beside it names the host, the
  # database and the role; this file answers for whichever it names.
  printf '*:*:*:*:%s\n' "${v}" | cred_put "${RENDER}/${role}/pgpass" 0444
  v=''
done

for name in objects-root objects-sealer; do
  render_dir "${name}"
  v=$(cred_value "${STORE}" "${name}") || exit 1
  printf '%s\n' "${v}" | cred_put "${RENDER}/${name}/secret" 0444
done
v=

cred_log 'ready: every credential is in the trust volume and rendered for its readers'
