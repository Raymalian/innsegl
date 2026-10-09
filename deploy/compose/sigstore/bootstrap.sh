#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Bootstrap the local CA, the transparency log's identity, and Fulcio's issuer
# configuration for the reference Sigstore compose stack (RM-030, #38).
#
# Runs to completion before fulcio or rekor start, in the shape
# spire/bootstrap.sh established: one container, no network, the only place a
# private key is ever writable, and it exits.
#
# THREE OUTPUTS, THREE DIFFERENT KINDS OF THING
# ---------------------------------------------
#   /out/fulcio/ca.crt + ca.key   The local CA. Every certificate this
#                                 deployment issues chains to it, so it is the
#                                 root a verifier has to be given. Compromise =
#                                 mint a certificate for any SPIFFE ID in the
#                                 trust domain, which is to say: forge the
#                                 attribution of any agent run. Doc 05 §2 puts
#                                 the equivalent SPIRE key in a KMS/HSM in
#                                 production; compose keeps it on a volume the
#                                 same way it keeps SPIRE's datastore in
#                                 SQLite, and for the same reason — this is a
#                                 reference stack, not a deployment.
#
#   /out/rekor/log.key            The transparency log's signing identity. It
#                                 signs checkpoints, and ADR-0009 decision 2
#                                 ends its verification chain on exactly this
#                                 key: "Only the last step trusts anything, and
#                                 what it trusts is a key." It is generated
#                                 here, and never regenerated, because a log
#                                 that forgets who it is invalidates every
#                                 anchor it ever issued.
#
#   /out/fulcio/config.yaml       Rendered from the mounted template with the
#                                 OIDC issuer substituted in. Not a secret;
#                                 written here only because Fulcio has no
#                                 environment expansion and the issuer must
#                                 match spire-server's `jwt_issuer` exactly.
#
#   /out/fulcio/ca.pass           The CA key's password, generated on this
#   /out/fulcio/serve.yaml        host, and Fulcio's config file carrying it
#                                 (#533, ADR-0075). ca-lib.sh says why a file
#                                 and not a command-line value.
#
# IDEMPOTENT, AND ASYMMETRICALLY SO. The keys are generated once and then left
# alone: a CA is replaced only by `make innsegl-ca-rotate`
# (runbooks/trust-rotation.md), which keeps the old root in the trust
# history. The config is re-rendered on every run, because the issuer is the
# one input an operator legitimately changes and a stale rendered copy would
# mean Fulcio silently disagreeing with SPIRE about who the issuer is.
#
# THE CA PASSWORD, ON AN EXISTING HOST. Before #533 the password came from
# INNSEGL_FULCIO_CA_PASSWORD, and the compose file defaulted it to a value
# anyone could read. So the first run of this version moves a host onto a
# password file, with no step for the operator:
#   - ca.pass exists: it is the password. The variable is no longer read.
#   - the variable is set: ca.pass is written from it, once, after checking it
#     opens the key.
#   - neither, and the key opens with the old public default: the key is
#     re-locked under a generated password (ca-lib.sh, ca_relock).
#   - neither, and it does not: refused, naming the variable to set once.
#   - no key yet: a password is generated, then the key.

set -eu

FULCIO_OUT=/out/fulcio
REKOR_OUT=/out/rekor
CONFIG_IN=/in/fulcio-config.yaml
CA_LIB=/ca-lib.sh

# ADR-0078. Set by sigstore.yml; unset, as in a run of this script on its own
# (sigstore-bootstrap-selftest.sh), the credentials step is skipped.
CRED_LIB=/credentials-lib.sh
CRED_STORE="${INNSEGL_CREDENTIALS_STORE:-}"
CRED_RENDER=/run/innsegl/render
REKOR_INDEX_TEMPLATE=/in/rekor-index.sql
TRILLIAN_DB_USER="${INNSEGL_TRILLIAN_DB_USER:-test}"
TRILLIAN_DB_NAME="${INNSEGL_TRILLIAN_DB_NAME:-test}"

# Both Sigstore images run as uid 65532 (`docker inspect ghcr.io/sigstore/
# fulcio`, `.../rekor-server`). Docker creates a fresh named volume root-owned,
# so what those two must read is chowned here rather than by running them as
# root. ca-lib.sh holds the same pair, and the CA's 10-year lifetime: the
# certificates it issues are ten minutes long, because Fulcio hard-codes that
# and short-lived certificates are the whole point of the design.
RUN_UID=65532
RUN_GID=65532

# The placeholder the template carries. Substituted by exact string match
# rather than by `sed`, because the replacement is a URL: every sed delimiter
# worth using appears in some legitimate URL, and a bootstrap that corrupts the
# issuer would fail as "Fulcio rejects every token" three layers away.
PLACEHOLDER='${INNSEGL_SPIRE_JWT_ISSUER}'

log()  { printf 'sigstore-bootstrap: %s\n' "$*"; }
fail() { printf 'sigstore-bootstrap: FAIL: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Validate the inputs before writing anything.
# ---------------------------------------------------------------------------
[ -n "${INNSEGL_SPIRE_JWT_ISSUER:-}" ] \
  || fail 'INNSEGL_SPIRE_JWT_ISSUER is empty; sigstore.yml should have refused to start'
case "${INNSEGL_SPIRE_JWT_ISSUER}" in
  http://*|https://*) : ;;
  *) fail "INNSEGL_SPIRE_JWT_ISSUER must be an http(s) URL, got: ${INNSEGL_SPIRE_JWT_ISSUER}" ;;
esac
[ -r "${CONFIG_IN}" ] || fail "${CONFIG_IN} is not readable; check the bind mount"
[ -r "${CA_LIB}" ] || fail "${CA_LIB} is not readable; check the bind mount"
# shellcheck source=ca-lib.sh
. "${CA_LIB}"

mkdir -p "${FULCIO_OUT}" "${REKOR_OUT}"

# ---------------------------------------------------------------------------
# The Fulcio CA, and its password.
#
# ECDSA P-256, matching spire/bootstrap.sh's choice throughout and Fulcio's own
# ephemeral CA; ca-lib.sh's ca_generate says which extensions Fulcio checks.
# The key is an ENCRYPTED PKCS#8 blob because that is what `fileca` expects.
# Its password is this host's own (see the header): the encryption protects a
# copy of ca.key that travels without ca.pass. What protects the key on the
# volume is still the mount table: one writer, one reader, read-only.
# ---------------------------------------------------------------------------
CA_KEY="${FULCIO_OUT}/ca.key"
CA_CRT="${FULCIO_OUT}/ca.crt"
CA_PASS="${FULCIO_OUT}/ca.pass"
NL='
'

ca_finish_relock "${FULCIO_OUT}"

# An existing host whose password is in the environment: move it into the file.
if [ ! -s "${CA_PASS}" ] && [ -n "${INNSEGL_FULCIO_CA_PASSWORD:-}" ]; then
  if [ "${INNSEGL_FULCIO_CA_PASSWORD}" = "${CA_LEGACY_PUBLIC_PASSWORD}" ]; then
    log 'INNSEGL_FULCIO_CA_PASSWORD is the public default earlier releases shipped; it is not adopted'
  else
    case "${INNSEGL_FULCIO_CA_PASSWORD}" in
      *"${NL}"*) fail 'INNSEGL_FULCIO_CA_PASSWORD holds a line break; a password file holds one line' ;;
    esac
    if [ -s "${CA_KEY}" ] && ! ca_opens "${CA_KEY}" env:INNSEGL_FULCIO_CA_PASSWORD; then
      fail 'INNSEGL_FULCIO_CA_PASSWORD does not open the CA key; nothing was written. Set it to the password the key is locked with.'
    fi
    (umask 077 && printf '%s\n' "${INNSEGL_FULCIO_CA_PASSWORD}" > "${CA_PASS}.tmp") \
      || fail "could not write ${CA_PASS}"
    chmod 0400 "${CA_PASS}.tmp"
    mv "${CA_PASS}.tmp" "${CA_PASS}"
    log 'moved the CA password from INNSEGL_FULCIO_CA_PASSWORD into the trust volume (ca.pass); the variable is no longer read and can be removed from .env'
  fi
fi

if [ ! -s "${CA_PASS}" ]; then
  if [ ! -s "${CA_KEY}" ]; then
    log 'generating this host'"'"'s CA password'
    ca_new_password "${CA_PASS}"
  elif ca_opens_legacy "${CA_KEY}"; then
    log 'the CA key is locked with the public default earlier releases shipped; re-locking it with a password of this host'"'"'s own'
    ca_relock "${FULCIO_OUT}" env:CA_LEGACY_PUBLIC_PASSWORD
    log 'CA key re-locked: same key, new password, and the old one no longer opens it'
  else
    fail 'the CA key exists, but there is no ca.pass beside it and INNSEGL_FULCIO_CA_PASSWORD is not set. Set INNSEGL_FULCIO_CA_PASSWORD once, to the password the key is locked with, and run this again; it is then moved into ca.pass.'
  fi
elif [ -n "${INNSEGL_FULCIO_CA_PASSWORD:-}" ] \
  && [ "$(head -n 1 "${CA_PASS}")" != "${INNSEGL_FULCIO_CA_PASSWORD}" ]; then
  log 'INNSEGL_FULCIO_CA_PASSWORD is set and differs from ca.pass; ca.pass is the password and the variable is ignored. Remove it from .env.'
fi

if [ -s "${CA_KEY}" ] && [ -s "${CA_CRT}" ]; then
  log 'Fulcio CA already present; leaving it alone (make innsegl-ca-rotate is how a CA is replaced)'
else
  log 'generating the Fulcio CA'
  ca_generate "${FULCIO_OUT}" "${CA_PASS}"
  log 'Fulcio CA written'
fi

ca_opens "${CA_KEY}" "file:${CA_PASS}" \
  || fail 'the CA key does not open with ca.pass; nothing was changed. Restore the pair from the trust-key backup.'
# ca.pass itself holding the public default: re-lock, the same as above.
if ca_opens_legacy "${CA_KEY}"; then
  log 'ca.pass is the public default earlier releases shipped; re-locking the key'
  ca_relock "${FULCIO_OUT}" "file:${CA_PASS}"
fi
ca_render_serve_config "${CA_PASS}" "${FULCIO_OUT}/serve.yaml"

# ---------------------------------------------------------------------------
# The transparency log's signing key.
#
# ECDSA P-256 in unencrypted PKCS#8. Unencrypted deliberately: Rekor's file
# signer takes a password, but supplying one here would buy nothing — the
# password would have to sit on Rekor's command line next to the path, so both
# halves would be in the same `docker inspect` output. The control is the same
# one the CA key has: one writer, one reader, mounted read-only, mode 0400.
#
# NEVER REGENERATED once it exists. This is the key ADR-0009's anchor
# verification terminates on; a new one makes every checkpoint signed by the
# old one unverifiable, and the failure appears as a signature mismatch on an
# entry that is demonstrably still in the log.
# ---------------------------------------------------------------------------
if [ -s "${REKOR_OUT}/log.key" ]; then
  log 'Rekor log key already present; leaving it alone (a new one invalidates every anchor issued under the old one — ADR-0009)'
else
  log 'generating the Rekor log signing key'
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "${REKOR_OUT}/log.key"
  log 'Rekor log key written'
fi

# ---------------------------------------------------------------------------
# Fulcio's issuer configuration. Re-rendered every run; see the header.
# ---------------------------------------------------------------------------
log "rendering fulcio config for issuer ${INNSEGL_SPIRE_JWT_ISSUER}"
awk -v placeholder="${PLACEHOLDER}" -v value="${INNSEGL_SPIRE_JWT_ISSUER}" '
  {
    line = $0
    out = ""
    n = length(placeholder)
    while ((i = index(line, placeholder)) > 0) {
      out = out substr(line, 1, i - 1) value
      line = substr(line, i + n)
    }
    print out line
  }
' "${CONFIG_IN}" > "${FULCIO_OUT}/config.yaml"

grep -qF "${INNSEGL_SPIRE_JWT_ISSUER}" "${FULCIO_OUT}/config.yaml" \
  || fail 'the rendered fulcio config does not contain the issuer; substitution failed'
# `if` rather than `&& fail`: under `set -e` a `grep && fail` whose grep finds
# nothing returns 1 from the whole list, and the script would exit non-zero on
# the SUCCESS path.
if grep -qF "${PLACEHOLDER}" "${FULCIO_OUT}/config.yaml"; then
  fail 'the rendered fulcio config still contains an unsubstituted placeholder'
fi

# ---------------------------------------------------------------------------
# Ownership and modes. Certificates are world-readable — they are public by
# construction and Fulcio serves ca.crt to anyone who asks, at
# /api/v1/rootCert. Private keys are 0400 and owned by the uid that must read
# them.
# ---------------------------------------------------------------------------
chmod 0644 "${FULCIO_OUT}/config.yaml"
chmod 0400 "${REKOR_OUT}/log.key"
chown "${RUN_UID}:${RUN_GID}" "${FULCIO_OUT}/config.yaml" "${REKOR_OUT}/log.key"
ca_own "${FULCIO_OUT}"

# ---------------------------------------------------------------------------
# The log database's credentials (ADR-0078).
#
# Three, generated for this host and kept in the trust volume
# sigstore-credentials-store: MySQL's root, Trillian's user and Rekor's index
# user. Each reader gets its own rendered volume:
#   logdb/        trillian-db: the entrypoint's *_PASSWORD_FILE values, the
#                 init file it runs at every start, and two client option
#                 files (its healthcheck; scripts/rekor-reindex.sh)
#   trillian/     the Trillian pair's flag file (--config)
#   rekor-index/  Rekor's config file (--config)
#
# THE INIT FILE IS THE MOVE. MySQL runs it as the superuser at every start,
# so it needs no old password: it sets every user's password from the files.
# On an existing host that is the step from the old public values to this
# host's own; after that it is a no-op. It also removes root@'%', which
# nothing uses; root stays on the container's local socket.
#
# root@localhost is set only once Trillian's user exists. On a first start the
# image runs the init file during its own setup too, before it has set the
# root password itself, and a password set there would lock the image out of
# the rest of its setup.
# ---------------------------------------------------------------------------
if [ -n "${CRED_STORE:-}" ]; then
  CRED_WHO=sigstore-bootstrap
  . "${CRED_LIB}"
  cred_ensure "${CRED_STORE}" logdb-root logdb-trillian logdb-rekor
  for d in "${CRED_RENDER}/logdb" "${CRED_RENDER}/trillian" "${CRED_RENDER}/rekor-index"; do
    [ -d "${d}" ] || fail "${d} is not mounted; sigstore.yml gives this one-shot every per-credential volume"
  done
  [ -r "${REKOR_INDEX_TEMPLATE}" ] || fail "${REKOR_INDEX_TEMPLATE} is not readable; check the bind mount"
  root_pw=$(cred_value "${CRED_STORE}" logdb-root) || exit 1
  trillian_pw=$(cred_value "${CRED_STORE}" logdb-trillian) || exit 1
  rekor_pw=$(cred_value "${CRED_STORE}" logdb-rekor) || exit 1

  printf '%s\n' "${root_pw}" | cred_put "${CRED_RENDER}/logdb/root" 0444
  printf '%s\n' "${trillian_pw}" | cred_put "${CRED_RENDER}/logdb/trillian" 0444
  {
    sed "s/@REKOR_INDEX_PASSWORD@/${rekor_pw}/" "${REKOR_INDEX_TEMPLATE}"
    printf '%s\n' \
      "-- ADR-0078: every user's password from this host's files, at every start." \
      "ALTER USER IF EXISTS '${TRILLIAN_DB_USER}'@'%' IDENTIFIED BY '${trillian_pw}';" \
      "DROP USER IF EXISTS 'root'@'%';" \
      "SET @innsegl_root = IF((SELECT COUNT(*) FROM mysql.user WHERE user = '${TRILLIAN_DB_USER}' AND host = '%') > 0, 'ALTER USER IF EXISTS ''root''@''localhost'' IDENTIFIED BY ''${root_pw}''', 'DO 0');" \
      "PREPARE innsegl_root FROM @innsegl_root;" \
      "EXECUTE innsegl_root;" \
      "DEALLOCATE PREPARE innsegl_root;" \
      "SET @innsegl_root = NULL;" \
      "FLUSH PRIVILEGES;"
  } | cred_put "${CRED_RENDER}/logdb/init.sql" 0444
  grep -q '@REKOR_INDEX_PASSWORD@' "${CRED_RENDER}/logdb/init.sql" \
    && fail 'the rendered init file still holds the placeholder; substitution failed'
  printf '[client]\nuser=%s\npassword=%s\n' "${TRILLIAN_DB_USER}" "${trillian_pw}" \
    | cred_put "${CRED_RENDER}/logdb/healthcheck.cnf" 0444
  printf '[client]\nuser=rekor\npassword=%s\n' "${rekor_pw}" \
    | cred_put "${CRED_RENDER}/logdb/rekor.cnf" 0444

  printf '%s\n' "--mysql_uri=${TRILLIAN_DB_USER}:${trillian_pw}@tcp(trillian-db:3306)/${TRILLIAN_DB_NAME}" \
    | cred_put "${CRED_RENDER}/trillian/flags" 0444
  printf 'search_index:\n  mysql:\n    dsn: rekor:%s@tcp(trillian-db:3306)/rekor_index\n' "${rekor_pw}" \
    | cred_put "${CRED_RENDER}/rekor-index/rekor-server.yaml" 0444
  root_pw=''; trillian_pw=''; rekor_pw=''
  log "the log database's credentials are in the trust volume and rendered for their readers"
fi

log 'ready'
printf 'sigstore-bootstrap: Fulcio CA subject and validity:\n'
openssl x509 -in "${FULCIO_OUT}/ca.crt" -noout -subject -dates -ext basicConstraints,keyUsage,extendedKeyUsage
printf 'sigstore-bootstrap: Rekor log public key (this is what an anchor is verified under — ADR-0009):\n'
openssl pkey -in "${REKOR_OUT}/log.key" -pubout
