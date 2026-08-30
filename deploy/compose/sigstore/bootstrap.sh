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
# IDEMPOTENT, AND ASYMMETRICALLY SO. The keys are generated once and then left
# alone forever — `docker compose down -v` is the only way to rotate them, and
# that is deliberate. The config is re-rendered on every run, because the
# issuer is the one input an operator legitimately changes and a stale rendered
# copy would mean Fulcio silently disagreeing with SPIRE about who the issuer
# is.

set -eu

FULCIO_OUT=/out/fulcio
REKOR_OUT=/out/rekor
CONFIG_IN=/in/fulcio-config.yaml

# Both Sigstore images run as uid 65532 (`docker inspect ghcr.io/sigstore/
# fulcio`, `.../rekor-server`). Docker creates a fresh named volume root-owned,
# so what those two must read is chowned here rather than by running them as
# root.
RUN_UID=65532
RUN_GID=65532

# 10 years. These are compose credentials whose entire lifecycle is
# `docker compose down -v`; a short lifetime would buy nothing and would break
# long-lived local stacks in a way that looks like a Sigstore bug. Note this is
# the *CA's* lifetime — the certificates it issues are ten minutes long,
# because Fulcio hard-codes that and short-lived certificates are the whole
# point of the design.
DAYS=3650

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
[ -n "${INNSEGL_FULCIO_CA_PASSWORD:-}" ] \
  || fail 'INNSEGL_FULCIO_CA_PASSWORD is empty; fileca requires an encrypted key'
[ -r "${CONFIG_IN}" ] || fail "${CONFIG_IN} is not readable; check the bind mount"

mkdir -p "${FULCIO_OUT}" "${REKOR_OUT}"

# ---------------------------------------------------------------------------
# The Fulcio CA.
#
# ECDSA P-256, matching spire/bootstrap.sh's choice throughout and Fulcio's own
# ephemeral CA. Fulcio runs the loaded key through sigstore's `goodkey`
# validator, which accepts P-256/384/521 and RSA 2048-4096; P-256 is the one
# every part of this stack already speaks.
#
# The three extensions are not decoration — Fulcio's ca.VerifyCertChain checks
# all of them at startup and refuses to serve if any is missing:
#   basicConstraints CA:TRUE    "certificate is not a CA"
#   keyUsage keyCertSign        needed to sign the leaves it will issue
#   extendedKeyUsage codeSigning
#                               VerifyCertChain calls x509.Verify with
#                               KeyUsages=[CodeSigning]; without it the root
#                               fails to verify against itself.
#
# The key is written as an ENCRYPTED PKCS#8 blob because that is what `fileca`
# expects (sigstore/pkg/cryptoutils handles "ENCRYPTED PRIVATE KEY"). See the
# password's comment in sigstore.yml for what that encryption is and is not
# protecting.
# ---------------------------------------------------------------------------
if [ -s "${FULCIO_OUT}/ca.key" ] && [ -s "${FULCIO_OUT}/ca.crt" ]; then
  log 'Fulcio CA already present; leaving it alone (rotating it would invalidate every certificate issued so far)'
else
  log 'generating the Fulcio CA'
  work=$(mktemp -d)
  openssl ecparam -name prime256v1 -genkey -noout -out "${work}/ca.plain.key"
  openssl req -x509 -new -key "${work}/ca.plain.key" -sha256 -days "${DAYS}" \
    -subj '/O=Innsegl/CN=innsegl.dev Fulcio CA (compose)' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -addext 'extendedKeyUsage=codeSigning' \
    -out "${work}/ca.crt"
  # -v2 aes-256-cbc: PBES2/PBKDF2-HMAC-SHA256, which is what Fulcio's PKCS#8
  # reader understands. The legacy PBE algorithms it would otherwise pick are
  # not accepted there.
  INNSEGL_FULCIO_CA_PASSWORD="${INNSEGL_FULCIO_CA_PASSWORD}" \
    openssl pkcs8 -topk8 -v2 aes-256-cbc \
      -in "${work}/ca.plain.key" -out "${work}/ca.key" \
      -passout env:INNSEGL_FULCIO_CA_PASSWORD
  mv "${work}/ca.crt" "${FULCIO_OUT}/ca.crt"
  mv "${work}/ca.key" "${FULCIO_OUT}/ca.key"
  rm -rf "${work}"
  log 'Fulcio CA written'
fi

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
chmod 0644 "${FULCIO_OUT}/ca.crt" "${FULCIO_OUT}/config.yaml"
chmod 0400 "${FULCIO_OUT}/ca.key" "${REKOR_OUT}/log.key"
chown "${RUN_UID}:${RUN_GID}" \
  "${FULCIO_OUT}/ca.crt" "${FULCIO_OUT}/ca.key" "${FULCIO_OUT}/config.yaml" \
  "${REKOR_OUT}/log.key"

log 'ready'
printf 'sigstore-bootstrap: Fulcio CA subject and validity:\n'
openssl x509 -in "${FULCIO_OUT}/ca.crt" -noout -subject -dates -ext basicConstraints,keyUsage,extendedKeyUsage
printf 'sigstore-bootstrap: Rekor log public key (this is what an anchor is verified under — ADR-0009):\n'
openssl pkey -in "${REKOR_OUT}/log.key" -pubout
