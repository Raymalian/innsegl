#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end proof that the reference Sigstore compose stack does the one thing
# it exists for (RM-030, #38).
#
# A compose file that has never been booted is a guess. spire/verify.sh makes
# that argument for the SPIRE trio; this is its other half, and between them
# they walk the whole of doc 01 §1 component 3 up to the point where RM-032's
# gitsign wrapper takes over:
#
#     JWT-SVID (audience-bound to Sigstore)
#       -> SIGSTORE_ID_TOKEN
#         -> Fulcio short-lived certificate           <- this script ends here
#           -> signed commit                          (RM-032, RM-033)
#             -> Rekor                                <- and proves this works
#
# WHAT IT ACTUALLY CHECKS, IN ORDER
#
#   1. Both halves serve their TRUST MATERIAL, and the bytes parse as that
#      material. This is ADR-0024's definition of "Sigstore is reachable",
#      used here so the compose stack's readiness and the MCP's health report
#      mean the same thing: Fulcio's /api/v1/rootCert must decode as a PEM CA
#      certificate, Rekor's /api/v1/log/publicKey as a PKIX public key. A TCP
#      dial would pass against any listening socket.
#
#   2. A REAL registration entry, a REAL JWT-SVID. The entry is registered
#      the way register_agent registers it, with the one run selector
#      innsegl:run:<run_id> (ADR-0053), and the token is minted the way
#      get_credential mints it: MintJWTSVID on the SPIRE server, audience
#      `sigstore`. No workload attestation is involved, because none is
#      involved for a real run either. Nothing here is a fixture; doc 01 §2 —
#      "a mocked Fulcio proves nothing about I5" — cuts the same way against a
#      mocked SVID.
#
#   3. A REAL certificate from Fulcio, and the assertion that matters: the URI
#      SAN is exactly the SPIFFE ID of the run. That URI SAN is what makes a
#      commit attributable to one agent run rather than to a machine or a
#      workflow. It is the whole of I1 and half of I5.
#
#   4. A REAL Rekor round trip ending in an INCLUSION PROOF. This is here to
#      carry RM-012's most expensive finding into something executable: without
#      the Trillian log signer, leaves are queued and never integrated, so the
#      entry is accepted and the proof never arrives. That failure looks like
#      slowness. Polling for the proof, with a deadline, is what turns it back
#      into a failure with a name.
#
#   5. Retirement. The registration entry is deleted on every exit path,
#      including failure — an orphaned entry outliving its run is what RM-017's
#      reaper exists to catch, and this script should not be manufacturing work
#      for it.
#
# Exit status is the verdict.
#
# Two settings, for scripts/ca-rotate.sh's proof step (#533):
#   INNSEGL_SIGSTORE_VERIFY_ROOT=<pem>  the certificate must chain to this
#                                       root, and Fulcio must publish it
#   INNSEGL_SIGSTORE_VERIFY_CERT_ONLY=1 stop after the certificate; write
#                                       nothing to the transparency log
#
# WHAT THIS SCRIPT IS NOT. It is not TC-SIG and it must not become it. SIG-001
# is a signed *commit* verified through the shipped tooling, and it belongs to
# E5's Go tests against this stack. This is the infrastructure check that has
# to pass before those tests have anything to run against.

set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly COMPOSE_DIR="${SCRIPT_DIR}/.."
readonly SPIRE_COMPOSE="${COMPOSE_DIR}/spire.yml"
# A DEV stack (scripts/stack-mode.sh, ADR-0072) is the same file with
# deploy/compose/dev/spire.yml over it; the Makefile exports INNSEGL_STACK_MODE
# and INNSEGL_STACK_PREFIX for it, and both are unset on a live host.
SPIRE_FILES=(-f "${SPIRE_COMPOSE}")
[ "${INNSEGL_STACK_MODE:-live}" = dev ] && SPIRE_FILES+=(-f "${COMPOSE_DIR}/dev/spire.yml")
readonly SIGSTORE_COMPOSE="${COMPOSE_DIR}/sigstore.yml"

readonly TRUST_DOMAIN="innsegl.dev"
readonly ADMIN_SOCKET="/run/spire/admin/api.sock"

# The audience. A PROTECTED-ADJACENT literal: `sigstore` is the client-id in
# sigstore/fulcio-config.yaml, and a JWT-SVID minted for any other audience is
# refused by Fulcio. The two must agree, so neither is parameterised.
readonly SIGSTORE_AUDIENCE="sigstore"

FULCIO_URL="${INNSEGL_FULCIO_URL:-http://127.0.0.1:${INNSEGL_FULCIO_PORT:-5555}}"
REKOR_URL="${INNSEGL_REKOR_URL:-http://127.0.0.1:${INNSEGL_REKOR_PORT:-23000}}"
JWT_ISSUER="${INNSEGL_SPIRE_JWT_ISSUER:-http://spire-oidc:8080}"
export INNSEGL_SPIRE_JWT_ISSUER="${JWT_ISSUER}"

# The run being registered. Overridable so the script can be pointed at a
# second run without editing it.
AGENT_TYPE="${INNSEGL_DEMO_AGENT_TYPE:-demo}"
TASK_ID="${INNSEGL_DEMO_TASK_ID:-rm-030}"
RUN_ID="${INNSEGL_DEMO_RUN_ID:-run-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
export INNSEGL_DEMO_AGENT_TYPE="${AGENT_TYPE}"
export INNSEGL_DEMO_TASK_ID="${TASK_ID}"
export INNSEGL_DEMO_RUN_ID="${RUN_ID}"

readonly EXPECTED_ID="spiffe://${TRUST_DOMAIN}/agent/${AGENT_TYPE}/${TASK_ID}/${RUN_ID}"

log()  { printf '\nsigstore-verify: %s\n' "$*"; }
note() { printf '  %s\n' "$*"; }
fail() { printf 'sigstore-verify: FAIL: %s\n' "$*" >&2; exit 1; }

spire_compose() { docker compose "${SPIRE_FILES[@]}" "$@"; }
spire() { spire_compose exec -T spire-server /opt/spire/bin/spire-server "$@" -socketPath "${ADMIN_SOCKET}"; }

WORK=""
ENTRY_ID=""
cleanup() {
  if [ -n "${ENTRY_ID}" ]; then
    printf '\nsigstore-verify: retiring — deleting entry %s\n' "${ENTRY_ID}"
    spire entry delete -entryID "${ENTRY_ID}" >/dev/null 2>&1 || true
    ENTRY_ID=""
  fi
  [ -n "${WORK}" ] && rm -rf "${WORK}"
  return 0
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Small helpers. No jq: this script has to run on a fresh clone (OPS-004), and
# the only tools it may assume are the ones docker, curl and openssl bring.
# ---------------------------------------------------------------------------

# json_string_field <json> <key> — first string value for a top-level-ish key.
json_string_field() {
  printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -n 1
}

# pem_as_json_string <file> — PEM with real newlines turned into the two
# characters backslash-n, so it can be pasted into a JSON string literal.
pem_as_json_string() { awk '{ printf "%s\\n", $0 }' "$1"; }

# unescape_json_pem — the inverse, for reading a certificate back out of a
# response. awk rather than `sed 's/\\n/\n/'` because the BSD sed on macOS does
# not expand \n in a replacement and would emit a literal `n`.
unescape_json_pem() { awk '{ gsub(/\\n/, "\n"); print }'; }

# cert_extension <file> <heading> — print the lines of one X.509 extension.
#
# MEASURED: macOS ships LibreSSL (3.3.6 on the machine this was written on),
# whose `x509` has no `-ext` flag at all — it exits 1 with a usage dump. A
# script that used `-ext` would fail on a fresh Mac clone (OPS-004 is "on a
# clean machine") while passing in CI on GNU OpenSSL. `-text` plus grep is the
# portable spelling and is what this file uses everywhere.
cert_extension() {
  openssl x509 -in "$1" -noout -text 2>/dev/null \
    | awk -v want="$2" '
        index($0, want) > 0 { grabbing = 1; print; next }
        grabbing && /^ +[A-Za-z0-9]/ && !/^ {16}/ { grabbing = 0 }
        grabbing { print }
      '
}

# jwt_claim <token> <claim> — decode the payload and read one string claim.
jwt_claim() {
  local payload
  payload="$(printf '%s' "$1" | cut -d. -f2 | tr '_-' '/+')"
  case $(( ${#payload} % 4 )) in
    2) payload="${payload}==" ;;
    3) payload="${payload}=" ;;
  esac
  printf '%s' "${payload}" | openssl base64 -d -A 2>/dev/null \
    | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -n 1
}

# ---------------------------------------------------------------------------
# Step 1 — trust material (ADR-0024).
# ---------------------------------------------------------------------------
check_trust_material() {
  log 'checking that both halves serve parseable trust material (ADR-0024)'

  local root_pem
  root_pem="$(curl -sS --max-time 15 "${FULCIO_URL}/api/v1/rootCert" 2>&1)" \
    || fail "Fulcio ${FULCIO_URL} is not answering: ${root_pem}"
  printf '%s\n' "${root_pem}" > "${WORK}/fulcio-root.pem"
  openssl x509 -in "${WORK}/fulcio-root.pem" -noout >/dev/null 2>&1 \
    || fail "Fulcio's /api/v1/rootCert did not return a parseable certificate"
  # "must decode as a PEM CA certificate" — the CA part is the half a status
  # check would miss.
  cert_extension "${WORK}/fulcio-root.pem" 'X509v3 Basic Constraints' \
    | grep -q 'CA:TRUE' \
    || fail "Fulcio's root certificate is not a CA certificate"
  note "fulcio  $(openssl x509 -in "${WORK}/fulcio-root.pem" -noout -subject)"

  local log_pub
  log_pub="$(curl -sS --max-time 15 "${REKOR_URL}/api/v1/log/publicKey" 2>&1)" \
    || fail "Rekor ${REKOR_URL} is not answering: ${log_pub}"
  printf '%s\n' "${log_pub}" > "${WORK}/rekor-pub.pem"
  openssl pkey -pubin -in "${WORK}/rekor-pub.pem" -noout >/dev/null 2>&1 \
    || fail "Rekor's /api/v1/log/publicKey did not return a parseable public key"
  # grep -E, not `sed 's/\(a\|b\)/'`: BSD sed has no BRE alternation, so the
  # GNU spelling silently matches nothing and prints an empty line.
  note "rekor   log key: $(openssl pkey -pubin -in "${WORK}/rekor-pub.pem" -noout -text 2>/dev/null \
    | grep -E 'Public-Key|ASN1 OID|NIST CURVE' | sed 's/^ *//;s/ *$//' | tr '\n' ',' | sed 's/,$//;s/,/, /g')"
}

# ---------------------------------------------------------------------------
# Step 2 — a real registration entry and a real JWT-SVID.
#
# This script must exercise the identity path a run actually takes, not an
# easier one of its own. Since ADR-0053 that path is: register_agent creates
# the run's entry with one selector no workload attestor emits, and
# get_credential mints the JWT-SVID through the SPIRE server's MintJWTSVID.
# No workload is ever issued a run's identity by attestation.
#
# So this script does the same two things. `spire-server jwt mint` on the
# local admin socket is that same MintJWTSVID RPC, signed by the same server
# key and stamped with the same issuer. The MCP reaches the RPC over the admin
# API with its own SVID; this script reaches it the way an operator does
# (ADR-0011). Until ADR-0053 this step had the verify workload attest on a
# run's docker labels. That tested a path no run used, and the MCP's start-up
# rewrite would now move such an entry off its labels mid-run.
# ---------------------------------------------------------------------------
mint_jwt_svid() {
  log "registering run ${RUN_ID} and minting a JWT-SVID for audience '${SIGSTORE_AUDIENCE}'"

  local parent out
  parent="$(spire agent list 2>/dev/null | sed -n 's/^SPIFFE ID *: *//p' | head -n 1 || true)"
  [ -n "${parent}" ] || fail 'no attested SPIRE agent — bring the SPIRE stack up first (make sigstore-up)'

  note "spiffe id : ${EXPECTED_ID}"
  note "parent    : ${parent}"

  out="$(spire entry create \
    -parentID "${parent}" \
    -spiffeID "${EXPECTED_ID}" \
    -selector "innsegl:run:${RUN_ID}" \
    -x509SVIDTTL 300 \
    -jwtSVIDTTL 300)"
  ENTRY_ID="$(printf '%s\n' "${out}" | sed -n 's/^Entry ID *: *//p' | head -n 1)"
  [ -n "${ENTRY_ID}" ] || { printf '%s\n' "${out}"; fail 'entry create returned no entry ID'; }
  note "entry id  : ${ENTRY_ID}"

  # The mint is answered by the server directly, not through an agent cache,
  # so there is nothing to poll for. TTL 300s, the entry's own. stderr stays on
  # the terminal rather than in ${out}: only the token belongs there, and a
  # dotted string in a warning must not be read as one.
  out="$(spire jwt mint \
    -spiffeID "${EXPECTED_ID}" \
    -audience "${SIGSTORE_AUDIENCE}" \
    -ttl 300s)" || fail 'MintJWTSVID refused (the CLI printed why, above)'

  # Read the token out of whatever the CLI wraps it in.
  TOKEN="$(printf '%s\n' "${out}" | tr -d '\r' | grep -oE '[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' | head -n 1)"
  [ -n "${TOKEN}" ] || { printf '%s\n' "${out}"; fail 'could not find a JWT in the jwt mint output'; }

  local tok_sub tok_iss
  tok_sub="$(jwt_claim "${TOKEN}" sub)"
  tok_iss="$(jwt_claim "${TOKEN}" iss)"
  note "token sub : ${tok_sub}"
  note "token iss : ${tok_iss}"

  [ "${tok_sub}" = "${EXPECTED_ID}" ] \
    || fail "JWT-SVID subject ${tok_sub} is not the run's SPIFFE ID ${EXPECTED_ID}"
  # The check that catches the single most likely misconfiguration in this
  # stack: SPIRE and Fulcio disagreeing about who the issuer is. Fulcio would
  # answer `invalid identity token` with no hint which of the three copies of
  # this string moved.
  [ "${tok_iss}" = "${JWT_ISSUER}" ] \
    || fail "JWT-SVID issuer ${tok_iss} != the issuer Fulcio is configured for (${JWT_ISSUER}); the two stacks were brought up with different INNSEGL_SPIRE_JWT_ISSUER values"
}

# ---------------------------------------------------------------------------
# Step 3 — a real certificate from Fulcio.
#
# The v2 API takes the token plus a public key and a PROOF OF POSSESSION: a
# signature over the token's subject claim, which for a `spiffe` issuer is the
# SPIFFE ID itself. That is what stops a leaked token being exchanged by
# somebody who does not hold the key the certificate will bind to.
# ---------------------------------------------------------------------------
obtain_certificate() {
  log 'exchanging the JWT-SVID for a Fulcio certificate'

  openssl ecparam -name prime256v1 -genkey -noout -out "${WORK}/signing.key" 2>/dev/null
  openssl ec -in "${WORK}/signing.key" -pubout -out "${WORK}/signing.pub" 2>/dev/null

  # Proof of possession: ECDSA-SHA256 over the exact bytes of the subject, with
  # no trailing newline. `printf %s`, never `echo`.
  printf '%s' "${EXPECTED_ID}" > "${WORK}/challenge.txt"
  openssl dgst -sha256 -sign "${WORK}/signing.key" -out "${WORK}/pop.sig" "${WORK}/challenge.txt"
  local pop
  pop="$(openssl base64 -A -in "${WORK}/pop.sig")"

  {
    printf '{"credentials":{"oidcIdentityToken":"%s"},' "${TOKEN}"
    printf '"publicKeyRequest":{"publicKey":{"algorithm":"ECDSA","content":"%s"},' \
      "$(pem_as_json_string "${WORK}/signing.pub")"
    printf '"proofOfPossession":"%s"}}' "${pop}"
  } > "${WORK}/req.json"

  local status body
  status="$(curl -sS --max-time 30 -o "${WORK}/resp.json" -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    --data-binary "@${WORK}/req.json" \
    "${FULCIO_URL}/api/v2/signingCert")" || fail 'the request to Fulcio failed'
  body="$(cat "${WORK}/resp.json")"
  [ "${status}" = "200" ] || fail "Fulcio returned HTTP ${status}: ${body}"

  printf '%s' "${body}" \
    | sed -n 's/.*"certificates":\[[[:space:]]*"\([^"]*\)".*/\1/p' \
    | unescape_json_pem > "${WORK}/leaf.pem"
  [ -s "${WORK}/leaf.pem" ] || fail "no certificate in Fulcio's response: ${body}"

  note "HTTP ${status}, ${#body} bytes"
}

# ---------------------------------------------------------------------------
# Step 4 — the assertions on that certificate, and then show it.
# ---------------------------------------------------------------------------
check_certificate() {
  log 'checking the certificate'

  local san
  san="$(cert_extension "${WORK}/leaf.pem" 'X509v3 Subject Alternative Name' \
    | tr ', ' '\n\n' | sed -n 's/^URI:\(spiffe:.*\)$/\1/p' | head -n 1)"
  [ -n "${san}" ] || fail 'the certificate carries no SPIFFE URI SAN'
  [ "${san}" = "${EXPECTED_ID}" ] \
    || fail "URI SAN ${san} != ${EXPECTED_ID}"
  note "URI SAN matches the run's SPIFFE ID: ${san}"

  # It must chain to the root Fulcio publishes, or "Fulcio issued it" is an
  # assumption rather than an observation. -purpose any: these are code-signing
  # certificates and openssl's default purpose check would reject them for the
  # wrong reason.
  openssl verify -CAfile "${WORK}/fulcio-root.pem" -purpose any "${WORK}/leaf.pem" \
    || fail 'the certificate does not chain to the root Fulcio publishes'

  printf '\n'
  openssl x509 -in "${WORK}/leaf.pem" -noout -serial -subject -issuer -dates
  cert_extension "${WORK}/leaf.pem" 'X509v3 Subject Alternative Name'
  cert_extension "${WORK}/leaf.pem" 'X509v3 Key Usage'
  cert_extension "${WORK}/leaf.pem" 'X509v3 Extended Key Usage'
  # The Fulcio extension OIDs under 1.3.6.1.4.1.57264.1 that
  # pkg/identity/spiffe renders — .1 OIDIssuer (deprecated), .8 OIDIssuerV2,
  # .24 OIDTokenSubject. RM-032 and RM-037 read these back, and doc 01 §6.7's
  # trailer-to-certificate match is against .24 and the URI SAN. Note also
  # what is NOT here: the subject DN is empty, by design — the identity is the
  # SAN, not a distinguished name.
  openssl x509 -in "${WORK}/leaf.pem" -noout -text 2>/dev/null \
    | grep -A1 '1\.3\.6\.1\.4\.1\.57264' | sed 's/^ */    /'
  printf '\n'
  cat "${WORK}/leaf.pem"
}

# ---------------------------------------------------------------------------
# Step 5 — a real Rekor round trip, ending in an inclusion proof.
#
# RM-012's finding, made executable. See this file's header and the
# trillian-log-signer service in sigstore.yml.
# ---------------------------------------------------------------------------
check_rekor_round_trip() {
  log 'submitting a hashedrekord entry and waiting for an inclusion proof'

  printf 'innsegl RM-030 compose verification %s' "${RUN_ID}" > "${WORK}/payload.bin"
  local digest
  digest="$(openssl dgst -sha256 "${WORK}/payload.bin" | awk '{print $NF}')"
  openssl dgst -sha256 -sign "${WORK}/signing.key" -out "${WORK}/payload.sig" "${WORK}/payload.bin"

  {
    printf '{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{'
    printf '"data":{"hash":{"algorithm":"sha256","value":"%s"}},' "${digest}"
    printf '"signature":{"content":"%s","publicKey":{"content":"%s"}}}}' \
      "$(openssl base64 -A -in "${WORK}/payload.sig")" \
      "$(openssl base64 -A -in "${WORK}/signing.pub")"
  } > "${WORK}/rekor-req.json"

  local status body uuid
  status="$(curl -sS --max-time 30 -o "${WORK}/rekor-resp.json" -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    --data-binary "@${WORK}/rekor-req.json" \
    "${REKOR_URL}/api/v1/log/entries")" || fail 'the request to Rekor failed'
  body="$(cat "${WORK}/rekor-resp.json")"
  [ "${status}" = "201" ] || fail "Rekor returned HTTP ${status}: ${body}"

  uuid="$(printf '%s' "${body}" | sed -n 's/^{"\([0-9a-f]\{1,\}\)".*/\1/p' | head -n 1)"
  [ -n "${uuid}" ] || fail "could not read the entry uuid from Rekor's response: ${body}"
  note "entry uuid : ${uuid}"
  note "log index  : $(printf '%s' "${body}" | sed -n 's/.*"logIndex":\([0-9]*\).*/\1/p' | head -n 1)"

  # THE CHECK THAT NEEDS THE LOG SIGNER. Without trillian-log-signer this loop
  # runs to its deadline and fails saying so, rather than the stack appearing
  # merely slow.
  local attempt entry
  attempt=0
  while :; do
    attempt=$((attempt + 1))
    entry="$(curl -sS --max-time 15 "${REKOR_URL}/api/v1/log/entries/${uuid}" 2>&1 || true)"
    if printf '%s' "${entry}" | grep -q '"inclusionProof"'; then
      break
    fi
    [ "${attempt}" -lt 30 ] || fail \
      'no inclusion proof after 30 attempts. The leaf was accepted and never integrated, which is what happens when trillian-log-signer is not running (RM-012).'
    sleep 2
  done

  note "inclusion proof present after ${attempt} poll(s)"
  note "tree size  : $(printf '%s' "${entry}" | sed -n 's/.*"treeSize":\([0-9]*\).*/\1/p' | head -n 1)"
  note "root hash  : $(json_string_field "${entry}" rootHash)"
  printf '\n'
  printf '%s' "${entry}" | sed -n 's/.*"checkpoint":"\([^"]*\)".*/\1/p' | unescape_json_pem
}

main() {
  command -v docker  >/dev/null 2>&1 || fail 'docker is not on PATH'
  command -v curl    >/dev/null 2>&1 || fail 'curl is not on PATH'
  command -v openssl >/dev/null 2>&1 || fail 'openssl is not on PATH'

  WORK="$(mktemp -d)"

  printf 'sigstore-verify: fulcio %s\n' "${FULCIO_URL}"
  printf 'sigstore-verify: rekor  %s\n' "${REKOR_URL}"
  printf 'sigstore-verify: issuer %s\n' "${JWT_ISSUER}"

  check_trust_material
  mint_jwt_svid
  obtain_certificate
  check_certificate
  check_expected_root

  # The rotation's proof (scripts/ca-rotate.sh) stops at the certificate: it
  # proves the NEW root issues, and a test entry in a deployment's own log is
  # an entry that stays there forever.
  if [ -n "${INNSEGL_SIGSTORE_VERIFY_CERT_ONLY:-}" ]; then
    log 'OK — a real Fulcio certificate was issued for a real JWT-SVID (certificate only; Rekor not written to)'
    return 0
  fi
  check_rekor_round_trip

  log 'OK — a real Fulcio certificate was issued for a real JWT-SVID, and a real Rekor entry was proved included'
}

# check_expected_root: with INNSEGL_SIGSTORE_VERIFY_ROOT naming a PEM file,
# the certificate must chain to THAT root, and it must be the root Fulcio
# publishes. scripts/ca-rotate.sh passes the root it just staged, so a Fulcio
# that came back up on the old key fails here rather than passing on "some
# root".
check_expected_root() {
  local want="${INNSEGL_SIGSTORE_VERIFY_ROOT:-}"
  [ -n "${want}" ] || return 0
  log "checking the certificate chains to the expected root ${want}"
  [ -r "${want}" ] || fail "INNSEGL_SIGSTORE_VERIFY_ROOT=${want} is not readable"
  openssl verify -CAfile "${want}" -purpose any "${WORK}/leaf.pem" \
    || fail 'the certificate does not chain to the expected root'
  local a b
  a="$(openssl x509 -in "${want}" -outform DER | openssl dgst -sha256 | awk '{print $NF}')"
  b="$(openssl x509 -in "${WORK}/fulcio-root.pem" -outform DER | openssl dgst -sha256 | awk '{print $NF}')"
  [ "${a}" = "${b}" ] || fail "Fulcio publishes root ${b}, not the expected ${a}"
  note "the expected root ${a} issued it and is the one Fulcio publishes"
}

main "$@"
