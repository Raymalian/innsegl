#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Bootstrap PKI for the reference SPIRE compose stack (RM-014, #22).
#
# WHY THIS EXISTS
# ---------------
# A SPIRE agent has to prove *what node it is* before the server will issue it
# an agent SVID, and it has to know the server's trust bundle before it will
# talk to the server at all. Both are out-of-band inputs. In compose there are
# three ways to supply them and only one of them is defensible:
#
#   1. `insecure_bootstrap = true` on the agent. The agent accepts whatever
#      bundle the server hands it on first contact. That is trust-on-first-use
#      against a spoofed server — the exact spoofing case doc 04 "SPIRE
#      deployment" says node attestation is the control for. Rejected.
#
#   2. A join token. The token has to be minted by `spire-server token
#      generate` *after* the server is up and then handed to the agent, which
#      in compose means an interactive `docker exec` — so `docker compose up`
#      alone would not produce a working stack. A join token is also a bearer
#      secret, single-use, and an agent that loses its data directory can never
#      re-attest with it. Rejected.
#
#   3. Pre-provisioned X.509 node identity (`x509pop`). The agent proves
#      possession of a private key against a CA the server trusts. It is
#      reproducible, survives restarts, needs no interactive step, and is a
#      real cryptographic proof rather than a shared secret. Chosen.
#
# The same reasoning gives the server an UpstreamAuthority "disk" root: with a
# known upstream root the agent's `trust_bundle_path` is a file this script
# already wrote, so nothing has to be scraped out of a running server. It also
# mirrors production, where doc 05 §2 puts the upstream signing CA in a
# KMS/HSM — compose keeps it on disk the same way it keeps the datastore in
# SQLite, and for the same reason: this is a reference stack, not a deployment.
#
# THREE SEPARATE KEYS, THREE SEPARATE BLAST RADII
# -----------------------------------------------
#   upstream-ca.key  signs the SPIRE server's own X.509 CA. Compromise = mint
#                    any identity in the trust domain (threat model A1). Only
#                    spire-server ever sees it.
#   node-ca.key      signs node identity certs. Compromise = attest a rogue
#                    node. Only this bootstrapper ever sees it; the server
#                    needs the *certificate* to verify, never the key.
#   agent.key        one node's identity. Only spire-agent ever sees it.
#
# They are written to two volumes so the split is enforced by the mount table
# and not by convention: spire-server mounts the server PKI read-only and never
# sees agent.key; spire-agent mounts the agent PKI read-only and never sees
# either CA key. See the `volumes:` block of spire.yml.
#
# IDEMPOTENT. Re-running must not rotate the PKI: the agent's SPIFFE ID is
# derived from its certificate fingerprint, so a rotation would silently orphan
# every registration entry parented to the old agent ID.

set -eu

SERVER_PKI=/out/server
AGENT_PKI=/out/agent

# The server image runs as 1000:1000 (`docker inspect ghcr.io/spiffe/
# spire-server:1.15.3`). Docker creates a fresh named volume root-owned, so the
# files it must read and the directories it must write are chowned here rather
# than by dropping the server to root.
SERVER_UID=1000
SERVER_GID=1000

# 10 years. These are compose-only development credentials whose whole
# lifecycle is `docker compose down -v`; a short lifetime would buy nothing and
# would break long-lived local stacks in a way that looks like a SPIRE bug.
DAYS=3650

log() { printf 'bootstrap: %s\n' "$*"; }

if [ -s "$SERVER_PKI/upstream-ca.key" ] && [ -s "$AGENT_PKI/agent.key" ]; then
  log 'PKI already present; leaving it alone (rotating it would orphan every entry)'
else
  log 'generating the compose PKI'
  mkdir -p "$SERVER_PKI" "$AGENT_PKI"
  work=$(mktemp -d)

  # --- upstream CA: the root of the trust domain -------------------------
  # P-256 throughout: SPIRE's default signing algorithm, and the disk
  # UpstreamAuthority accepts EC keys in ASN.1 or PKCS#8.
  openssl ecparam -name prime256v1 -genkey -noout -out "$work/upstream-ca.key"
  openssl req -x509 -new -key "$work/upstream-ca.key" -sha256 -days "$DAYS" \
    -subj '/O=Innsegl/CN=innsegl.dev SPIRE upstream CA (compose)' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -out "$work/upstream-ca.crt"

  # --- node CA: the x509pop trust root -----------------------------------
  # Deliberately NOT the upstream CA. A node identity cert and the trust
  # domain's signing root are different authorities with different blast
  # radii; collapsing them would mean anything that can attest as a node is
  # one step from the root of the whole trust domain.
  openssl ecparam -name prime256v1 -genkey -noout -out "$work/node-ca.key"
  openssl req -x509 -new -key "$work/node-ca.key" -sha256 -days "$DAYS" \
    -subj '/O=Innsegl/CN=innsegl.dev SPIRE node CA (compose)' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -out "$work/node-ca.crt"

  # --- the agent's node identity -----------------------------------------
  # x509pop requires digitalSignature in KeyUsage: the server issues a
  # signature challenge and the agent has to sign it, which is what makes this
  # proof-of-possession rather than proof-of-holding-a-file.
  openssl ecparam -name prime256v1 -genkey -noout -out "$work/agent.key"
  openssl req -new -key "$work/agent.key" \
    -subj '/O=Innsegl/CN=spire-agent.innsegl-spire.compose' \
    -out "$work/agent.csr"
  cat >"$work/agent.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EXT
  openssl x509 -req -in "$work/agent.csr" -sha256 -days "$DAYS" \
    -CA "$work/node-ca.crt" -CAkey "$work/node-ca.key" -CAcreateserial \
    -extfile "$work/agent.ext" -out "$work/agent.crt"

  # --- place the material, split by blast radius -------------------------
  cp "$work/upstream-ca.crt" "$work/upstream-ca.key" "$work/node-ca.crt" "$SERVER_PKI/"
  cp "$work/agent.crt" "$work/agent.key" "$AGENT_PKI/"
  # The agent's bootstrap trust bundle. With a disk UpstreamAuthority acting as
  # a root CA, the trust domain's X.509 root *is* the upstream CA certificate,
  # so the agent can be given it up front and `insecure_bootstrap` stays off.
  cp "$work/upstream-ca.crt" "$AGENT_PKI/trust-bundle.crt"

  rm -rf "$work"
  log 'PKI written'
fi

# Private keys are 0600; certificates are world-readable (they are public by
# construction and the agent's own cert is handed to the server on every
# attestation anyway).
chmod 0644 "$SERVER_PKI"/*.crt "$AGENT_PKI"/*.crt
chmod 0600 "$SERVER_PKI"/upstream-ca.key "$AGENT_PKI"/agent.key
chown -R "$SERVER_UID:$SERVER_GID" "$SERVER_PKI"

# The server's data directory arrives as an empty root-owned volume. Chown it
# here so spire-server keeps running as the unprivileged user its image ships
# with, rather than being dropped to root to work around a mount permission.
# (The admin-socket directory needs no equivalent: it is a tmpfs created with
# the right ownership by the container runtime — see spire.yml.)
for d in /out/server-data; do
  [ -d "$d" ] || continue
  chown "$SERVER_UID:$SERVER_GID" "$d"
  chmod 0700 "$d"
done

log 'ready'
printf 'bootstrap: agent node identity SHA1 fingerprint (this is the agent SPIFFE ID suffix):\n'
openssl x509 -in "$AGENT_PKI/agent.crt" -noout -fingerprint -sha1
