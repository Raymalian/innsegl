# SPDX-License-Identifier: Apache-2.0
#
# The Fulcio CA's key and password, as functions (#533, ADR-0075).
#
# Sourced, never run. Two callers, so the CA is made one way:
#   bootstrap.sh          the first CA, and moving an existing host onto a
#                         password of its own;
#   ca-rotate-volume.sh   the next CA, during `make innsegl-ca-rotate`.
# Both run in the pinned openssl image, as root, with /tmp on tmpfs: a key in
# the clear only ever touches memory.
#
# The caller defines log() and fail().
#
# THE FILES, in the Fulcio CA's trust volume:
#   ca.crt       the root. Public.
#   ca.key       the CA key, encrypted PKCS#8 (PBES2, AES-256-CBC).
#   ca.pass      the key's password: 32 bytes from openssl's CSPRNG, as hex,
#                generated on this host. Read by the bootstrap and the
#                rotation, never by Fulcio.
#   serve.yaml   Fulcio's own config file, holding the same password as
#                `fileca-key-passwd`. Fulcio reads it with `--config`, so the
#                password is in no compose file, no command line and no
#                `docker inspect`. Re-rendered from ca.pass on every run.
#
# The Fulcio and openssl images are not the same image: Fulcio's is
# distroless, with no shell to read a file and exec with it. Fulcio's config
# file is the one way to hand it a password that is not an argument.

# The password the reference stack shipped as a default before #533. It is
# public, so a key that opens with it is treated as unlocked: the bootstrap
# re-locks it with a generated password, and never adopts this one.
CA_LEGACY_PUBLIC_PASSWORD='innsegl-compose-ca'
# Exported so openssl can read it as `-passin env:CA_LEGACY_PUBLIC_PASSWORD`
# and it is never an argument. It is public; exporting it reveals nothing.
export CA_LEGACY_PUBLIC_PASSWORD

# Fulcio runs as uid 65532; Docker creates a fresh volume root-owned.
CA_RUN_UID=65532
CA_RUN_GID=65532

# 10 years: the CA's own lifetime. The certificates it issues live ten minutes.
CA_DAYS=3650

# ca_new_password FILE writes a new password to FILE, mode 0400.
ca_new_password() {
  (umask 077 && openssl rand -hex 32 > "$1") || fail "could not generate a password into $1"
  chmod 0400 "$1"
}

# ca_opens KEY PASSIN says whether KEY decrypts with PASSIN, an openssl
# -passin spec (file:PATH or env:NAME).
ca_opens() {
  openssl pkey -in "$1" -passin "$2" -noout >/dev/null 2>&1
}

# ca_opens_legacy KEY says whether KEY decrypts with the old public default.
ca_opens_legacy() {
  ca_opens "$1" env:CA_LEGACY_PUBLIC_PASSWORD
}

# ca_generate DIR PASSFILE makes a new CA in DIR: ca.crt and ca.key, the key
# encrypted with PASSFILE.
#
# ECDSA P-256. The three extensions are what Fulcio's ca.VerifyCertChain
# checks at start-up; without any one of them it refuses to serve:
#   basicConstraints CA:TRUE, keyUsage keyCertSign, extendedKeyUsage
#   codeSigning (x509.Verify is called with KeyUsages=[CodeSigning]).
# -v2 aes-256-cbc is PBES2, which Fulcio's PKCS#8 reader understands; the
# legacy algorithms openssl would pick otherwise are not accepted there.
ca_generate() {
  _dir="$1"; _pass="$2"
  _work="$(mktemp -d)"
  openssl ecparam -name prime256v1 -genkey -noout -out "${_work}/ca.plain.key" \
    || fail 'could not generate the CA key'
  openssl req -x509 -new -key "${_work}/ca.plain.key" -sha256 -days "${CA_DAYS}" \
    -subj '/O=Innsegl/CN=innsegl.dev Fulcio CA (compose)' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -addext 'extendedKeyUsage=codeSigning' \
    -out "${_work}/ca.crt" || fail 'could not make the CA certificate'
  openssl pkcs8 -topk8 -v2 aes-256-cbc \
    -in "${_work}/ca.plain.key" -out "${_work}/ca.key" \
    -passout "file:${_pass}" || fail 'could not encrypt the CA key'
  mv "${_work}/ca.crt" "${_dir}/ca.crt"
  mv "${_work}/ca.key" "${_dir}/ca.key"
  rm -rf "${_work}"
}

# ca_render_serve_config PASSFILE OUT writes Fulcio's config file: the
# password as a YAML single-quoted scalar, in which '' is the only escape.
ca_render_serve_config() {
  _pw="$(head -n 1 "$1")"
  _quoted="$(printf '%s' "${_pw}" | sed "s/'/''/g")"
  (umask 077 && printf "fileca-key-passwd: '%s'\n" "${_quoted}" > "$2.new") \
    || fail "could not write $2"
  mv "$2.new" "$2"
}

# ca_own DIR sets the modes and owner of DIR's CA files that exist. Fulcio
# reads ca.crt and serve.yaml; ca.key and ca.pass are its uid's too, 0400,
# the same reader the key has always had.
ca_own() {
  for _f in ca.crt ca.key ca.pass serve.yaml; do
    [ -e "$1/${_f}" ] || continue
    case "${_f}" in
      ca.crt) chmod 0644 "$1/${_f}" ;;
      *)      chmod 0400 "$1/${_f}" ;;
    esac
    chown "${CA_RUN_UID}:${CA_RUN_GID}" "$1/${_f}"
  done
}

# ca_relock DIR OLDPASSIN re-encrypts DIR/ca.key under a new generated
# password, the way the first manual re-lock was done:
#   open with the old -> write the new -> open with the new
#   -> the old no longer opens -> the same public key -> rename.
# The two renames are key first, then password; ca_finish_relock completes
# or undoes a run that stopped between them.
ca_relock() {
  _dir="$1"; _old="$2"
  _work="$(mktemp -d)"
  openssl pkcs8 -in "${_dir}/ca.key" -passin "${_old}" -out "${_work}/plain.key" 2>/dev/null \
    || fail 're-lock: the CA key does not open with its current password'
  openssl pkey -in "${_work}/plain.key" -pubout -out "${_work}/old.pub" 2>/dev/null \
    || fail 're-lock: could not read the public key'
  ca_new_password "${_dir}/ca.pass.new"
  openssl pkcs8 -topk8 -v2 aes-256-cbc -in "${_work}/plain.key" \
    -out "${_dir}/ca.key.new" -passout "file:${_dir}/ca.pass.new" \
    || fail 're-lock: could not encrypt the key under the new password'
  rm -f "${_work}/plain.key"
  ca_opens "${_dir}/ca.key.new" "file:${_dir}/ca.pass.new" \
    || fail 're-lock: the re-encrypted key does not open with the new password'
  if ca_opens "${_dir}/ca.key.new" "${_old}"; then
    fail 're-lock: the re-encrypted key still opens with the old password'
  fi
  openssl pkey -in "${_dir}/ca.key.new" -passin "file:${_dir}/ca.pass.new" -pubout \
    -out "${_work}/new.pub" 2>/dev/null || fail 're-lock: could not read the new public key'
  cmp -s "${_work}/old.pub" "${_work}/new.pub" \
    || fail 're-lock: the re-encrypted key is not the same key'
  rm -rf "${_work}"
  chmod 0400 "${_dir}/ca.key.new"
  chown "${CA_RUN_UID}:${CA_RUN_GID}" "${_dir}/ca.key.new" "${_dir}/ca.pass.new"
  mv "${_dir}/ca.key.new" "${_dir}/ca.key"
  mv "${_dir}/ca.pass.new" "${_dir}/ca.pass"
}

# ca_finish_relock DIR completes a re-lock that stopped between its renames,
# or removes what one that stopped before them left behind.
ca_finish_relock() {
  if [ -e "$1/ca.pass.new" ]; then
    if [ -s "$1/ca.key" ] && ca_opens "$1/ca.key" "file:$1/ca.pass.new"; then
      mv "$1/ca.pass.new" "$1/ca.pass"
      log 'finished a re-lock that was interrupted between its two renames'
    else
      rm -f "$1/ca.pass.new"
      log 'removed the new password an interrupted re-lock left; the key was not changed'
    fi
  fi
  if [ -e "$1/ca.key.new" ]; then
    rm -f "$1/ca.key.new"
    log 'removed the new key an interrupted re-lock left; the key was not changed'
  fi
}
