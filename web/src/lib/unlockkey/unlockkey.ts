// SPDX-License-Identifier: Apache-2.0

/*
 * Unlock-key derivation: a security key's WebAuthn PRF output becomes a plain
 * age X25519 identity, in the browser (epic E34, #610).
 *
 * Format v1, identical to internal/unlockkey in Go:
 *
 *   scalar    = HKDF-SHA256(ikm = PRF output (32 bytes), salt = empty,
 *                           info = "innsegl unlock v1 age-x25519 " + purpose,
 *                           length = 32 bytes)
 *   identity  = bech32("age-secret-key-", scalar), upper-cased
 *   recipient = bech32("age", X25519(scalar, basepoint))
 *
 * purpose is "custody" or "backup". The per-device randomness is the salt
 * passed as the PRF input, not part of this function. The strings are frozen
 * once used: a change is a new format version with its own vectors. Both
 * languages pass testdata/unlockkey/vectors.json (BAK-038 Go, FE-153 here).
 *
 * No dependency: HKDF and X25519 are WebCrypto's own (X25519 in every browser
 * that has security-key PRF). bech32 is the few lines below.
 */

export const PRF_SIZE = 32;
export const FORMAT_VERSION = "innsegl unlock v1";
export const INFO_PREFIX = "innsegl unlock v1 age-x25519 ";

export type Purpose = "custody" | "backup";

export class UnlockKeyError extends Error {
  override name = "UnlockKeyError";
}

export interface UnlockKey {
  /** AGE-SECRET-KEY-1… — secret; never leaves the browser. */
  identity: string;
  /** age1… — public; the core encrypts to it. */
  recipient: string;
}

// PKCS#8 header for a raw X25519 private key (RFC 8410): the 32 key bytes follow.
const PKCS8_X25519_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

function check(prf: Uint8Array, purpose: Purpose): void {
  if (prf.length !== PRF_SIZE) throw new UnlockKeyError("PRF output must be 32 bytes");
  if (purpose !== "custody" && purpose !== "backup") throw new UnlockKeyError("unknown purpose");
}

/** The 32-byte X25519 secret for a PRF output and a purpose. */
export async function deriveScalar(prf: Uint8Array, purpose: Purpose): Promise<Uint8Array> {
  check(prf, purpose);
  const ikm = await crypto.subtle.importKey("raw", new Uint8Array(prf), "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(),
      info: new TextEncoder().encode(INFO_PREFIX + purpose),
    },
    ikm,
    256,
  );
  return new Uint8Array(bits);
}

function fromBase64url(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** The age identity and recipient for a PRF output and a purpose. */
export async function deriveUnlockKey(prf: Uint8Array, purpose: Purpose): Promise<UnlockKey> {
  const scalar = await deriveScalar(prf, purpose);
  const pkcs8 = new Uint8Array(PKCS8_X25519_PREFIX.length + scalar.length);
  pkcs8.set(PKCS8_X25519_PREFIX);
  pkcs8.set(scalar, PKCS8_X25519_PREFIX.length);
  const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "X25519" }, true, ["deriveBits"]);
  const jwk = await crypto.subtle.exportKey("jwk", key);
  if (jwk.x === undefined) throw new UnlockKeyError("X25519 public key unavailable");
  return {
    identity: bech32Encode("age-secret-key-", scalar).toUpperCase(),
    recipient: bech32Encode("age", fromBase64url(jwk.x)),
  };
}

// BIP-173 bech32, encode only, without the 90-character limit (age keys are longer).
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = (((chk & 0x1ffffff) << 5) ^ v) >>> 0;
    for (let i = 0; i < 5; i++) {
      if ((top >>> i) & 1) chk = (chk ^ (GEN[i] ?? 0)) >>> 0;
    }
  }
  return chk;
}

export function bech32Encode(hrp: string, data: Uint8Array): string {
  const groups: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const b of data) {
    acc = ((acc << 8) | b) & 0xfff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      groups.push((acc >>> bits) & 31);
    }
  }
  if (bits > 0) groups.push((acc << (5 - bits)) & 31);

  const values: number[] = [];
  for (let i = 0; i < hrp.length; i++) values.push(hrp.charCodeAt(i) >> 5);
  values.push(0);
  for (let i = 0; i < hrp.length; i++) values.push(hrp.charCodeAt(i) & 31);
  values.push(...groups, 0, 0, 0, 0, 0, 0);
  const mod = (polymod(values) ^ 1) >>> 0;

  let out = hrp + "1";
  for (const g of groups) out += CHARSET[g];
  for (let i = 0; i < 6; i++) out += CHARSET[(mod >>> (5 * (5 - i))) & 31];
  return out;
}
