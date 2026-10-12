// SPDX-License-Identifier: Apache-2.0

// @vitest-environment node
// WebCrypto's X25519 and HKDF, as the browser has them; jsdom's window has no
// SubtleCrypto of its own, so the derivation runs under Node's.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  FORMAT_VERSION,
  INFO_PREFIX,
  PRF_SIZE,
  UnlockKeyError,
  bech32Encode,
  deriveScalar,
  deriveUnlockKey,
  type Purpose,
} from "./unlockkey";

interface Vector {
  name: string;
  prf_hex: string;
  purpose: string;
  scalar_hex: string;
  identity: string;
  recipient: string;
}

interface VectorFile {
  format: string;
  hkdf_hash: string;
  hkdf_salt_hex: string;
  info_prefix: string;
  vectors: Vector[];
}

// The same file the Go side (BAK-038) reads and generates.
function loadVectors(): VectorFile {
  const path = join(import.meta.dirname, "..", "..", "..", "..", "testdata", "unlockkey", "vectors.json");
  return JSON.parse(readFileSync(path, "utf-8")) as VectorFile;
}

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

describe("FE-153 unlock-key derivation, TypeScript side", () => {
  const file = loadVectors();

  it("uses the v1 constants the vectors were made with", () => {
    expect(file.format).toBe(FORMAT_VERSION);
    expect(file.info_prefix).toBe(INFO_PREFIX);
    expect(file.hkdf_hash).toBe("SHA-256");
    expect(file.hkdf_salt_hex).toBe("");
    expect(file.vectors.length).toBeGreaterThanOrEqual(5);
  });

  for (const v of file.vectors) {
    it(`matches the golden vector: ${v.name}`, async () => {
      const prf = fromHex(v.prf_hex);
      expect(toHex(await deriveScalar(prf, v.purpose as Purpose))).toBe(v.scalar_hex);
      const key = await deriveUnlockKey(prf, v.purpose as Purpose);
      expect(key.identity).toBe(v.identity);
      expect(key.recipient).toBe(v.recipient);
    });
  }

  it("refuses a PRF output that is not 32 bytes", async () => {
    for (const n of [0, 16, 31, 33, 64]) {
      await expect(deriveUnlockKey(new Uint8Array(n), "custody")).rejects.toBeInstanceOf(UnlockKeyError);
    }
  });

  it("refuses an unknown purpose", async () => {
    for (const p of ["", "Custody", "custody ", "signing"]) {
      await expect(deriveUnlockKey(new Uint8Array(PRF_SIZE), p as Purpose)).rejects.toBeInstanceOf(UnlockKeyError);
    }
  });

  it("encodes bech32 like BIP-173's own test strings", () => {
    expect(bech32Encode("a", new Uint8Array())).toBe("a12uel5l");
    expect(bech32Encode("abcdef", fromHex("00443214c74254b635cf84653a56d7c675be77df"))).toBe(
      "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    );
  });
});
