// SPDX-License-Identifier: Apache-2.0

/*
 * A Chromium virtual authenticator for the unlock-key suites (#616): a USB
 * FIDO2 security key with a PIN (user verification) and, unless asked
 * otherwise, PRF (CTAP2 hmac-secret). It also holds one discoverable
 * credential standing in for the person's sign-in passkey, so the
 * confirmation a ceremony starts with really runs too.
 */

import { generateKeyPairSync, randomBytes } from "node:crypto";

import type { CDPSession, Page } from "@playwright/test";

export interface VirtualKey {
  readonly cdp: CDPSession;
  readonly authenticatorId: string;
  /** base64url id of the sign-in passkey credential. */
  readonly signInCredentialId: string;
  /** Every credential the authenticator holds, ids in base64url. */
  credentials(): Promise<{ id: string; resident: boolean }[]>;
}

export async function addSecurityKey(page: Page, opts: { prf: boolean }): Promise<VirtualKey> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable", { enableUI: false });
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "usb",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      hasPrf: opts.prf,
      automaticPresenceSimulation: true,
    },
  });
  const signInId = randomBytes(16);
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  await cdp.send("WebAuthn.addCredential", {
    authenticatorId,
    credential: {
      credentialId: signInId.toString("base64"),
      isResidentCredential: true,
      rpId: "localhost",
      privateKey: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
      userHandle: Buffer.from("operator").toString("base64"),
      signCount: 0,
    },
  });
  return {
    cdp,
    authenticatorId,
    signInCredentialId: signInId.toString("base64url"),
    async credentials() {
      const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
      return credentials.map((c) => ({
        id: Buffer.from(c.credentialId, "base64").toString("base64url"),
        resident: c.isResidentCredential,
      }));
    },
  };
}
