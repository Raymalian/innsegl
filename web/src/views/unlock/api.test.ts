// SPDX-License-Identifier: Apache-2.0

// @vitest-environment node
// WebCrypto's X25519 and HKDF, as the browser has them (see unlockkey.test.ts).

/*
 * FE-154, unit half (#616): the ceremonies behind the unlock-key section and
 * the unlock page, against a fake browser and a fake API. The Playwright half
 * (web/tests/unlock) drives a real Chromium virtual authenticator with PRF.
 *
 * What these hold:
 *   - enrolment derives both recipients in the browser and sends only them;
 *   - the PRF output never leaves the browser, in any request body;
 *   - an unlock opens the sealed material here and sends the material, once,
 *     with the assertion;
 *   - no PRF (FE-156's case) stops before anything is sent.
 */

import { Encrypter } from "age-encryption";
import { afterEach, describe, expect, it, vi } from "vitest";

import { deriveUnlockKey } from "../../lib/unlockkey/unlockkey";
import type { WebAuthnBrowser } from "../auth/client";
import {
  NoPRFError,
  NotSealedToThisKeyError,
  browserSupport,
  enrolUnlockKey,
  fetchCustodyStatus,
  fetchUnlockKeys,
  revokeUnlockKey,
  unlockCA,
} from "./api";

const CUSTODY_PRF = new Uint8Array(32).fill(7);
const BACKUP_PRF = new Uint8Array(32).fill(9);
const CUSTODY_SALT = "Y3VzdG9keS1zYWx0LTAwMDAwMDAwMDAwMDAwMDAwMDA"; // 32 bytes, base64url
const BACKUP_SALT = "YmFja3VwLXNhbHQtMDAwMDAwMDAwMDAwMDAwMDAwMDA";
const NEW_ID = "bmV3LWNyZWQ";

const MATERIAL = {
  unseal_key: "unseal",
  role_id: "role",
  secret_id: "secret",
  backup_role_id: "brole",
  backup_secret_id: "bsecret",
};

interface Call {
  url: string;
  method: string;
  body: unknown;
}

function respond(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

function stubFetch(routes: Record<string, (body: unknown) => Response>): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
      calls.push({ url, method, body });
      const route = routes[`${method} ${url}`];
      if (route === undefined) throw new Error(`unexpected ${method} ${url}`);
      return route(body);
    }),
  );
  return calls;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

function buf(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer;
}

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

interface FakeCredentialSpec {
  id: string;
  ext: Record<string, unknown>;
}

/** A credential as a browser hands it back: toJSON() carries the client
 * extension results the way WebAuthn L3 serialises them, PRF results and all,
 * so the code under test is what has to strip them. */
function fakeCredential({ id, ext }: FakeCredentialSpec): Credential {
  const jsonExt: Record<string, unknown> = {};
  const prf = ext["prf"] as { enabled?: boolean; results?: { first?: ArrayBuffer; second?: ArrayBuffer } } | undefined;
  if (prf !== undefined) {
    const p: Record<string, unknown> = {};
    if (prf.enabled !== undefined) p["enabled"] = prf.enabled;
    if (prf.results !== undefined) {
      p["results"] = {
        first: prf.results.first ? b64url(new Uint8Array(prf.results.first)) : undefined,
        second: prf.results.second ? b64url(new Uint8Array(prf.results.second)) : undefined,
      };
    }
    jsonExt["prf"] = p;
  }
  return {
    id,
    type: "public-key",
    getClientExtensionResults: () => ext,
    toJSON: () => ({ id, rawId: id, type: "public-key", response: {}, clientExtensionResults: jsonExt }),
  } as unknown as Credential;
}

interface BrowserLog {
  creates: PublicKeyCredentialCreationOptions[];
  gets: PublicKeyCredentialRequestOptions[];
}

function fakeBrowser(
  answers: { create?: Credential; gets: Credential[] },
  log: BrowserLog = { creates: [], gets: [] },
): WebAuthnBrowser & { log: BrowserLog } {
  const gets = [...answers.gets];
  return {
    supported: true,
    log,
    publicKeyCredential: {
      parseCreationOptionsFromJSON: (json) => structuredClone(json) as never,
      parseRequestOptionsFromJSON: (json) => structuredClone(json) as never,
    },
    credentials: {
      create: async ({ publicKey }) => {
        log.creates.push(publicKey);
        return answers.create ?? null;
      },
      get: async ({ publicKey }) => {
        log.gets.push(publicKey);
        return gets.shift() ?? null;
      },
    },
  };
}

function enrolBegin() {
  return {
    ceremony_id: "cer-enrol",
    confirm: { publicKey: { challenge: "Y29uZmlybQ", userVerification: "required" } },
    create: {
      publicKey: {
        challenge: "Y3JlYXRl",
        rp: { id: "localhost", name: "innsegl" },
        user: { id: "dXNlcg", name: "u", displayName: "u" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: { authenticatorAttachment: "cross-platform", residentKey: "discouraged", userVerification: "required" },
        extensions: { prf: {} },
      },
    },
    prf: {
      publicKey: {
        challenge: "cHJm",
        userVerification: "required",
        extensions: { prf: { eval: { first: CUSTODY_SALT, second: BACKUP_SALT } } },
      },
    },
    custody_salt: CUSTODY_SALT,
    backup_salt: BACKUP_SALT,
    format: "innsegl unlock v1",
  };
}

/** Anything in a body that is, or encodes, the PRF output. */
function leaksPRF(body: unknown): boolean {
  const text = JSON.stringify(body);
  return (
    /"results"|hmacGetSecret/.test(text) ||
    [CUSTODY_PRF, BACKUP_PRF].some(
      (p) => text.includes(b64url(p)) || text.includes(Buffer.from(p).toString("base64")),
    )
  );
}

describe("FE-154 (unit) enrolling an unlock key", () => {
  it("confirms, creates, evaluates PRF on the new key, and sends only the derived recipients", async () => {
    const calls = stubFetch({
      "POST /api/v1/account/unlock-keys/begin": () => respond(enrolBegin()),
      "POST /api/v1/account/unlock-keys/finish": () =>
        respond({ id: "k1", label: "Desk key", state: "pending" }),
    });
    const browser = fakeBrowser({
      create: fakeCredential({ id: NEW_ID, ext: { prf: { enabled: true } } }),
      gets: [
        fakeCredential({ id: "c2lnbi1pbg", ext: {} }),
        fakeCredential({
          id: NEW_ID,
          ext: { prf: { results: { first: buf(CUSTODY_PRF), second: buf(BACKUP_PRF) } } },
        }),
      ],
    });

    const key = await enrolUnlockKey("Desk key", browser);
    expect(key.id).toBe("k1");

    expect(calls[0]?.body).toEqual({ label: "Desk key" });
    // The PRF get() names the new credential, and evaluates both salts as bytes.
    const prfGet = browser.log.gets[1];
    expect(prfGet?.allowCredentials?.map((c) => c.id)).toEqual([NEW_ID]);
    const evalValues = (prfGet?.extensions as { prf: { eval: { first: BufferSource; second: BufferSource } } }).prf.eval;
    expect(new Uint8Array(evalValues.first as ArrayBuffer)).toEqual(new Uint8Array(Buffer.from(CUSTODY_SALT, "base64url")));
    expect(new Uint8Array(evalValues.second as ArrayBuffer)).toEqual(new Uint8Array(Buffer.from(BACKUP_SALT, "base64url")));
    // The confirmation is the sign-in passkey, with no PRF asked of it.
    expect(browser.log.gets[0]?.extensions).toBeUndefined();

    const finish = calls[1]?.body as Record<string, unknown>;
    expect(finish["ceremony_id"]).toBe("cer-enrol");
    expect(finish["custody_recipient"]).toBe((await deriveUnlockKey(CUSTODY_PRF, "custody")).recipient);
    expect(finish["backup_recipient"]).toBe((await deriveUnlockKey(BACKUP_PRF, "backup")).recipient);
    expect(finish["credential"]).toMatchObject({ id: NEW_ID, clientExtensionResults: { prf: { enabled: true } } });
    expect(finish["assertion"]).toMatchObject({ id: NEW_ID });
    expect(finish["confirmation"]).toMatchObject({ id: "c2lnbi1pbg" });
    expect(leaksPRF(finish)).toBe(false);
    expect(JSON.stringify(finish)).not.toMatch(/AGE-SECRET-KEY/);
  });

  it("stops with NoPRFError, sending nothing more, when the key has no PRF", async () => {
    const calls = stubFetch({
      "POST /api/v1/account/unlock-keys/begin": () => respond(enrolBegin()),
    });
    const browser = fakeBrowser({
      create: fakeCredential({ id: NEW_ID, ext: { prf: { enabled: false } } }),
      gets: [fakeCredential({ id: "c2lnbi1pbg", ext: {} })],
    });
    await expect(enrolUnlockKey("Desk key", browser)).rejects.toBeInstanceOf(NoPRFError);
    expect(calls.map((c) => c.url)).toEqual(["/api/v1/account/unlock-keys/begin"]);
  });

  it("stops with NoPRFError when the PRF get() returns no results", async () => {
    const calls = stubFetch({
      "POST /api/v1/account/unlock-keys/begin": () => respond(enrolBegin()),
    });
    const browser = fakeBrowser({
      create: fakeCredential({ id: NEW_ID, ext: { prf: { enabled: true } } }),
      gets: [fakeCredential({ id: "c2lnbi1pbg", ext: {} }), fakeCredential({ id: NEW_ID, ext: {} })],
    });
    await expect(enrolUnlockKey("Desk key", browser)).rejects.toBeInstanceOf(NoPRFError);
    expect(calls).toHaveLength(1);
  });

  it("passes a server refusal through as the server worded it", async () => {
    stubFetch({
      "POST /api/v1/account/unlock-keys/begin": () =>
        respond({ error: { code: "forbidden", message: "only an owner or admin" } }, 403),
    });
    await expect(enrolUnlockKey("x", fakeBrowser({ gets: [] }))).rejects.toThrow("only an owner or admin");
  });
});

async function sealTo(recipients: string[]): Promise<string> {
  const e = new Encrypter();
  for (const r of recipients) e.addRecipient(r);
  const sealed = await e.encrypt(JSON.stringify(MATERIAL));
  return Buffer.from(sealed).toString("base64");
}

function unlockBegin(sealed: string) {
  return {
    ceremony_id: "cer-unlock",
    publicKey: {
      challenge: "dW5sb2Nr",
      userVerification: "required",
      allowCredentials: [{ type: "public-key", id: NEW_ID }],
      extensions: { prf: { evalByCredential: { [NEW_ID]: { first: CUSTODY_SALT } } } },
    },
    sealed,
  };
}

describe("FE-154 (unit) unlocking the CA from the browser", () => {
  it("opens the sealed material here and sends it once, with the assertion and no PRF output", async () => {
    const mine = await deriveUnlockKey(CUSTODY_PRF, "custody");
    const other = await deriveUnlockKey(BACKUP_PRF, "custody");
    const sealed = await sealTo([other.recipient, mine.recipient]);
    const calls = stubFetch({
      "POST /api/v1/account/ca-custody/unlock/begin": () => respond(unlockBegin(sealed)),
      "POST /api/v1/account/ca-custody/unlock/finish": () =>
        respond({ status: { enabled: true, initialized: true, sealed: false, can_sign: true } }),
    });
    const browser = fakeBrowser({
      gets: [fakeCredential({ id: NEW_ID, ext: { prf: { results: { first: buf(CUSTODY_PRF) } } } })],
    });

    const status = await unlockCA(browser);
    expect(status.can_sign).toBe(true);

    const get = browser.log.gets[0];
    const byCred = (get?.extensions as { prf: { evalByCredential: Record<string, { first: ArrayBuffer }> } }).prf
      .evalByCredential;
    expect(new Uint8Array(byCred[NEW_ID]!.first)).toEqual(new Uint8Array(Buffer.from(CUSTODY_SALT, "base64url")));

    const finish = calls[1]?.body as Record<string, unknown>;
    expect(finish).toEqual({
      ceremony_id: "cer-unlock",
      credential: expect.objectContaining({ id: NEW_ID }),
      material: MATERIAL,
    });
    expect(leaksPRF(finish)).toBe(false);
    expect(JSON.stringify(finish)).not.toContain(mine.identity);
  });

  it("refuses to send anything when the material is not sealed to this key", async () => {
    const other = await deriveUnlockKey(BACKUP_PRF, "custody");
    const sealed = await sealTo([other.recipient]);
    const calls = stubFetch({
      "POST /api/v1/account/ca-custody/unlock/begin": () => respond(unlockBegin(sealed)),
    });
    const browser = fakeBrowser({
      gets: [fakeCredential({ id: NEW_ID, ext: { prf: { results: { first: buf(CUSTODY_PRF) } } } })],
    });
    await expect(unlockCA(browser)).rejects.toBeInstanceOf(NotSealedToThisKeyError);
    expect(calls).toHaveLength(1);
  });

  it("stops with NoPRFError, before any finish, when the browser returns no PRF", async () => {
    const mine = await deriveUnlockKey(CUSTODY_PRF, "custody");
    const sealed = await sealTo([mine.recipient]);
    const calls = stubFetch({
      "POST /api/v1/account/ca-custody/unlock/begin": () => respond(unlockBegin(sealed)),
    });
    const browser = fakeBrowser({ gets: [fakeCredential({ id: NEW_ID, ext: {} })] });
    await expect(unlockCA(browser)).rejects.toBeInstanceOf(NoPRFError);
    expect(calls).toHaveLength(1);
  });
});

describe("FE-154 (unit) listing, status and revoking", () => {
  it("reads the list and the custodian's status", async () => {
    stubFetch({
      "GET /api/v1/account/unlock-keys": () =>
        respond({ custody: { enabled: true, reachable: true, set_digest: "d" }, keys: [{ id: "k1", state: "active" }] }),
      "GET /api/v1/account/ca-custody": () =>
        respond({ enabled: true, initialized: true, sealed: true, can_sign: false, reason: "sealed" }),
    });
    const list = await fetchUnlockKeys();
    expect(list.keys[0]?.id).toBe("k1");
    expect(list.custody.reachable).toBe(true);
    const status = await fetchCustodyStatus();
    expect(status).toMatchObject({ can_sign: false, reason: "sealed" });
  });

  it("revokes after a fresh passkey", async () => {
    const calls = stubFetch({
      "POST /api/v1/account/unlock-keys/revoke/begin": () =>
        respond({ ceremony_id: "cer-r", publicKey: { challenge: "cg" } }),
      "POST /api/v1/account/unlock-keys/revoke/finish": () => respond({ id: "k1", state: "revoked" }),
    });
    const browser = fakeBrowser({ gets: [fakeCredential({ id: "c2lnbi1pbg", ext: {} })] });
    const key = await revokeUnlockKey("k1", browser);
    expect(key.state).toBe("revoked");
    expect(calls[0]?.body).toEqual({ id: "k1" });
    expect(calls[1]?.body).toMatchObject({ ceremony_id: "cer-r", credential: { id: "c2lnbi1pbg" } });
  });
});

describe("FE-156 (unit) which browsers can use a security key's PRF", () => {
  const chrome =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
  const edge = chrome + " Edg/141.0.0.0";
  const firefox = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:143.0) Gecko/20100101 Firefox/143.0";
  const safari =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15";
  const iosChrome =
    "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/141.0 Mobile/15E148 Safari/604.1";

  it("treats Chrome, Edge and Firefox as able, Safari and every iOS browser as not", () => {
    expect(browserSupport(true, chrome)).toBe("ok");
    expect(browserSupport(true, edge)).toBe("ok");
    expect(browserSupport(true, firefox)).toBe("ok");
    expect(browserSupport(true, safari)).toBe("webkit");
    expect(browserSupport(true, iosChrome)).toBe("webkit");
  });

  it("names a browser with no WebAuthn at all", () => {
    expect(browserSupport(false, chrome)).toBe("none");
  });
});
