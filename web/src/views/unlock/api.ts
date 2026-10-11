// SPDX-License-Identifier: Apache-2.0

/*
 * Unlock keys and the dashboard unlock (ADR-0082, #616): what the account
 * page's "Unlock keys" section and the unlock page read and write.
 *
 *   GET  /api/v1/account/unlock-keys                every key and its state
 *   POST /api/v1/account/unlock-keys/begin|finish   enrol a security key
 *   POST /api/v1/account/unlock-keys/revoke/begin|finish
 *   GET  /api/v1/account/ca-custody                 can the CA sign
 *   POST /api/v1/account/ca-custody/unlock/begin|finish
 *
 * The security key's PRF output is the secret an identity derives from. It
 * stays in this file's local variables: it is turned into an age identity
 * (web/src/lib/unlockkey), used, and its bytes overwritten. No request body
 * ever carries it. `credentialJSON` below strips it from what the browser
 * serialises, and then refuses to send a body that still holds it.
 *
 * The sealed material is opened HERE, with age-encryption (typage, the age
 * project's own TypeScript implementation), pinned exactly in package.json.
 * It is pure JavaScript over WebCrypto and the audited @noble libraries: no
 * eval, no WebAssembly, so it runs under the dashboard's `script-src 'self'`.
 *
 * Every WebAuthn call goes through the WebAuthnBrowser seam that
 * auth/client.ts defines, so tests supply a fake browser.
 */

import { deriveUnlockKey } from "../../lib/unlockkey/unlockkey";
import { AuthRequestError, type WebAuthnBrowser } from "../auth/client";

const BASE = "/api/v1";

// ---------------------------------------------------------------------------
// Wire types: internal/api/unlockkeys.go and unlockcustody.go.
// ---------------------------------------------------------------------------

export type UnlockKeyState = "pending" | "active" | "revoked" | "unknown";

export interface UnlockKey {
  readonly id: string;
  readonly label: string;
  readonly state: UnlockKeyState | string;
  readonly mine: boolean;
  readonly owner: string;
  readonly custody_recipient: string;
  readonly custody_fingerprint: string;
  readonly backup_recipient: string;
  readonly backup_fingerprint: string;
  readonly created_at: string;
  readonly last_used_at: string | null;
  readonly revoked_at: string | null;
}

export interface UnlockKeyCustody {
  readonly enabled: boolean;
  readonly reachable: boolean;
  readonly set_digest?: string;
  readonly error?: string;
}

export interface UnlockKeyList {
  readonly custody: UnlockKeyCustody;
  readonly keys: readonly UnlockKey[];
}

/** cacustody.CoreStatus, as the API passes it through. */
export interface CustodyStatus {
  readonly enabled: boolean;
  readonly initialized: boolean;
  readonly sealed: boolean;
  readonly can_sign: boolean;
  readonly reason?: string;
  readonly error?: string;
}

/** cacustody.Material: every field, and no other. */
interface Material {
  readonly unseal_key: string;
  readonly role_id: string;
  readonly secret_id: string;
  readonly backup_role_id: string;
  readonly backup_secret_id: string;
}

const MATERIAL_FIELDS = ["unseal_key", "role_id", "secret_id", "backup_role_id", "backup_secret_id"] as const;

// ---------------------------------------------------------------------------
// Errors a page words differently.
// ---------------------------------------------------------------------------

/** The browser or the security key returned no PRF for the credential. */
export class NoPRFError extends Error {
  override name = "NoPRFError";
}

/** The key's identity opened nothing: the material is not sealed to it. */
export class NotSealedToThisKeyError extends Error {
  override name = "NotSealedToThisKeyError";
}

/** The browser offers no WebAuthn at all. */
export class NoWebAuthnError extends Error {
  override name = "NoWebAuthnError";
}

// ---------------------------------------------------------------------------
// Which browsers can use a security key's PRF.
// ---------------------------------------------------------------------------

export type BrowserSupport = "ok" | "webkit" | "none";

/**
 * "webkit" for Safari and every iOS or iPadOS browser (all of them are
 * WebKit): WebKit's PRF for security keys is not dependable yet (ADR-0082,
 * plan §2.6), so the page says to use Chrome, Edge or Firefox rather than
 * create a credential that then cannot unlock. Anything else is tried, and a
 * missing PRF is caught when the key answers.
 */
export function browserSupport(webauthn: boolean, userAgent: string): BrowserSupport {
  if (!webauthn) return "none";
  const ios = /\b(iPhone|iPad|iPod)\b/.test(userAgent);
  const otherEngine = /\b(Chrome|Chromium|Edg|Firefox)\//.test(userAgent);
  const safari = /\bSafari\//.test(userAgent) && /\bVersion\//.test(userAgent) && !otherEngine;
  return ios || safari ? "webkit" : "ok";
}

// ---------------------------------------------------------------------------
// Requests.
// ---------------------------------------------------------------------------

async function request(method: "GET" | "POST", path: string, body?: unknown): Promise<unknown> {
  const response = await fetch(`${BASE}${path}`, {
    method,
    credentials: "same-origin",
    headers:
      method === "POST"
        ? { "Content-Type": "application/json", Accept: "application/json" }
        : { Accept: "application/json" },
    ...(method === "POST" ? { body: JSON.stringify(body ?? {}) } : {}),
  });
  const text = await response.text();
  let parsed: unknown = {};
  try {
    parsed = text === "" ? {} : JSON.parse(text);
  } catch {
    parsed = {};
  }
  if (!response.ok) {
    const error = (parsed as { error?: { message?: unknown } }).error;
    const message = typeof error?.message === "string" ? error.message : `${path} answered ${response.status}`;
    throw new AuthRequestError(message, response.status);
  }
  return parsed;
}

function record(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
}

export async function fetchUnlockKeys(): Promise<UnlockKeyList> {
  const body = record(await request("GET", "/account/unlock-keys"));
  const custody = record(body["custody"]);
  return {
    custody: {
      enabled: custody["enabled"] === true,
      reachable: custody["reachable"] === true,
      ...(typeof custody["set_digest"] === "string" ? { set_digest: custody["set_digest"] } : {}),
      ...(typeof custody["error"] === "string" ? { error: custody["error"] } : {}),
    },
    keys: Array.isArray(body["keys"]) ? (body["keys"] as UnlockKey[]) : [],
  };
}

function custodyStatusOf(value: unknown): CustodyStatus {
  const o = record(value);
  return {
    enabled: o["enabled"] === true,
    initialized: o["initialized"] === true,
    sealed: o["sealed"] === true,
    can_sign: o["can_sign"] === true,
    ...(typeof o["reason"] === "string" ? { reason: o["reason"] } : {}),
    ...(typeof o["error"] === "string" ? { error: o["error"] } : {}),
  };
}

export async function fetchCustodyStatus(): Promise<CustodyStatus> {
  return custodyStatusOf(await request("GET", "/account/ca-custody"));
}

// ---------------------------------------------------------------------------
// Bytes.
// ---------------------------------------------------------------------------

function fromBase64url(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function toBase64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function bufferOf(s: unknown): ArrayBuffer {
  if (typeof s !== "string") throw new Error("the server sent a PRF input that is not base64url");
  return fromBase64url(s).buffer as ArrayBuffer;
}

function bytesOf(value: unknown): Uint8Array | null {
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  return null;
}

// ---------------------------------------------------------------------------
// WebAuthn, with the PRF handled here rather than by the JSON bridge.
// ---------------------------------------------------------------------------

/** The request options without their PRF extension, parsed by the browser's
 * own JSON bridge; the PRF inputs are then set as bytes by the caller. Not
 * every browser's parseRequestOptionsFromJSON converts PRF inputs, so none
 * is relied on to. */
function requestOptions(
  browser: WebAuthnBrowser,
  publicKey: unknown,
  overrides: Record<string, unknown> = {},
): { options: PublicKeyCredentialRequestOptions; prf: Record<string, unknown> | undefined } {
  const json = { ...record(publicKey), ...overrides };
  const extensions = { ...record(json["extensions"]) };
  const prf = extensions["prf"] === undefined ? undefined : record(extensions["prf"]);
  delete extensions["prf"];
  if (Object.keys(extensions).length === 0) delete json["extensions"];
  else json["extensions"] = extensions;
  return { options: browser.publicKeyCredential.parseRequestOptionsFromJSON(json), prf };
}

function withPRF(
  options: PublicKeyCredentialRequestOptions,
  prf: AuthenticationExtensionsPRFInputs,
): PublicKeyCredentialRequestOptions {
  return { ...options, extensions: { ...(options.extensions ?? {}), prf } };
}

/** The PRF inputs of a server's `prf` extension, as bytes. */
function prfInputs(prf: Record<string, unknown>): AuthenticationExtensionsPRFInputs {
  const out: AuthenticationExtensionsPRFInputs = {};
  const values = (v: unknown): AuthenticationExtensionsPRFValues => {
    const o = record(v);
    return o["second"] === undefined
      ? { first: bufferOf(o["first"]) }
      : { first: bufferOf(o["first"]), second: bufferOf(o["second"]) };
  };
  if (prf["eval"] !== undefined) out.eval = values(prf["eval"]);
  if (prf["evalByCredential"] !== undefined) {
    const by: Record<string, AuthenticationExtensionsPRFValues> = {};
    for (const [id, v] of Object.entries(record(prf["evalByCredential"]))) by[id] = values(v);
    out.evalByCredential = by;
  }
  return out;
}

async function get(browser: WebAuthnBrowser, options: PublicKeyCredentialRequestOptions): Promise<Credential> {
  const credential = await browser.credentials.get({ publicKey: options });
  if (credential === null) throw new Error("no security key was offered");
  return credential;
}

interface PRFOutputs {
  readonly enabled: boolean | undefined;
  readonly first: Uint8Array | null;
  readonly second: Uint8Array | null;
}

function prfOutputs(credential: Credential): PRFOutputs {
  const c = credential as unknown as { getClientExtensionResults?: () => unknown };
  const ext = record(typeof c.getClientExtensionResults === "function" ? c.getClientExtensionResults() : {});
  const prf = record(ext["prf"]);
  const results = record(prf["results"]);
  return {
    enabled: typeof prf["enabled"] === "boolean" ? prf["enabled"] : undefined,
    first: bytesOf(results["first"]),
    second: bytesOf(results["second"]),
  };
}

/**
 * A credential as the API reads it (WebAuthn L3 toJSON()), with every PRF
 * result removed. `secrets` are the PRF outputs this ceremony produced: a
 * body that still holds one, in either base64 form, is never sent.
 */
function credentialJSON(credential: Credential, secrets: readonly Uint8Array[]): Record<string, unknown> {
  const c = credential as unknown as { toJSON?: () => unknown };
  if (typeof c.toJSON !== "function") {
    throw new Error("this browser's PublicKeyCredential carries no toJSON()");
  }
  const json = { ...record(c.toJSON()) };
  const ext = { ...record(json["clientExtensionResults"]) };
  delete ext["hmacGetSecret"];
  delete ext["hmacCreateSecret"];
  if (ext["prf"] !== undefined) {
    const enabled = record(ext["prf"])["enabled"];
    if (typeof enabled === "boolean") ext["prf"] = { enabled };
    else delete ext["prf"];
  }
  json["clientExtensionResults"] = ext;
  const text = JSON.stringify(json);
  for (const s of secrets) {
    if (s.length > 0 && (text.includes(toBase64url(s)) || text.includes(toBase64(s)))) {
      throw new Error("refusing to send a request that carries the PRF output");
    }
  }
  return json;
}

function wipe(...buffers: (Uint8Array | null)[]): void {
  for (const b of buffers) b?.fill(0);
}

// ---------------------------------------------------------------------------
// Enrol.
// ---------------------------------------------------------------------------

/**
 * Enrol a security key: confirm with the sign-in passkey, create the unlock
 * credential (cross-platform, non-discoverable, PIN, PRF), then one PRF get()
 * on it evaluating the custody and backup salts. Both recipients are derived
 * here; the server gets the recipients and the three ceremonies, stripped.
 */
export async function enrolUnlockKey(label: string, browser: WebAuthnBrowser): Promise<UnlockKey> {
  const begin = record(await request("POST", "/account/unlock-keys/begin", { label }));
  if (!browser.supported) throw new NoWebAuthnError("this browser has no WebAuthn");
  const ceremonyID = begin["ceremony_id"];
  if (typeof ceremonyID !== "string") throw new Error("the server's response carried no ceremony_id");

  // 1. The sign-in passkey confirms it is you.
  const confirmOpts = requestOptions(browser, record(begin["confirm"])["publicKey"]);
  const confirmation = await get(browser, confirmOpts.options);

  // 2. The new unlock credential, on the security key.
  const createOptions = browser.publicKeyCredential.parseCreationOptionsFromJSON(
    record(begin["create"])["publicKey"],
  );
  const created = await browser.credentials.create({
    publicKey: { ...createOptions, extensions: { ...(createOptions.extensions ?? {}), prf: {} } },
  });
  if (created === null) throw new Error("no security key was created");
  const createdPRF = prfOutputs(created);
  if (createdPRF.enabled !== true) {
    wipe(createdPRF.first, createdPRF.second);
    throw new NoPRFError("the security key or this browser has no PRF");
  }

  // 3. The PRF, on the new credential only.
  const prfOpts = requestOptions(browser, record(begin["prf"])["publicKey"], {
    allowCredentials: [{ type: "public-key", id: created.id }],
  });
  const salts = {
    first: bufferOf(begin["custody_salt"]),
    second: bufferOf(begin["backup_salt"]),
  };
  const assertion = await get(browser, withPRF(prfOpts.options, { eval: salts }));
  const out = prfOutputs(assertion);
  const secrets = [out.first, out.second, createdPRF.first, createdPRF.second].filter(
    (b): b is Uint8Array => b !== null,
  );
  try {
    if (out.first === null || out.second === null) {
      throw new NoPRFError("the security key returned no PRF");
    }
    const custody = await deriveUnlockKey(out.first.slice(), "custody");
    const backup = await deriveUnlockKey(out.second.slice(), "backup");
    const body = {
      ceremony_id: ceremonyID,
      confirmation: credentialJSON(confirmation, secrets),
      credential: credentialJSON(created, secrets),
      assertion: credentialJSON(assertion, secrets),
      custody_recipient: custody.recipient,
      backup_recipient: backup.recipient,
    };
    return record(await request("POST", "/account/unlock-keys/finish", body)) as unknown as UnlockKey;
  } finally {
    wipe(...secrets);
  }
}

// ---------------------------------------------------------------------------
// Revoke.
// ---------------------------------------------------------------------------

export async function revokeUnlockKey(id: string, browser: WebAuthnBrowser): Promise<UnlockKey> {
  const begin = record(await request("POST", "/account/unlock-keys/revoke/begin", { id }));
  if (!browser.supported) throw new NoWebAuthnError("this browser has no WebAuthn");
  const { options } = requestOptions(browser, begin["publicKey"]);
  const credential = await get(browser, options);
  return record(
    await request("POST", "/account/unlock-keys/revoke/finish", {
      ceremony_id: begin["ceremony_id"],
      credential: credentialJSON(credential, []),
    }),
  ) as unknown as UnlockKey;
}

// ---------------------------------------------------------------------------
// Unlock.
// ---------------------------------------------------------------------------

async function openSealed(sealed: Uint8Array, identity: string): Promise<Material> {
  // Loaded on the first unlock only: the library is a separate chunk, so
  // every other page of the dashboard ships without it.
  const { Decrypter } = await import("age-encryption");
  const decrypter = new Decrypter();
  decrypter.addIdentity(identity);
  let text: string;
  try {
    text = await decrypter.decrypt(sealed, "text");
  } catch {
    throw new NotSealedToThisKeyError("the sealed material is not sealed to this security key");
  }
  let parsed: Record<string, unknown>;
  try {
    parsed = record(JSON.parse(text));
  } catch {
    throw new Error("the sealed material opened, but is not unlock material");
  }
  const material: Record<string, string> = {};
  for (const field of MATERIAL_FIELDS) {
    const v = parsed[field];
    if (typeof v !== "string" || v === "") throw new Error("the sealed material opened, but is incomplete");
    material[field] = v;
  }
  return material as unknown as Material;
}

/**
 * Unlock the CA key store: touch an active key, derive its custody identity
 * from the PRF, open the sealed material here, and send the material once
 * with the assertion. Answers the custodian's status after the unlock.
 */
export async function unlockCA(browser: WebAuthnBrowser): Promise<CustodyStatus> {
  const begin = record(await request("POST", "/account/ca-custody/unlock/begin", {}));
  if (!browser.supported) throw new NoWebAuthnError("this browser has no WebAuthn");
  const sealedB64 = begin["sealed"];
  if (typeof sealedB64 !== "string") throw new Error("the server sent no sealed material");
  const sealed = Uint8Array.from(atob(sealedB64), (c) => c.charCodeAt(0));

  const { options, prf } = requestOptions(browser, begin["publicKey"]);
  if (prf === undefined) throw new Error("the server asked for no PRF");
  const assertion = await get(browser, withPRF(options, prfInputs(prf)));
  const out = prfOutputs(assertion);
  const secrets = [out.first, out.second].filter((b): b is Uint8Array => b !== null);
  try {
    if (out.first === null) throw new NoPRFError("the security key returned no PRF");
    const key = await deriveUnlockKey(out.first.slice(), "custody");
    const material = await openSealed(sealed, key.identity);
    const body = {
      ceremony_id: begin["ceremony_id"],
      credential: credentialJSON(assertion, secrets),
      material,
    };
    const finished = record(await request("POST", "/account/ca-custody/unlock/finish", body));
    return custodyStatusOf(finished["status"]);
  } finally {
    wipe(...secrets);
  }
}
