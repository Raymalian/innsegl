// SPDX-License-Identifier: Apache-2.0

/*
 * What the sign-in surface reads and writes, and how — RM-260/RM-261,
 * ADR-0062, doc 06 §7.
 *
 *   GET  /api/v1/health          "enrolled" — is there anyone to sign in as
 *   GET  /api/v1/auth/session    "am I signed in", and my display name
 *   POST /api/v1/auth/enrol/begin    one-time code + display name -> a
 *                                     WebAuthn creation challenge
 *   POST /api/v1/auth/enrol/finish   the browser's attestation -> a session
 *   POST /api/v1/auth/login/begin    -> a WebAuthn request challenge
 *   POST /api/v1/auth/login/finish   the browser's assertion -> a session
 *   POST /api/v1/auth/logout         revokes the session
 *
 * This is the ONE file in the dashboard that calls `navigator.credentials`.
 * Every function that does is a thin wrapper taking the browser API as a
 * parameter (default: the real one) — jsdom, which every component test in
 * this directory runs under, implements neither `navigator.credentials` nor
 * `PublicKeyCredential`, so a test supplies a fake rather than this file
 * reaching for `window` directly and becoming untestable.
 *
 * The creation/request OPTIONS this reads off the server are already the
 * WebAuthn Level 3 JSON form (base64url strings, not ArrayBuffers) —
 * `internal/api`'s own `protocol.CredentialCreation`/`CredentialAssertion`
 * marshal that way — so `PublicKeyCredential.parseCreationOptionsFromJSON`
 * and `.parseRequestOptionsFromJSON` do the ArrayBuffer conversion a browser
 * ceremony needs, and `credential.toJSON()` does the reverse on the way
 * back. Both are standard WebAuthn L3 methods; this file does not hand-roll
 * base64url itself.
 */

const DEFAULT_API_BASE = "/api/v1";

export class AuthRequestError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "AuthRequestError";
  }
}

async function postJSON(
  base: string,
  path: string,
  body: unknown,
): Promise<unknown> {
  const response = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(body ?? {}),
  });
  const text = await response.text();
  const parsed: unknown = text === "" ? {} : JSON.parse(text);
  if (!response.ok) {
    const message = errorMessage(parsed) ?? `${path} answered ${response.status}`;
    throw new AuthRequestError(message, response.status);
  }
  return parsed;
}

function errorMessage(body: unknown): string | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const error = (body as Record<string, unknown>)["error"];
  if (typeof error !== "object" || error === null) return undefined;
  const message = (error as Record<string, unknown>)["message"];
  return typeof message === "string" ? message : undefined;
}

export interface SessionStatus {
  readonly authenticated: boolean;
  readonly displayName: string;
}

/** `GET /api/v1/auth/session`. Never throws on "not signed in" — that is an
 * ordinary, expected answer here, not a failure. */
export async function fetchSessionStatus(
  base: string = DEFAULT_API_BASE,
): Promise<SessionStatus> {
  const response = await fetch(`${base}/auth/session`, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) return { authenticated: false, displayName: "" };
  const body = (await response.json()) as unknown;
  if (typeof body !== "object" || body === null) {
    return { authenticated: false, displayName: "" };
  }
  const o = body as Record<string, unknown>;
  return {
    authenticated: o["authenticated"] === true,
    displayName: typeof o["display_name"] === "string" ? o["display_name"] : "",
  };
}

/** `GET /api/v1/health`'s `auth.enrolled` — the allow-listed, unauthenticated
 * fact this page needs to choose between the enrolment page and sign-in. */
export async function fetchEnrolled(base: string = DEFAULT_API_BASE): Promise<boolean> {
  const response = await fetch(`${base}/health`, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) return false;
  const body = (await response.json()) as unknown;
  if (typeof body !== "object" || body === null) return false;
  const auth = (body as Record<string, unknown>)["auth"];
  if (typeof auth !== "object" || auth === null) return false;
  return (auth as Record<string, unknown>)["enrolled"] === true;
}

/** `POST /api/v1/auth/logout`. */
export async function signOut(base: string = DEFAULT_API_BASE): Promise<void> {
  await postJSON(base, "/auth/logout", {});
}

// ---------------------------------------------------------------------------
// The browser API seam.
// ---------------------------------------------------------------------------

/** The slice of `navigator.credentials` a ceremony needs. */
export interface CredentialsContainerLike {
  create(options: { publicKey: PublicKeyCredentialCreationOptions }): Promise<Credential | null>;
  get(options: { publicKey: PublicKeyCredentialRequestOptions }): Promise<Credential | null>;
}

/** The slice of the `PublicKeyCredential` static interface a ceremony needs
 * — the WebAuthn L3 JSON bridge, and the feature-detection flag this page's
 * error copy reads. */
export interface PublicKeyCredentialStaticLike {
  parseCreationOptionsFromJSON(
    json: unknown,
  ): PublicKeyCredentialCreationOptions;
  parseRequestOptionsFromJSON(json: unknown): PublicKeyCredentialRequestOptions;
}

export interface WebAuthnBrowser {
  readonly credentials: CredentialsContainerLike;
  readonly publicKeyCredential: PublicKeyCredentialStaticLike;
  /** False in a browser with no passkey support at all — the error copy
   * this page shows is different from "the ceremony was cancelled". */
  readonly supported: boolean;
}

/** The real browser, read lazily so importing this module never touches
 * `window` (and so it does not throw in an environment, like jsdom, that
 * defines neither piece of it). */
export function realBrowser(): WebAuthnBrowser {
  const PKC = (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential as
    | (PublicKeyCredentialStaticLike & { new (): unknown })
    | undefined;
  return {
    credentials: navigator.credentials as unknown as CredentialsContainerLike,
    publicKeyCredential: PKC as unknown as PublicKeyCredentialStaticLike,
    supported: PKC !== undefined && typeof navigator.credentials?.create === "function",
  };
}

/** A credential the browser handed back, serialised the same way
 * `internal/api`'s own handlers read a request body — id/rawId/response,
 * base64url throughout (WebAuthn L3's own `toJSON()`). */
function credentialJSON(credential: Credential): unknown {
  const withToJSON = credential as unknown as { toJSON?: () => unknown };
  if (typeof withToJSON.toJSON === "function") return withToJSON.toJSON();
  // Every browser this dashboard is documented to run in implements
  // toJSON() (WebAuthn L3); this is a clear failure rather than a silent
  // guess if one somehow does not.
  throw new Error("this browser's PublicKeyCredential carries no toJSON()");
}

export interface CeremonyOptions {
  readonly ceremonyId: string;
  readonly publicKey: unknown;
}

function asCeremonyOptions(body: unknown): CeremonyOptions {
  if (typeof body !== "object" || body === null) {
    throw new Error("the server's response was not a ceremony");
  }
  const o = body as Record<string, unknown>;
  if (typeof o["ceremony_id"] !== "string" || o["publicKey"] === undefined) {
    throw new Error("the server's response carried no ceremony_id or publicKey");
  }
  return { ceremonyId: o["ceremony_id"], publicKey: o["publicKey"] };
}

/**
 * The whole first-enrolment ceremony: mint the options, create the passkey,
 * finish it. Throws AuthRequestError for anything the SERVER refused (a bad
 * code, the socket denial not in effect), and a plain Error for anything the
 * BROWSER refused (no passkey support, the operator cancelled the platform
 * prompt) — the two need different copy, see EnrolPage.
 */
export async function enrol(
  displayName: string,
  code: string,
  browser: WebAuthnBrowser,
  base: string = DEFAULT_API_BASE,
): Promise<void> {
  const begin = asCeremonyOptions(
    await postJSON(base, "/auth/enrol/begin", { display_name: displayName, code }),
  );
  if (!browser.supported) {
    throw new Error("this browser has no passkey support");
  }
  const options = browser.publicKeyCredential.parseCreationOptionsFromJSON(begin.publicKey);
  const credential = await browser.credentials.create({ publicKey: options });
  if (credential === null) {
    throw new Error("no passkey was created");
  }
  await postJSON(base, "/auth/enrol/finish", {
    ceremony_id: begin.ceremonyId,
    credential: credentialJSON(credential),
  });
}

/** The whole sign-in ceremony: mint the options, ask for the passkey the
 * platform already knows (discoverable/usernameless — no display name or
 * code is ever asked here), finish it. Returns the display name the server
 * reports for the session it just opened. */
export async function signIn(
  browser: WebAuthnBrowser,
  base: string = DEFAULT_API_BASE,
): Promise<string> {
  const begin = asCeremonyOptions(await postJSON(base, "/auth/login/begin", {}));
  if (!browser.supported) {
    throw new Error("this browser has no passkey support");
  }
  const options = browser.publicKeyCredential.parseRequestOptionsFromJSON(begin.publicKey);
  const credential = await browser.credentials.get({ publicKey: options });
  if (credential === null) {
    throw new Error("no passkey was offered");
  }
  const finished = await postJSON(base, "/auth/login/finish", {
    ceremony_id: begin.ceremonyId,
    credential: credentialJSON(credential),
  });
  return displayNameOf(finished);
}

function displayNameOf(body: unknown): string {
  if (typeof body !== "object" || body === null) return "";
  const name = (body as Record<string, unknown>)["display_name"];
  return typeof name === "string" ? name : "";
}
