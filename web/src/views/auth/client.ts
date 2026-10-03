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
 *   GET  /api/v1/account/machines, /sessions, /repositories, /agents
 *   POST /api/v1/account/machines/revoke/begin, .../finish
 *   POST /api/v1/account/enrolment-tokens/begin, .../finish
 *   POST /api/v1/account/sessions/sign-out-others
 *                                     RM-333 (#511): the organisation, its
 *                                     machines and the person's sign-ins
 *   POST /api/v1/alert-resolutions/begin, .../finish
 *                                     RM-330: resolve alerts, confirmed
 *                                     with a fresh passkey assertion
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

import type {
  Account,
  AccountAgents,
  AccountMachine,
  AccountMachines,
  AccountOrganisation,
  AccountPasskey,
  AccountRepository,
  AccountSession,
  EnrolmentToken,
  RecoverResult,
  RecoveryCodes,
  SetupStatus,
} from "./types";

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

/** `postJSON`'s GET/PATCH/DELETE siblings, for #445's account surface. Kept
 * separate from `postJSON` rather than folded into one method-taking
 * function so the sign-in/enrol ceremony's own tests, written against
 * `postJSON`'s exact request shape, are untouched by this issue. */
async function getJSON(base: string, path: string): Promise<unknown> {
  const response = await fetch(`${base}${path}`, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  const text = await response.text();
  const parsed: unknown = text === "" ? {} : JSON.parse(text);
  if (!response.ok) {
    const message = errorMessage(parsed) ?? `${path} answered ${response.status}`;
    throw new AuthRequestError(message, response.status);
  }
  return parsed;
}

async function patchJSON(base: string, path: string, body: unknown): Promise<unknown> {
  const response = await fetch(`${base}${path}`, {
    method: "PATCH",
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

async function deleteJSON(base: string, path: string): Promise<void> {
  const response = await fetch(`${base}${path}`, {
    method: "DELETE",
    headers: { Accept: "application/json" },
    credentials: "same-origin",
  });
  if (!response.ok) {
    const text = await response.text();
    const parsed: unknown = text === "" ? {} : JSON.parse(text);
    const message = errorMessage(parsed) ?? `${path} answered ${response.status}`;
    throw new AuthRequestError(message, response.status);
  }
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

/** `GET /api/v1/auth/setup` — the allow-listed, unauthenticated fact this
 * page needs to choose between the setup page and sign-in (#445). Never
 * throws: an unreachable or failing check reads as "nothing to set up",
 * which is `fetchSessionStatus`'s own fail-safe default for the same
 * reason — the gate cannot block on a read that is itself allowed to fail. */
export async function fetchSetupStatus(
  base: string = DEFAULT_API_BASE,
): Promise<SetupStatus> {
  const response = await fetch(`${base}/auth/setup`, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) return { needed: false };
  const body = (await response.json()) as unknown;
  if (typeof body !== "object" || body === null) return { needed: false };
  return { needed: (body as Record<string, unknown>)["needed"] === true };
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

/** What a completed first-enrolment ceremony hands back: the session it
 * opened, and the account's first ten recovery codes (#445's
 * `EnrolFinished`), shown exactly once — SetupPage's own "save your
 * recovery codes" step is this result, nothing re-fetched. */
export interface EnrolResult {
  readonly displayName: string;
  readonly recoveryCodes: readonly string[];
}

function enrolResultOf(body: unknown): EnrolResult {
  if (typeof body !== "object" || body === null) {
    return { displayName: "", recoveryCodes: [] };
  }
  const o = body as Record<string, unknown>;
  const codes = Array.isArray(o["recovery_codes"])
    ? o["recovery_codes"].filter((c): c is string => typeof c === "string")
    : [];
  return {
    displayName: typeof o["display_name"] === "string" ? o["display_name"] : "",
    recoveryCodes: codes,
  };
}

/**
 * The whole first-enrolment ceremony: mint the options, create the passkey,
 * finish it. Throws AuthRequestError for anything the SERVER refused (a bad
 * code), and a plain Error for anything the BROWSER refused (no passkey
 * support, the operator cancelled the platform prompt) — the two need
 * different copy, see SetupPage.
 */
export async function enrol(
  displayName: string,
  code: string,
  browser: WebAuthnBrowser,
  base: string = DEFAULT_API_BASE,
): Promise<EnrolResult> {
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
  const finished = await postJSON(base, "/auth/enrol/finish", {
    ceremony_id: begin.ceremonyId,
    credential: credentialJSON(credential),
  });
  return enrolResultOf(finished);
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

// ---------------------------------------------------------------------------
// #445: recovery sign-in, and the account page's own reads/writes.
// ---------------------------------------------------------------------------

/** `POST /api/v1/auth/recover` {code} -> RecoverResult. No session required;
 * a wrong, used or expired code is an ordinary AuthRequestError (401),
 * shown verbatim — the same discipline `enrol` and `signIn` hold. */
export async function recover(
  code: string,
  base: string = DEFAULT_API_BASE,
): Promise<RecoverResult> {
  return recoverResultOf(await postJSON(base, "/auth/recover", { code }));
}

function recoverResultOf(body: unknown): RecoverResult {
  if (typeof body !== "object" || body === null) {
    return { authenticated: false, display_name: "", remaining: 0 };
  }
  const o = body as Record<string, unknown>;
  return {
    authenticated: o["authenticated"] === true,
    display_name: typeof o["display_name"] === "string" ? o["display_name"] : "",
    remaining: typeof o["remaining"] === "number" ? o["remaining"] : 0,
  };
}

function passkeyOf(body: unknown): AccountPasskey {
  const o = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
  return {
    id: typeof o["id"] === "string" ? o["id"] : "",
    name: typeof o["name"] === "string" ? o["name"] : "",
    created_at: typeof o["created_at"] === "string" ? o["created_at"] : "",
    last_used_at: typeof o["last_used_at"] === "string" ? o["last_used_at"] : null,
    current: o["current"] === true,
  };
}

function accountOf(body: unknown): Account {
  if (typeof body !== "object" || body === null) {
    throw new Error("the server's response was not an account");
  }
  const o = body as Record<string, unknown>;
  return {
    user_id: typeof o["user_id"] === "string" ? o["user_id"] : "",
    display_name: typeof o["display_name"] === "string" ? o["display_name"] : "",
    created_at: typeof o["created_at"] === "string" ? o["created_at"] : "",
    passkeys: Array.isArray(o["passkeys"]) ? o["passkeys"].map(passkeyOf) : [],
    recovery_codes_remaining:
      typeof o["recovery_codes_remaining"] === "number" ? o["recovery_codes_remaining"] : 0,
    organisations: Array.isArray(o["organisations"])
      ? (o["organisations"] as AccountOrganisation[])
      : [],
  };
}

/** `GET /api/v1/account`. */
export async function fetchAccount(base: string = DEFAULT_API_BASE): Promise<Account> {
  return accountOf(await getJSON(base, "/account"));
}

/** `PATCH /api/v1/account` {display_name}. */
export async function updateAccount(
  displayName: string,
  base: string = DEFAULT_API_BASE,
): Promise<Account> {
  return accountOf(await patchJSON(base, "/account", { display_name: displayName }));
}

/**
 * The whole "add a passkey while signed in" ceremony — the same shape as
 * `enrol`'s ceremony, against the account's own begin/finish pair rather
 * than the first-enrolment one. Throws AuthRequestError for anything the
 * server refused and a plain Error for anything the browser refused, same
 * split as `enrol`/`signIn`.
 */
export async function addPasskey(
  name: string,
  browser: WebAuthnBrowser,
  base: string = DEFAULT_API_BASE,
): Promise<AccountPasskey> {
  const begin = asCeremonyOptions(
    await postJSON(base, "/account/passkeys/begin", { name }),
  );
  if (!browser.supported) {
    throw new Error("this browser has no passkey support");
  }
  const options = browser.publicKeyCredential.parseCreationOptionsFromJSON(begin.publicKey);
  const credential = await browser.credentials.create({ publicKey: options });
  if (credential === null) {
    throw new Error("no passkey was created");
  }
  const finished = await postJSON(base, "/account/passkeys/finish", {
    ceremony_id: begin.ceremonyId,
    credential: credentialJSON(credential),
  });
  return passkeyOf(finished);
}

/** `PATCH /api/v1/account/passkeys/{id}` {name}. */
export async function renamePasskey(
  id: string,
  name: string,
  base: string = DEFAULT_API_BASE,
): Promise<AccountPasskey> {
  return passkeyOf(
    await patchJSON(base, `/account/passkeys/${encodeURIComponent(id)}`, { name }),
  );
}

/** `DELETE /api/v1/account/passkeys/{id}`. 409s as an ordinary
 * AuthRequestError when `id` is the account's last passkey — the account
 * page disables the control for that row already, so this is the server's
 * own backstop, not the primary guard. */
export async function removePasskey(
  id: string,
  base: string = DEFAULT_API_BASE,
): Promise<void> {
  await deleteJSON(base, `/account/passkeys/${encodeURIComponent(id)}`);
}

/** `POST /api/v1/account/recovery-codes`: ten new codes, shown once; every
 * earlier code becomes void. */
export async function generateRecoveryCodes(
  base: string = DEFAULT_API_BASE,
): Promise<RecoveryCodes> {
  const body = await postJSON(base, "/account/recovery-codes", {});
  if (typeof body !== "object" || body === null) return { codes: [] };
  const codes = (body as Record<string, unknown>)["codes"];
  return {
    codes: Array.isArray(codes) ? codes.filter((c): c is string => typeof c === "string") : [],
  };
}

// ---------------------------------------------------------------------------
// RM-330 (#506): resolving alerts, confirmed with a fresh passkey.
// ---------------------------------------------------------------------------

/** One resolution the server wrote. */
export interface WrittenResolution {
  readonly event_id: string;
  readonly resolved_by: string;
  readonly resolved_at: string;
  readonly reason: string;
}

/**
 * The whole resolve ceremony: name the alerts and the reason, sign the
 * server's challenge with one of this account's passkeys, finish. The server
 * holds the alerts and the reason with the ceremony, so finish sends only
 * the assertion. Throws AuthRequestError for anything the server refused (an
 * alert already resolved is a 409) and a plain Error for anything the
 * browser refused, the same split as `enrol` and `signIn`.
 */
export async function resolveAlerts(
  eventIds: readonly string[],
  reason: string,
  browser: WebAuthnBrowser,
  base: string = DEFAULT_API_BASE,
): Promise<readonly WrittenResolution[]> {
  const begin = asCeremonyOptions(
    await postJSON(base, "/alert-resolutions/begin", { event_ids: eventIds, reason }),
  );
  if (!browser.supported) {
    throw new Error("this browser has no passkey support");
  }
  const options = browser.publicKeyCredential.parseRequestOptionsFromJSON(begin.publicKey);
  const credential = await browser.credentials.get({ publicKey: options });
  if (credential === null) {
    throw new Error("no passkey was offered");
  }
  const finished = await postJSON(base, "/alert-resolutions/finish", {
    ceremony_id: begin.ceremonyId,
    credential: credentialJSON(credential),
  });
  const list =
    typeof finished === "object" && finished !== null
      ? (finished as Record<string, unknown>)["resolutions"]
      : undefined;
  return Array.isArray(list) ? (list as WrittenResolution[]) : [];
}

// ---------------------------------------------------------------------------
// RM-333 (#511): the organisation, its machines, repositories and agents,
// and the person's own sign-ins.
// ---------------------------------------------------------------------------

function listOf<T>(body: unknown, key: string): T[] {
  if (typeof body !== "object" || body === null) return [];
  const list = (body as Record<string, unknown>)[key];
  return Array.isArray(list) ? (list as T[]) : [];
}

/** `GET /api/v1/account/machines`: the machines, and the core's CA
 * fingerprint for the connect command ("" when the API cannot read it). A
 * 503 (no accounts store) arrives as an AuthRequestError with status 503. */
export async function fetchMachines(base: string = DEFAULT_API_BASE): Promise<AccountMachines> {
  const body = await getJSON(base, "/account/machines");
  const fingerprint = (body as Record<string, unknown>)["ca_fingerprint"];
  return {
    machines: listOf<AccountMachine>(body, "machines"),
    ca_fingerprint: typeof fingerprint === "string" ? fingerprint : "",
  };
}

/** `GET /api/v1/account/repositories`. */
export async function fetchAccountRepositories(
  base: string = DEFAULT_API_BASE,
): Promise<AccountRepository[]> {
  return listOf<AccountRepository>(await getJSON(base, "/account/repositories"), "repositories");
}

/** `GET /api/v1/account/agents`. */
export async function fetchAccountAgents(base: string = DEFAULT_API_BASE): Promise<AccountAgents> {
  const body = await getJSON(base, "/account/agents");
  return {
    agent_types: listOf(body, "agent_types"),
    recent_runs: listOf(body, "recent_runs"),
  };
}

/** `GET /api/v1/account/sessions`. */
export async function fetchSessions(base: string = DEFAULT_API_BASE): Promise<AccountSession[]> {
  return listOf<AccountSession>(await getJSON(base, "/account/sessions"), "sessions");
}

/** `POST /api/v1/account/sessions/sign-out-others`: how many were ended. */
export async function signOutOtherSessions(base: string = DEFAULT_API_BASE): Promise<number> {
  const body = await postJSON(base, "/account/sessions/sign-out-others", {});
  const n =
    typeof body === "object" && body !== null
      ? (body as Record<string, unknown>)["signed_out"]
      : undefined;
  return typeof n === "number" ? n : 0;
}

/** A begin/finish pair confirmed by a fresh passkey assertion — the shape
 * resolveAlerts uses, for the account surface's two passkey-gated actions. */
async function confirmWithPasskey(
  base: string,
  path: string,
  request: unknown,
  browser: WebAuthnBrowser,
): Promise<unknown> {
  const begin = asCeremonyOptions(await postJSON(base, `${path}/begin`, request));
  if (!browser.supported) {
    throw new Error("this browser has no passkey support");
  }
  const options = browser.publicKeyCredential.parseRequestOptionsFromJSON(begin.publicKey);
  const credential = await browser.credentials.get({ publicKey: options });
  if (credential === null) {
    throw new Error("no passkey was offered");
  }
  return postJSON(base, `${path}/finish`, {
    ceremony_id: begin.ceremonyId,
    credential: credentialJSON(credential),
  });
}

/** Revoke one machine, confirmed with a passkey. Answers the machine as it
 * now stands. */
export async function revokeMachine(
  machineId: string,
  browser: WebAuthnBrowser,
  base: string = DEFAULT_API_BASE,
): Promise<AccountMachine> {
  return (await confirmWithPasskey(
    base,
    "/account/machines/revoke",
    { machine_id: machineId },
    browser,
  )) as AccountMachine;
}

/** Mint a single-use enrolment token, confirmed with a passkey. The token
 * is in the answer once; nothing here stores it. */
export async function mintEnrolmentToken(
  organisationId: string,
  kind: string,
  browser: WebAuthnBrowser,
  base: string = DEFAULT_API_BASE,
): Promise<EnrolmentToken> {
  return (await confirmWithPasskey(
    base,
    "/account/enrolment-tokens",
    { organisation_id: organisationId, kind, repos: ["*"] },
    browser,
  )) as EnrolmentToken;
}
