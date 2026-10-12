// SPDX-License-Identifier: Apache-2.0

/*
 * FE-154 and FE-156 (#616, ADR-0082): a security key enrolled, listed,
 * used to unlock the CA key store, and revoked, from the BUILT dashboard
 * under its own Content-Security-Policy, with a Chromium virtual
 * authenticator that really evaluates PRF (CTAP2 hmac-secret).
 *
 * The API is mocked, statefully: enrolment stores what the browser sent;
 * the unlock seals real unlock material with age to the custody recipient
 * the browser derived at enrolment. So the unlock only succeeds when the
 * page derived the same identity from the key's PRF again and opened the
 * material itself, and the mock checks that the material came back intact.
 *
 * Every request body is checked: none carries the PRF output or an age
 * identity. Every page is watched for CSP violations, as FE-155 does.
 *
 * Set UNLOCK_SHOTS=<dir> to also write screenshots of each step there.
 */

import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test, type Page, type Route } from "@playwright/test";
import { Encrypter, generateX25519Identity, identityToRecipient } from "age-encryption";
import { build, preview, type PreviewServer } from "vite";

import { answerAccountRoute } from "../support/account-mocks";
import { addSecurityKey } from "../support/webauthn";

const here = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(here, "../..");
const uiGo = path.resolve(webRoot, "../internal/api/ui.go");

function dashboardCSP(): string {
  const source = readFileSync(uiGo, "utf8");
  const decl = /const dashboardCSP = ((?:"[^"]*"\s*\+?\s*)+)/.exec(source);
  if (decl === null) throw new Error(`no dashboardCSP constant in ${uiGo}`);
  return [...(decl[1] ?? "").matchAll(/"([^"]*)"/g)].map((m) => m[1]).join("");
}

const PORT = 4319;
let server: PreviewServer;
let outDir: string;
let origin: string;

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  test.setTimeout(120_000);
  const policy = dashboardCSP();
  expect(policy).not.toMatch(/unsafe-eval|wasm-unsafe-eval|unsafe-inline/);
  outDir = mkdtempSync(path.join(tmpdir(), "innsegl-unlock-"));
  const configFile = path.join(webRoot, "vite.config.ts");
  await build({ configFile, root: webRoot, logLevel: "error", build: { outDir, emptyOutDir: true } });
  server = await preview({
    configFile,
    root: webRoot,
    logLevel: "error",
    build: { outDir },
    preview: {
      host: "localhost",
      port: PORT,
      strictPort: true,
      headers: { "Content-Security-Policy": policy },
    },
  });
  origin = `http://localhost:${PORT}`;
});

test.afterAll(async () => {
  await server?.close();
  if (outDir) rmSync(outDir, { recursive: true, force: true });
});

async function watchViolations(page: Page): Promise<() => Promise<string[]>> {
  const consoleReports: string[] = [];
  page.on("console", (msg) => {
    if (/content security policy/i.test(msg.text())) consoleReports.push(msg.text());
  });
  await page.addInitScript(() => {
    const seen: string[] = [];
    (window as unknown as { __csp: string[] }).__csp = seen;
    document.addEventListener("securitypolicyviolation", (e) => {
      seen.push(`${e.effectiveDirective} blocked ${e.blockedURI || "inline"}`);
    });
  });
  return async () => {
    const events = await page.evaluate(() => (window as unknown as { __csp: string[] }).__csp);
    return [...events, ...consoleReports];
  };
}

async function shot(page: Page, name: string): Promise<void> {
  const dir = process.env["UNLOCK_SHOTS"];
  if (dir === undefined || dir === "") return;
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({ path: path.join(dir, `${name}.png`), fullPage: true });
}

const MATERIAL = {
  unseal_key: "dW5zZWFsLWtleS1mb3ItdGhlLXRlc3Q=",
  role_id: "role-0b1c",
  secret_id: "secret-7e2f",
  backup_role_id: "backup-role-41aa",
  backup_secret_id: "backup-secret-90dd",
};

const b64url = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const challenge = () => b64url(randomBytes(32));

interface Key {
  id: string;
  label: string;
  state: string;
  mine: boolean;
  owner: string;
  custody_recipient: string;
  custody_fingerprint: string;
  backup_recipient: string;
  backup_fingerprint: string;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

/** The API, as far as these pages reach it, with state. */
class MockAPI {
  keys: Key[] = [];
  locked = true;
  /** credential id -> custody salt, for the unlock's PRF input. */
  readonly salts = new Map<string, string>();
  readonly posts: { path: string; body: unknown }[] = [];
  private pendingSalts: { custody: string; backup: string } | null = null;

  async handle(route: Route): Promise<void> {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    const method = req.method();
    const body: unknown = method === "POST" ? JSON.parse(req.postData() ?? "{}") : undefined;
    if (method === "POST") this.posts.push({ path: p, body });
    const json = (b: unknown, status = 200) =>
      route.fulfill({ status, contentType: "application/json", body: JSON.stringify(b) });

    switch (`${method} ${p}`) {
      case "GET /api/v1/auth/session":
        return json({ authenticated: true, display_name: "Dev Operator", organisations: [{ id: "org-1", name: "example-org", role: "owner", operator: true }] });
      case "GET /api/v1/auth/setup":
        return json({ needed: false });
      case "GET /api/v1/account/unlock-keys":
        return json({ custody: { enabled: true, reachable: true }, keys: this.keys });
      case "GET /api/v1/account/ca-custody":
        return json(
          this.locked
            ? { enabled: true, initialized: true, sealed: true, can_sign: false, reason: "the CA key store is sealed" }
            : { enabled: true, initialized: true, sealed: false, can_sign: true },
        );
      case "POST /api/v1/account/unlock-keys/begin": {
        this.pendingSalts = { custody: b64url(randomBytes(32)), backup: b64url(randomBytes(32)) };
        return json({
          ceremony_id: "cer-enrol",
          confirm: { publicKey: { challenge: challenge(), rpId: "localhost", userVerification: "required" } },
          create: {
            publicKey: {
              challenge: challenge(),
              rp: { id: "localhost", name: "innsegl" },
              user: { id: b64url(randomBytes(16)), name: "Dev Operator", displayName: "Dev Operator" },
              pubKeyCredParams: [{ type: "public-key", alg: -7 }],
              authenticatorSelection: {
                authenticatorAttachment: "cross-platform",
                residentKey: "discouraged",
                requireResidentKey: false,
                userVerification: "required",
              },
              hints: ["security-key"],
              extensions: { prf: {} },
            },
          },
          prf: {
            publicKey: {
              challenge: challenge(),
              rpId: "localhost",
              userVerification: "required",
              hints: ["security-key"],
              extensions: { prf: { eval: { first: this.pendingSalts.custody, second: this.pendingSalts.backup } } },
            },
          },
          custody_salt: this.pendingSalts.custody,
          backup_salt: this.pendingSalts.backup,
          format: "innsegl unlock v1",
        });
      }
      case "POST /api/v1/account/unlock-keys/finish": {
        const b = body as { credential: { id: string }; custody_recipient: string; backup_recipient: string };
        this.salts.set(b.credential.id, this.pendingSalts?.custody ?? "");
        const key: Key = {
          id: `uk-${this.keys.length + 1}`,
          label: "Travel key",
          state: "pending",
          mine: true,
          owner: "Dev Operator",
          custody_recipient: b.custody_recipient,
          custody_fingerprint: "SHA256:" + b64url(randomBytes(8)),
          backup_recipient: b.backup_recipient,
          backup_fingerprint: "SHA256:" + b64url(randomBytes(8)),
          created_at: "2026-10-11T00:00:00Z",
          last_used_at: null,
          revoked_at: null,
        };
        this.keys.push(key);
        return json(key);
      }
      case "POST /api/v1/account/unlock-keys/revoke/begin":
        return json({
          ceremony_id: "cer-revoke",
          publicKey: { challenge: challenge(), rpId: "localhost", userVerification: "required" },
        });
      case "POST /api/v1/account/unlock-keys/revoke/finish": {
        for (const k of this.keys) {
          if (k.state !== "revoked") {
            k.state = "revoked";
            k.revoked_at = "2026-10-11T00:00:00Z";
          }
        }
        return json(this.keys[0]);
      }
      case "POST /api/v1/account/ca-custody/unlock/begin": {
        const active = this.keys.find((k) => k.state === "active");
        const credentials = [...this.salts.keys()];
        // The host's own recipient too, as on a real core: the browser must
        // find its own stanza among others.
        const enc = new Encrypter();
        enc.addRecipient(await identityToRecipient(await generateX25519Identity()));
        if (active !== undefined) enc.addRecipient(active.custody_recipient);
        const sealed = await enc.encrypt(JSON.stringify(MATERIAL));
        return json({
          ceremony_id: "cer-unlock",
          publicKey: {
            challenge: challenge(),
            rpId: "localhost",
            userVerification: "required",
            hints: ["security-key"],
            allowCredentials: credentials.map((id) => ({ type: "public-key", id })),
            extensions: {
              prf: {
                evalByCredential: Object.fromEntries(credentials.map((id) => [id, { first: this.salts.get(id) }])),
              },
            },
          },
          sealed: Buffer.from(sealed).toString("base64"),
        });
      }
      case "POST /api/v1/account/ca-custody/unlock/finish": {
        const b = body as { material: unknown };
        if (JSON.stringify(b.material) !== JSON.stringify(MATERIAL)) {
          return json({ error: { code: "forbidden", message: "not accepted" } }, 403);
        }
        this.locked = false;
        return json({ status: { enabled: true, initialized: true, sealed: false, can_sign: true } });
      }
    }
    if (await answerAccountRoute(route)) return;
    return json({ error: { code: "unmocked", message: `no fixture for ${p}` } }, 500);
  }

  /** No body ever carries the PRF output or an identity. */
  leaks(): string[] {
    return this.posts
      .filter(({ body }) => /"results"|hmacGetSecret|AGE-SECRET-KEY/i.test(JSON.stringify(body)))
      .map(({ path }) => path);
  }

  posted(p: string): unknown[] {
    return this.posts.filter((x) => x.path === p).map((x) => x.body);
  }
}

async function openAccount(page: Page, api: MockAPI, query = ""): Promise<void> {
  await page.route("**/api/v1/**", (route) => api.handle(route));
  await page.goto(`${origin}/account${query}`);
  await expect(page.getByRole("heading", { name: "Unlock keys" })).toBeVisible();
}

test.describe("FE-154: unlock keys with a PRF security key, under the dashboard's CSP", () => {
  test.use({ viewport: { width: 1280, height: 900 } });

  test("enrol, list, unlock and revoke, with no PRF output sent and zero violations", async ({ page }) => {
    const violations = await watchViolations(page);
    const key = await addSecurityKey(page, { prf: true });
    const api = new MockAPI();
    await openAccount(page, api);
    const section = page.getByRole("region", { name: "Unlock keys" });

    // The CA cannot sign: the banner says so.
    await expect(page.getByText("The CA cannot sign")).toBeVisible();
    await expect(section.getByText("No unlock keys yet.")).toBeVisible();
    await expect(section.getByText(/Until one key is active, add it from the operator machine/)).toBeVisible();
    await shot(page, "1-account-banner-and-section");

    // Enrol.
    await section.getByRole("button", { name: "Add a security key" }).click();
    await section.getByLabel("Name for this key").fill("Travel key");
    await shot(page, "2-add-key-form");
    await section.getByRole("button", { name: "Add the key" }).click();
    await expect(section.getByText("Added. The key is pending until a reseal applies it.")).toBeVisible();

    const [finish] = api.posted("/api/v1/account/unlock-keys/finish") as {
      confirmation: { id: string };
      credential: { id: string; clientExtensionResults: { prf?: { enabled?: boolean } } };
      assertion: { id: string };
      custody_recipient: string;
      backup_recipient: string;
    }[];
    expect(finish).toBeDefined();
    expect(finish!.confirmation.id).toBe(key.signInCredentialId);
    expect(finish!.credential.clientExtensionResults.prf?.enabled).toBe(true);
    expect(finish!.assertion.id).toBe(finish!.credential.id);
    expect(finish!.custody_recipient).toMatch(/^age1[02-9ac-hj-np-z]{58}$/);
    expect(finish!.backup_recipient).toMatch(/^age1[02-9ac-hj-np-z]{58}$/);
    expect(finish!.backup_recipient).not.toBe(finish!.custody_recipient);
    // The new credential is on the key, and is not discoverable.
    expect(await key.credentials()).toContainEqual({ id: finish!.credential.id, resident: false });

    // Listed, pending, with the command that activates it.
    const table = section.getByRole("table", { name: "Unlock keys" });
    await expect(table.getByText("Travel key")).toBeVisible();
    await expect(table.getByText("Pending")).toBeVisible();
    await expect(section.getByText(`innsegl ca-custody reseal --add ${finish!.custody_recipient}`)).toBeVisible();
    await shot(page, "3-key-pending");

    // The operator machine reseals the material to it.
    api.keys[0]!.state = "active";
    await page.reload();
    await expect(section.getByRole("table", { name: "Unlock keys" }).getByText("Active")).toBeVisible();

    // Unlock from the banner.
    await page.getByRole("link", { name: "Unlock with a security key" }).click();
    const unlock = page.getByRole("region", { name: "Unlock the CA key store" });
    await expect(unlock).toBeVisible();
    await shot(page, "4-unlock-page");
    await unlock.getByRole("button", { name: "Unlock with a security key" }).click();
    await expect(unlock.getByText("Unlocked. The CA can sign again.")).toBeVisible();
    await expect(page.getByText("The CA cannot sign")).toHaveCount(0);
    const [unlockFinish] = api.posted("/api/v1/account/ca-custody/unlock/finish") as {
      credential: { id: string };
      material: unknown;
    }[];
    expect(unlockFinish!.material).toEqual(MATERIAL);
    expect(unlockFinish!.credential.id).toBe(finish!.credential.id);
    await shot(page, "5-unlocked");

    // Revoke, after a confirmation.
    await section.getByRole("button", { name: "Revoke", exact: true }).click();
    await expect(section.getByText(/Revoke this key\?/)).toBeVisible();
    await section.getByRole("button", { name: "Revoke with passkey" }).click();
    await expect(section.getByRole("table", { name: "Unlock keys" }).getByText("Revoked")).toBeVisible();
    expect(api.posted("/api/v1/account/unlock-keys/revoke/finish")).toHaveLength(1);

    expect(api.leaks()).toEqual([]);
    expect(await violations()).toEqual([]);
  });
});

test.describe("FE-156: a security key without PRF", () => {
  test.use({ viewport: { width: 1280, height: 900 } });

  test("enrolment and unlock both stop with the fallback message, and send nothing on", async ({ page }) => {
    const violations = await watchViolations(page);
    const key = await addSecurityKey(page, { prf: false });
    const api = new MockAPI();
    await openAccount(page, api);
    const section = page.getByRole("region", { name: "Unlock keys" });

    await section.getByRole("button", { name: "Add a security key" }).click();
    await section.getByRole("button", { name: "Add the key" }).click();
    const fallback = /returned no PRF \(hmac-secret\), so it cannot unlock\. Nothing was saved or sent to the core\. Use Chrome, Edge or Firefox/;
    await expect(section.getByText(fallback)).toBeVisible();
    await shot(page, "6-no-prf-enrol");
    expect(api.posted("/api/v1/account/unlock-keys/finish")).toEqual([]);

    // The key does hold the credential the browser just created; offer it
    // for an unlock as an active key would be.
    const created = (await key.credentials()).find((c) => !c.resident);
    expect(created).toBeDefined();
    api.salts.set(created!.id, b64url(randomBytes(32)));
    await page.getByRole("link", { name: "Unlock with a security key" }).click();
    const unlock = page.getByRole("region", { name: "Unlock the CA key store" });
    await unlock.getByRole("button", { name: "Unlock with a security key" }).click();
    await expect(unlock.getByText(fallback)).toBeVisible();
    expect(api.posted("/api/v1/account/ca-custody/unlock/finish")).toEqual([]);

    expect(api.leaks()).toEqual([]);
    expect(await violations()).toEqual([]);
  });
});
