// SPDX-License-Identifier: Apache-2.0

/*
 * #602 and the E34 follow-up to #616, on the BUILT dashboard under its own
 * Content-Security-Policy (read from internal/api/ui.go, as FE-155 does),
 * with a Chromium virtual authenticator holding the person's passkey:
 *
 *   FE-157: removing a passkey, regenerating recovery codes and adding a
 *           passkey each ask that passkey for a fresh assertion first, and
 *           send it; nothing is changed on the session alone.
 *   FE-158: the "CA cannot sign" banner shows on every page (two checked)
 *           to an owner of the operator's organisation, links to the unlock
 *           page, and shows a member nothing.
 *   FE-159: 30 minutes without input signs out, on Playwright's clock, and
 *           the sign-in page says why; so does a session the server ended.
 *
 * Every page is watched for CSP violations. Set STEPUP_SHOTS=<dir> to write
 * screenshots of the step-up prompt, the banner on the overview and the idle
 * sign-out message there.
 */

import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test, type Page, type Route } from "@playwright/test";
import { build, preview, type PreviewServer } from "vite";

import { installApiMocks } from "../support/mock-routes";
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

const PORT = 4320;
let server: PreviewServer;
let outDir: string;
let origin: string;

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  test.setTimeout(120_000);
  outDir = mkdtempSync(path.join(tmpdir(), "innsegl-stepup-"));
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
      headers: { "Content-Security-Policy": dashboardCSP() },
    },
  });
  // localhost, not 127.0.0.1: a WebAuthn RP ID must be a domain.
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
  const dir = process.env["STEPUP_SHOTS"];
  if (dir === undefined || dir === "") return;
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({ path: path.join(dir, `${name}.png`), fullPage: false });
}

function challenge(): string {
  return Buffer.from(`challenge-${Math.random()}`).toString("base64url");
}

const LOCKED = { enabled: true, initialized: true, sealed: true, can_sign: false, reason: "the CA key store is sealed" };
const SIGNING = { enabled: true, initialized: true, sealed: false, can_sign: true };

/** The parts of the API this file reaches, with state. Everything else falls
 * through to the shared fixtures (installApiMocks). */
class MockAPI {
  role = "owner";
  custody: unknown = SIGNING;
  signedIn = true;
  ended: "idle" | undefined;
  passkeys = [
    { id: "pk-1", name: "MacBook", created_at: "2026-09-01T00:00:00Z", last_used_at: "2026-09-30T00:00:00Z", current: true },
    { id: "pk-2", name: "Phone", created_at: "2026-09-10T00:00:00Z", last_used_at: null, current: false },
  ];
  readonly posts: { path: string; body: Record<string, unknown> }[] = [];
  private removing = "";

  posted(p: string): Record<string, unknown>[] {
    return this.posts.filter((x) => x.path === p).map((x) => x.body);
  }

  async handle(route: Route): Promise<void> {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    const method = req.method();
    const body = (method === "POST" ? JSON.parse(req.postData() ?? "{}") : {}) as Record<string, unknown>;
    if (method === "POST") this.posts.push({ path: p, body });
    const json = (b: unknown, status = 200) =>
      route.fulfill({ status, contentType: "application/json", body: JSON.stringify(b) });
    const stepUp = (id: string) =>
      json({
        ceremony_id: id,
        publicKey: { challenge: challenge(), rpId: "localhost", allowCredentials: [], userVerification: "required" },
      });
    const confirmed = () => typeof body["credential"] === "object" && body["credential"] !== null;

    switch (`${method} ${p}`) {
      case "GET /api/v1/auth/session":
        return json(
          this.signedIn
            ? {
                authenticated: true,
                display_name: "Dev Operator",
                organisations: [{ id: "org-1", name: "example-org", role: this.role, operator: true }],
              }
            : { authenticated: false, ...(this.ended ? { ended: this.ended } : {}) },
        );
      case "POST /api/v1/auth/logout":
        this.signedIn = false;
        return json({});
      case "GET /api/v1/account/ca-custody":
        return this.role === "member"
          ? json({ error: { code: "forbidden", message: "not for a member" } }, 403)
          : json(this.custody);
      case "GET /api/v1/account": {
        return json({
          user_id: "6f1c2a9b3d4e5f60718293a4b5c6d7e8",
          display_name: "Dev Operator",
          created_at: "2026-09-01T00:00:00Z",
          passkeys: this.passkeys,
          recovery_codes_remaining: 8,
          organisations: [
            { id: "org-1", name: "example-org", role: this.role, operator: true, privileges: [] },
          ],
          sign_ins: [],
        });
      }
      case "POST /api/v1/account/passkeys/remove/begin":
        this.removing = String(body["id"]);
        return stepUp("cer-remove");
      case "POST /api/v1/account/passkeys/remove/finish":
        if (!confirmed()) return json({ error: { code: "unauthorized", message: "no confirmation" } }, 401);
        this.passkeys = this.passkeys.filter((k) => k.id !== this.removing);
        return json({});
      case "POST /api/v1/account/recovery-codes/begin":
        return stepUp("cer-codes");
      case "POST /api/v1/account/recovery-codes/finish":
        if (!confirmed()) return json({ error: { code: "unauthorized", message: "no confirmation" } }, 401);
        return json({ codes: Array.from({ length: 10 }, (_, i) => `ABCD-EFGH-${String(i).padStart(4, "0")}`) });
      case "POST /api/v1/account/passkeys/begin":
        return json({
          ceremony_id: "cer-add",
          publicKey: {
            challenge: challenge(),
            rp: { id: "localhost", name: "innsegl" },
            user: { id: Buffer.from("operator").toString("base64url"), name: "Dev Operator", displayName: "Dev Operator" },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            authenticatorSelection: { residentKey: "required", userVerification: "required" },
            excludeCredentials: [],
          },
          confirm: {
            publicKey: { challenge: challenge(), rpId: "localhost", allowCredentials: [], userVerification: "required" },
          },
        });
      case "POST /api/v1/account/passkeys/finish": {
        if (typeof body["confirmation"] !== "object") {
          return json({ error: { code: "unauthorized", message: "no confirmation" } }, 401);
        }
        const added = { id: "pk-3", name: "Passkey 3", created_at: "2026-10-12T00:00:00Z", last_used_at: null, current: false };
        this.passkeys = [...this.passkeys, added];
        return json(added);
      }
      default:
        return route.fallback();
    }
  }
}

async function open(page: Page, api: MockAPI, where: string): Promise<void> {
  await installApiMocks(page);
  await page.route("**/api/v1/**", (route) => api.handle(route));
  await page.goto(`${origin}${where}`);
}

test.describe("FE-157: security changes ask for a fresh passkey", () => {
  test.use({ viewport: { width: 1280, height: 900 } });

  test("remove a passkey, regenerate recovery codes, add a passkey: each confirmed by the passkey", async ({ page }) => {
    const violations = await watchViolations(page);
    const key = await addSecurityKey(page, { prf: false });
    const api = new MockAPI();
    await open(page, api, "/account");

    const passkeys = page.getByRole("region", { name: "Passkeys" });
    const phone = passkeys.getByRole("row").filter({ hasText: "Phone" });
    await phone.getByRole("button", { name: "Remove", exact: true }).click();
    await expect(phone.getByText(/One of your passkeys confirms it\./)).toBeVisible();
    await phone.scrollIntoViewIfNeeded();
    await shot(page, "step-up-prompt");
    await phone.getByRole("button", { name: "Remove with passkey" }).click();
    await expect(passkeys.getByText("Phone")).toHaveCount(0);
    const [removed] = api.posted("/api/v1/account/passkeys/remove/finish");
    expect((removed!["credential"] as { id: string }).id).toBe(key.signInCredentialId);

    const recovery = page.getByRole("region", { name: "Recovery codes" });
    await recovery.getByRole("button", { name: "Generate new codes" }).click();
    await expect(recovery.getByText(/One of your passkeys confirms it\./)).toBeVisible();
    await recovery.getByRole("button", { name: "Generate with passkey" }).click();
    await expect(page.getByText("ABCD-EFGH-0000")).toBeVisible();
    const [codes] = api.posted("/api/v1/account/recovery-codes/finish");
    expect((codes!["credential"] as { id: string }).id).toBe(key.signInCredentialId);

    await passkeys.getByRole("button", { name: "Add a passkey" }).click();
    await expect(passkeys.getByText(/One of your current passkeys confirms this first/)).toBeVisible();
    await passkeys.getByRole("button", { name: "Create passkey" }).click();
    await expect(passkeys.getByText("Passkey 3")).toBeVisible();
    const [added] = api.posted("/api/v1/account/passkeys/finish");
    expect((added!["confirmation"] as { id: string }).id).toBe(key.signInCredentialId);
    expect((added!["credential"] as { id: string }).id).not.toBe(key.signInCredentialId);

    // Nothing went out as a DELETE or a session-only POST.
    expect(api.posts.map((x) => x.path)).not.toContain("/api/v1/account/recovery-codes");
    expect(await violations()).toEqual([]);
  });
});

test.describe("FE-158: the cannot-sign banner is on every page", () => {
  test.use({ viewport: { width: 1280, height: 900 } });

  test("an owner of the operator's organisation sees it on the overview and the runs page, and it opens the unlock page", async ({ page }) => {
    const violations = await watchViolations(page);
    const api = new MockAPI();
    api.custody = LOCKED;
    await open(page, api, "/");

    const banner = page.getByRole("alert").filter({ hasText: "The CA cannot sign" });
    await expect(banner).toBeVisible();
    await expect(banner.getByText("The custodian says: the CA key store is sealed")).toBeVisible();
    await shot(page, "banner-overview");

    await page.getByRole("navigation").getByRole("link", { name: "Runs" }).click();
    await expect(page).toHaveURL(/\/runs$/);
    await expect(banner).toBeVisible();

    const link = banner.getByRole("link", { name: "Unlock with a security key" });
    await expect(link).toHaveAttribute("href", "/account?unlock");
    await link.click();
    await expect(page).toHaveURL(/\/account\?unlock$/);
    await expect(page.getByRole("region", { name: "Unlock the CA key store" })).toBeVisible();
    await expect(banner).toHaveCount(0);
    expect(await violations()).toEqual([]);
  });

  test("a member sees no banner, and the CA's status is never asked for", async ({ page }) => {
    const violations = await watchViolations(page);
    const api = new MockAPI();
    api.role = "member";
    api.custody = LOCKED;
    const asked: string[] = [];
    page.on("request", (r) => {
      if (r.url().endsWith("/api/v1/account/ca-custody")) asked.push(r.url());
    });
    await open(page, api, "/");
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await page.getByRole("navigation").getByRole("link", { name: "Runs" }).click();
    await expect(page).toHaveURL(/\/runs$/);
    await expect(page.getByText("The CA cannot sign")).toHaveCount(0);
    expect(asked).toEqual([]);
    expect(await violations()).toEqual([]);
  });
});

test.describe("FE-159: idle sessions end, and the dashboard says why", () => {
  test.use({ viewport: { width: 1280, height: 900 } });

  test("30 minutes without input signs out, on the page's clock", async ({ page }) => {
    const violations = await watchViolations(page);
    await page.clock.install();
    const api = new MockAPI();
    await open(page, api, "/");
    await expect(page.getByRole("button", { name: "Dev Operator" })).toBeVisible();

    // 29 minutes: still signed in.
    await page.clock.fastForward("29:00");
    await expect(page.getByRole("button", { name: "Dev Operator" })).toBeVisible();
    expect(api.posted("/api/v1/auth/logout")).toEqual([]);

    // Input restarts the clock.
    await page.mouse.click(5, 5);
    await page.clock.fastForward("29:00");
    expect(api.posted("/api/v1/auth/logout")).toEqual([]);

    // 30 minutes without input: signed out, and told why.
    await page.clock.fastForward("01:01");
    await expect(page.getByText("You were signed out after 30 minutes idle. Sign in again to continue.")).toBeVisible();
    await expect(page.getByRole("button", { name: "Sign in with a passkey" })).toBeVisible();
    expect(api.posted("/api/v1/auth/logout")).toHaveLength(1);
    await shot(page, "idle-sign-out");
    expect(await violations()).toEqual([]);
  });

  test("a session the server ended for idle says so on the next load", async ({ page }) => {
    const violations = await watchViolations(page);
    const api = new MockAPI();
    api.signedIn = false;
    api.ended = "idle";
    await open(page, api, "/");
    await expect(page.getByText("You were signed out after 30 minutes idle. Sign in again to continue.")).toBeVisible();

    api.ended = undefined;
    await page.reload();
    await expect(page.getByRole("button", { name: "Sign in with a passkey" })).toBeVisible();
    await expect(page.getByText(/30 minutes idle/)).toHaveCount(0);
    expect(await violations()).toEqual([]);
  });
});
