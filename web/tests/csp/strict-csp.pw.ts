// SPDX-License-Identifier: Apache-2.0

/*
 * FE-155 (#612) — every page renders under the dashboard's strict
 * Content-Security-Policy with zero violations, and passkey sign-in still
 * works under it.
 *
 * The rest of this suite drives the vite DEV server, which injects inline
 * script and style by design and sends no policy. A policy can only be
 * judged against what ships, so this file builds the dashboard with the real
 * web/vite.config.ts into a temporary directory and serves that build with
 * the policy `innsegl api` sends — read from internal/api/ui.go itself, so
 * the browser is held to the one definition and never to a copy of it.
 *
 * A violation is caught twice: by the page's own `securitypolicyviolation`
 * event and by Chromium's console report. Either fails the test.
 */

import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test, type Page } from "@playwright/test";
import { build, preview, type PreviewServer } from "vite";

import { installAccountMocks } from "../support/account-mocks";
import { installApiMocks } from "../support/mock-routes";
import { VIEWS } from "../support/views";

const here = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(here, "../..");
const uiGo = path.resolve(webRoot, "../internal/api/ui.go");

/** dashboardCSP from ui.go: the Go string literals of the constant, joined. */
function dashboardCSP(): string {
  const source = readFileSync(uiGo, "utf8");
  const decl = /const dashboardCSP = ((?:"[^"]*"\s*\+?\s*)+)/.exec(source);
  if (decl === null) throw new Error(`no dashboardCSP constant in ${uiGo}`);
  const policy = [...(decl[1] ?? "").matchAll(/"([^"]*)"/g)].map((m) => m[1]).join("");
  if (!policy.includes("script-src")) throw new Error(`dashboardCSP reads as ${policy}`);
  return policy;
}

const PORT = 4318;
let server: PreviewServer;
let outDir: string;
let origin: string;
let policy: string;

// One build and one server for the file: workers would each build their own.
test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  test.setTimeout(120_000);
  policy = dashboardCSP();
  outDir = mkdtempSync(path.join(tmpdir(), "innsegl-csp-"));
  const configFile = path.join(webRoot, "vite.config.ts");
  await build({
    configFile,
    root: webRoot,
    logLevel: "error",
    build: { outDir, emptyOutDir: true },
  });
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
  // localhost, not 127.0.0.1: a WebAuthn RP ID must be a domain.
  origin = `http://localhost:${PORT}`;
});

test.afterAll(async () => {
  await server?.close();
  if (outDir) rmSync(outDir, { recursive: true, force: true });
});

/** Records every violation the page reports, from the first byte on. */
async function watchViolations(page: Page): Promise<() => Promise<string[]>> {
  const consoleReports: string[] = [];
  page.on("console", (msg) => {
    if (/content security policy/i.test(msg.text())) consoleReports.push(msg.text());
  });
  await page.addInitScript(() => {
    const seen: string[] = [];
    (window as unknown as { __csp: string[] }).__csp = seen;
    document.addEventListener("securitypolicyviolation", (e) => {
      seen.push(`${e.effectiveDirective} blocked ${e.blockedURI || "inline"} (${e.sourceFile}:${e.lineNumber})`);
    });
  });
  return async () => {
    const events = await page.evaluate(() => (window as unknown as { __csp: string[] }).__csp);
    return [...events, ...consoleReports];
  };
}

/** Lets fonts, lazy styles and late effects settle before reading. */
async function settle(page: Page): Promise<void> {
  await page.evaluate(() => document.fonts.ready);
  await page.waitForLoadState("networkidle");
}

test.describe("FE-155: the built dashboard under its own Content-Security-Policy", () => {
  test("the served page carries the policy and no inline script", async ({ request }) => {
    const res = await request.get(`${origin}/`);
    expect(res.headers()["content-security-policy"]).toBe(policy);
    const html = await res.text();
    const inline = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)].filter(
      ([, attrs, body]) => !/\bsrc\s*=/.test(attrs ?? "") || (body ?? "").trim() !== "",
    );
    expect(inline.map((m) => m[0])).toEqual([]);
  });

  for (const view of VIEWS) {
    test(`${view.name} renders with zero violations`, async ({ page }) => {
      const violations = await watchViolations(page);
      await installApiMocks(page);
      await page.goto(origin + view.path);
      await expect(page).toHaveTitle(view.title);
      await settle(page);
      expect(await violations()).toEqual([]);
    });
  }

  test("the stored dark theme is applied before the bundle, without inline script", async ({
    page,
  }) => {
    const violations = await watchViolations(page);
    await installApiMocks(page);
    await page.addInitScript(() => window.localStorage.setItem("innsegl.theme", "dark"));
    // Hold the application bundle: whatever sets data-theme now is the
    // bootstrap alone, which is the no-flash guarantee FE-018 protects.
    await page.route("**/assets/index-*.js", () => new Promise(() => {}));
    await page.goto(origin + "/", { waitUntil: "commit" });
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    expect(await violations()).toEqual([]);
  });

  test("the account page renders with zero violations", async ({ page }) => {
    const violations = await watchViolations(page);
    await installAccountMocks(page);
    await page.goto(origin + "/account");
    await expect(page.getByRole("heading", { name: "Account", exact: true })).toBeVisible();
    await expect(page.getByText("This browser")).toBeVisible();
    await settle(page);
    expect(await violations()).toEqual([]);
  });

  test("passkey sign-in completes with a real WebAuthn ceremony and zero violations", async ({
    page,
  }) => {
    const violations = await watchViolations(page);

    // A Chromium virtual authenticator holding one discoverable credential
    // for this origin's RP ID: navigator.credentials.get really runs.
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
      },
    });
    const credentialId = randomBytes(16);
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    await cdp.send("WebAuthn.addCredential", {
      authenticatorId,
      credential: {
        credentialId: credentialId.toString("base64"),
        isResidentCredential: true,
        rpId: "localhost",
        privateKey: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
        userHandle: Buffer.from("operator").toString("base64"),
        signCount: 0,
      },
    });

    let signedIn = false;
    let finishBody: { ceremony_id?: string; credential?: { id?: string } } | null = null;
    await installApiMocks(page);
    await page.route("**/api/v1/auth/session", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(
          signedIn ? { authenticated: true, display_name: "Test Operator" } : { authenticated: false },
        ),
      }),
    );
    await page.route("**/api/v1/auth/login/begin", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          ceremony_id: "ceremony-1",
          publicKey: {
            challenge: randomBytes(32).toString("base64url"),
            rpId: "localhost",
            allowCredentials: [],
            userVerification: "required",
            timeout: 60_000,
          },
        }),
      }),
    );
    await page.route("**/api/v1/auth/login/finish", async (route) => {
      finishBody = route.request().postDataJSON() as typeof finishBody;
      signedIn = true;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ display_name: "Test Operator" }),
      });
    });

    await page.goto(origin + "/");
    await page.getByRole("button", { name: /sign in with a passkey/i }).click();
    await expect(page).toHaveTitle(VIEWS[0]?.title ?? "");
    expect(finishBody).not.toBeNull();
    expect(finishBody!.ceremony_id).toBe("ceremony-1");
    expect(finishBody!.credential?.id).toBe(credentialId.toString("base64url"));
    await settle(page);
    expect(await violations()).toEqual([]);
  });
});
