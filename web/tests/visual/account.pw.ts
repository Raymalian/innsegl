// SPDX-License-Identifier: Apache-2.0

/*
 * #445 (ADR-0062's accounts amendment) — a visual regression of the setup
 * page's recovery-codes step, the sign-in page with the recovery-code form
 * open, and the account page, at 1440px, light and dark — the same pattern
 * tests/visual/run-page.pw.ts already uses for the run page.
 */

import { expect, test } from "@playwright/test";
import type { Page, Route } from "@playwright/test";

import { installAccountMocks } from "../support/account-mocks";

function json(route: Route, body: unknown): Promise<void> {
  return route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

const CODES = Array.from({ length: 10 }, (_, i) => `abcd-${String(i).padStart(4, "0")}`);

/** A fake, zero-interaction WebAuthn authenticator — this suite proves what
 * the page renders, not a real platform passkey (that is `enrol`'s and
 * `addPasskey`'s own unit-level coverage in web/src). */
async function installFakeAuthenticator(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const credential = {
      id: "cred-1",
      rawId: "cred-1",
      type: "public-key",
      toJSON: () => ({ id: "cred-1", rawId: "cred-1", type: "public-key" }),
    };
    // `navigator.credentials` is a getter-only accessor on the Navigator
    // prototype; a plain assignment is a silent no-op. `defineProperty` is
    // what actually replaces it for this page — see tests/a11y/auth.pw.ts's
    // own copy of this trick for the measured failure mode.
    Object.defineProperty(navigator, "credentials", {
      configurable: true,
      value: {
        create: async () => credential,
        get: async () => credential,
      },
    });
  });
}

async function installUnauthenticatedMocks(page: Page, setupNeeded: boolean): Promise<void> {
  await page.route("**/api/v1/**", async (route) => {
    const p = new URL(route.request().url()).pathname;
    if (p === "/api/v1/auth/session") return json(route, { authenticated: false });
    if (p === "/api/v1/auth/setup") return json(route, { needed: setupNeeded });
    if (p === "/api/v1/auth/enrol/begin") {
      return json(route, {
        ceremony_id: "cer-1",
        publicKey: {
          rp: { name: "innsegl", id: "localhost" },
          user: { id: "dXNlcg", name: "operator", displayName: "Dev Operator" },
          challenge: "Y2hhbGxlbmdl",
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        },
      });
    }
    if (p === "/api/v1/auth/enrol/finish") {
      return json(route, { authenticated: true, display_name: "Dev Operator", recovery_codes: CODES });
    }
    await route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ error: { code: "unmocked", message: `no fixture for ${p}` } }),
    });
  });
}

for (const mode of ["light", "dark"] as const) {
  test.describe(`#445 accounts at 1440px (${mode})`, () => {
    test.use({ colorScheme: mode, viewport: { width: 1440, height: 1200 } });

    test(`the setup page's name/passkey step (${mode})`, async ({ page }) => {
      await installUnauthenticatedMocks(page, true);
      await page.goto("/setup?code=the-one-time-code");

      await expect(page.getByRole("heading", { name: /create your account/i })).toBeVisible();
      await page.evaluate(() => document.fonts.ready);

      await expect(page).toHaveScreenshot(`account-setup-form-${mode}.png`, {
        fullPage: true,
        animations: "disabled",
      });
    });

    test(`the setup page's recovery-codes step (${mode})`, async ({ page }) => {
      await installUnauthenticatedMocks(page, true);
      await installFakeAuthenticator(page);
      await page.goto("/setup?code=the-one-time-code");
      await page.getByLabel(/display name/i).fill("Dev Operator");
      await page.getByRole("button", { name: /create passkey/i }).click();

      await expect(page.getByRole("heading", { name: /save your recovery codes/i })).toBeVisible();
      await expect(page.getByText(CODES[0]!)).toBeVisible();
      await page.evaluate(() => document.fonts.ready);

      await expect(page).toHaveScreenshot(`account-setup-codes-${mode}.png`, {
        fullPage: true,
        animations: "disabled",
      });
    });

    test(`the sign-in page with the recovery-code form open (${mode})`, async ({ page }) => {
      await installUnauthenticatedMocks(page, false);
      await page.goto("/");
      await page.getByRole("button", { name: /use a recovery code/i }).click();
      await expect(page.getByRole("textbox", { name: /recovery code/i })).toBeVisible();
      await page.evaluate(() => document.fonts.ready);

      await expect(page).toHaveScreenshot(`account-signin-recovery-${mode}.png`, {
        fullPage: true,
        animations: "disabled",
      });
    });

    test(`the account page (${mode})`, async ({ page }) => {
      // A fixed instant: the page shows ages ("4 days ago"), and a picture
      // taken against the real clock changes every day.
      await page.clock.install({ time: new Date("2026-10-03T12:00:00Z") });
      await installAccountMocks(page);
      await page.goto("/account");
      await expect(page.getByText("MacBook", { exact: true })).toBeVisible();
  // RM-333: every section loads its own read; wait for the last ones.
  await expect(page.getByText("This browser")).toBeVisible();
  await expect(page.getByRole("link", { name: "claude-code" })).toBeVisible();
      await page.evaluate(() => document.fonts.ready);

      await expect(page).toHaveScreenshot(`account-page-${mode}.png`, {
        fullPage: true,
        animations: "disabled",
      });
    });
  });
}
