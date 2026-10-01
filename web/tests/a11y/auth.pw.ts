// SPDX-License-Identifier: Apache-2.0

/*
 * RM-260/RM-261 (ADR-0062) and #445 — the gated shell's own screens: sign-in
 * (passkey and the recovery-code form), the no-account notice, and the
 * setup-link page. doc 07's FE-009 pattern (axe pass + keyboard-only walk),
 * applied to every screen a reader reaches before a session exists.
 *
 * installApiMocks answers /api/v1/auth/session as an already-signed-in
 * operator by default (see that file's own comment), so these states are
 * wired here instead, by overriding the two routes AuthGate itself reads.
 * The account page's own axe/keyboard coverage lives in account.pw.ts,
 * since it needs an authenticated account read rather than these two.
 */

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { installApiMocks } from "../support/mock-routes";

async function asUnauthenticated(page: Page, setupNeeded: boolean): Promise<void> {
  await installApiMocks(page);
  await page.route("**/api/v1/auth/session", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ authenticated: false }),
    });
  });
  await page.route("**/api/v1/auth/setup", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ needed: setupNeeded }),
    });
  });
}

function formatViolations(violations: readonly import("axe-core").Result[]): string {
  if (violations.length === 0) return "";
  return violations
    .map((v) => {
      const nodes = v.nodes.map((n) => `    ${n.target.join(" ")}: ${n.failureSummary ?? ""}`);
      return `${v.id} (${v.impact ?? "unknown"}): ${v.help}\n${nodes.join("\n")}`;
    })
    .join("\n\n");
}

test.describe("RM-260/RM-261: the sign-in page", () => {
  test("has no WCAG 2.1 AA violations", async ({ page }) => {
    await asUnauthenticated(page, false);
    await page.goto("/");
    await expect(page.getByRole("button", { name: /sign in with a passkey/i })).toBeVisible();

    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    expect(results.violations, formatViolations(results.violations)).toEqual([]);
  });

  test("the passkey button is reachable by keyboard and carries a visible focus ring", async ({
    page,
  }) => {
    await asUnauthenticated(page, false);
    await page.goto("/");
    const button = page.getByRole("button", { name: /sign in with a passkey/i });
    await expect(button).toBeVisible();

    await page.keyboard.press("Tab");
    await expect(button).toBeFocused();
    const outline = await button.evaluate((el) => getComputedStyle(el).outlineStyle);
    expect(outline).not.toBe("none");
  });

  test("renders no other view's content — nothing of the dashboard leaks", async ({ page }) => {
    await asUnauthenticated(page, false);
    await page.goto("/runs");
    await expect(page.getByRole("button", { name: /sign in with a passkey/i })).toBeVisible();
    await expect(page.getByRole("table")).toHaveCount(0);
    await expect(page.getByRole("navigation")).toHaveCount(0);
  });

  test("#445: says there is no account yet, with no passkey button, when setup is still needed", async ({
    page,
  }) => {
    await asUnauthenticated(page, true);
    await page.goto("/");
    await expect(page.getByRole("heading", { name: /no account yet/i })).toBeVisible();
    await expect(page.getByRole("button", { name: /sign in with a passkey/i })).toHaveCount(0);

    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    expect(results.violations, formatViolations(results.violations)).toEqual([]);
  });

  test("#445: the recovery-code form opens, has no violations, and is reachable by keyboard", async ({
    page,
  }) => {
    await asUnauthenticated(page, false);
    await page.goto("/");
    await page.getByRole("button", { name: /use a recovery code/i }).click();
    const codeField = page.getByRole("textbox", { name: /recovery code/i });
    await expect(codeField).toBeVisible();

    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    expect(results.violations, formatViolations(results.violations)).toEqual([]);

    await codeField.focus();
    await expect(codeField).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(page.getByRole("button", { name: /sign in with this code/i })).toBeFocused();
  });
});

test.describe("#445: the setup-link page", () => {
  test("has no WCAG 2.1 AA violations, with a code in the URL", async ({ page }) => {
    await asUnauthenticated(page, true);
    await page.goto("/setup?code=the-one-time-code");
    await expect(page.getByRole("heading", { name: /create your account/i })).toBeVisible();

    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    expect(results.violations, formatViolations(results.violations)).toEqual([]);
  });

  test("the name field and the create-passkey button are reachable by keyboard, in order", async ({
    page,
  }) => {
    await asUnauthenticated(page, true);
    await page.goto("/setup?code=the-one-time-code");
    await expect(page.getByRole("heading", { name: /create your account/i })).toBeVisible();

    await page.keyboard.press("Tab");
    await expect(page.getByLabel(/display name/i)).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(page.getByRole("button", { name: /create passkey/i })).toBeFocused();
  });

  test("says a setup link is needed, with no violations, when the URL carries no code", async ({
    page,
  }) => {
    await asUnauthenticated(page, true);
    await page.goto("/setup");
    await expect(page.getByRole("heading", { name: /no setup link/i })).toBeVisible();

    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    expect(results.violations, formatViolations(results.violations)).toEqual([]);
  });

  test("completes the ceremony and shows the recovery-codes save step", async ({ page }) => {
    await asUnauthenticated(page, true);
    await page.route("**/api/v1/auth/enrol/begin", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          ceremony_id: "cer-1",
          publicKey: {
            rp: { name: "innsegl", id: "localhost" },
            user: { id: "dXNlcg", name: "operator", displayName: "Dev Operator" },
            challenge: "Y2hhbGxlbmdl",
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          },
        }),
      });
    });
    await page.route("**/api/v1/auth/enrol/finish", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          authenticated: true,
          display_name: "Dev Operator",
          recovery_codes: Array.from({ length: 10 }, (_, i) => `code-${i}-abcd`),
        }),
      });
    });
    await page.addInitScript(() => {
      // A fake, zero-interaction authenticator — this suite proves the
      // page's own flow, not a real platform passkey (that is `enrol`'s
      // own unit-level coverage in web/src).
      const credential = {
        id: "cred-1",
        rawId: "cred-1",
        type: "public-key",
        toJSON: () => ({ id: "cred-1", rawId: "cred-1", type: "public-key" }),
      };
      // `navigator.credentials` is a getter-only accessor on the Navigator
      // prototype; a plain assignment is a silent no-op (measured: the real
      // CredentialsContainer stayed in place and the ceremony hung on the
      // platform's own, headless-incapable prompt). `defineProperty` is
      // what actually replaces it for this page.
      Object.defineProperty(navigator, "credentials", {
        configurable: true,
        value: {
          create: async () => credential,
          get: async () => credential,
        },
      });
    });

    await page.goto("/setup?code=the-one-time-code");
    await page.getByLabel(/display name/i).fill("Dev Operator");
    await page.getByRole("button", { name: /create passkey/i }).click();

    await expect(page.getByRole("heading", { name: /save your recovery codes/i })).toBeVisible();
    await expect(page.getByText("code-0-abcd")).toBeVisible();
    await expect(page.getByRole("button", { name: /continue/i })).toBeDisabled();
    await page.getByRole("checkbox", { name: /i have saved these codes/i }).check();
    await expect(page.getByRole("button", { name: /continue/i })).toBeEnabled();
  });
});
