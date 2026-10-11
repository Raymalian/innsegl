// SPDX-License-Identifier: Apache-2.0

/*
 * FE-154 (#616): the banner shown when the CA cannot sign, and the unlock
 * page it opens, have no WCAG 2.1 AA violations, and the unlock page takes
 * the keyboard focus to its heading. The account page's own axe pass
 * (tests/a11y/account.pw.ts) covers the unlock-keys section itself.
 */

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { answerAccountRoute } from "../support/account-mocks";

async function lockedCA(page: Page): Promise<void> {
  await page.route("**/api/v1/**", async (route) => {
    const p = new URL(route.request().url()).pathname;
    const json = (b: unknown) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(b) });
    if (p === "/api/v1/auth/session") return json({ authenticated: true, display_name: "Dev Operator" });
    if (p === "/api/v1/auth/setup") return json({ needed: false });
    if (p === "/api/v1/account/ca-custody") {
      return json({ enabled: true, initialized: true, sealed: true, can_sign: false, reason: "the CA key store is sealed" });
    }
    if (await answerAccountRoute(route)) return;
    return route.fulfill({ status: 500, contentType: "application/json", body: "{}" });
  });
}

async function axe(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(
    results.violations,
    results.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.length} node(s))`).join("\n"),
  ).toEqual([]);
}

test("FE-154: the cannot-sign banner and the unlock page pass axe, and the page takes focus", async ({ page }) => {
  await lockedCA(page);
  await page.goto("/account");
  await expect(page.getByText("The CA cannot sign")).toBeVisible();
  await expect(page.getByRole("table", { name: "Unlock keys" })).toBeVisible();
  await axe(page);

  await page.getByRole("button", { name: "Unlock with a security key" }).click();
  await expect(page.getByRole("heading", { name: "Unlock the CA key store" })).toBeFocused();
  await axe(page);
});
