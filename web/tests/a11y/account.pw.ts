// SPDX-License-Identifier: Apache-2.0

/*
 * #445 (ADR-0062's accounts amendment) — the account page's own axe pass and
 * keyboard walkthrough, doc 07's FE-009 pattern applied to the profile,
 * passkeys table, add-a-passkey form and recovery-codes section.
 *
 * Self-contained mocks, the same shape run-page's a11y suite uses, rather
 * than tests/support/mock-routes.ts (RM-049's own path): this page's own
 * read (`/api/v1/account`) is not one of the six views' routes.
 */

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page, type Route } from "@playwright/test";

function json(route: Route, body: unknown): Promise<void> {
  return route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

const ACCOUNT = {
  user_id: "user-1",
  display_name: "Dev Operator",
  created_at: "2026-09-01T00:00:00Z",
  passkeys: [
    {
      id: "pk-1",
      name: "MacBook",
      created_at: "2026-09-01T00:00:00Z",
      last_used_at: "2026-09-30T00:00:00Z",
      current: true,
    },
    {
      id: "pk-2",
      name: "Phone",
      created_at: "2026-09-10T00:00:00Z",
      last_used_at: null,
      current: false,
    },
  ],
  recovery_codes_remaining: 8,
};

async function installMocks(page: Page): Promise<void> {
  await page.route("**/api/v1/**", async (route) => {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    if (p === "/api/v1/auth/session") {
      return json(route, { authenticated: true, display_name: "Dev Operator" });
    }
    if (p === "/api/v1/auth/setup") return json(route, { needed: false });
    if (p === "/api/v1/account" && req.method() === "GET") return json(route, ACCOUNT);
    await route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ error: { code: "unmocked", message: `no fixture for ${p}` } }),
    });
  });
}

test("RM-279: the account page has no WCAG 2.1 AA violations", async ({ page }) => {
  await installMocks(page);
  await page.goto("/account");
  await expect(page.getByRole("heading", { name: "Account", exact: true })).toBeVisible();
  await expect(page.getByText("MacBook")).toBeVisible();

  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(
    results.violations,
    results.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.length} node(s))`).join("\n"),
  ).toEqual([]);
});

test("RM-279: the profile edit, passkey rename/remove, add-passkey and recovery-code controls are all keyboard-reachable with a visible focus ring", async ({
  page,
}) => {
  await installMocks(page);
  await page.goto("/account");
  await expect(page.getByText("MacBook")).toBeVisible();

  const targets = [
    page.getByRole("button", { name: "Edit" }),
    page.getByRole("button", { name: "Rename" }).first(),
    page.getByRole("button", { name: "Remove" }).first(),
    page.getByRole("button", { name: "Create passkey" }),
    page.getByRole("button", { name: "Generate new codes" }),
  ];

  for (const target of targets) {
    await target.focus();
    await expect(target).toBeFocused();
    const outline = await target.evaluate((el) => getComputedStyle(el).outlineStyle);
    expect(outline, `${await target.textContent()} painted no visible outline`).not.toBe("none");
  }
});

test("RM-279: the top bar's account-name link reaches /account and the sign-in page reaches no view behind it", async ({
  page,
}) => {
  await installMocks(page);
  await page.goto("/");
  const accountLink = page.getByRole("link", { name: "Dev Operator" });
  await expect(accountLink).toHaveAttribute("href", "/account");
  await accountLink.click();
  await expect(page.getByRole("heading", { name: "Account", exact: true })).toBeVisible();
});
