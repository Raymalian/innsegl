// SPDX-License-Identifier: Apache-2.0

/*
 * #445 (ADR-0062's accounts amendment) — the account page's own axe pass and
 * keyboard walkthrough, doc 07's FE-009 pattern applied to the profile,
 * passkeys table, add-a-passkey form and recovery-codes section.
 *
 * RM-333 (#511) adds the organisation sections, the minted-token panel,
 * the sign-ins and the header's account menu. The fixtures live in
 * tests/support/account-mocks.ts, shared with the visual suite.
 */

import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { installAccountMocks, installFakePasskey } from "../support/account-mocks";

test("RM-279: the account page has no WCAG 2.1 AA violations", async ({ page }) => {
  await installAccountMocks(page);
  await page.goto("/account");
  await expect(page.getByRole("heading", { name: "Account", exact: true })).toBeVisible();
  await expect(page.getByText("MacBook", { exact: true })).toBeVisible();
  // RM-333: every section loads its own read; wait for the last ones.
  await expect(page.getByText("This browser")).toBeVisible();
  await expect(page.getByRole("link", { name: "claude-code" })).toBeVisible();

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
  await installAccountMocks(page);
  await page.goto("/account");
  await expect(page.getByText("MacBook", { exact: true })).toBeVisible();
  // RM-333: every section loads its own read; wait for the last ones.
  await expect(page.getByText("This browser")).toBeVisible();
  await expect(page.getByRole("link", { name: "claude-code" })).toBeVisible();

  const targets = [
    page.getByRole("button", { name: "Edit" }),
    page.getByRole("button", { name: "Copy user ID" }),
    page.getByRole("button", { name: "Revoke" }).first(),
    page.getByRole("combobox", { name: "Kind" }),
    page.getByRole("button", { name: "Connect a machine" }),
    page.getByRole("link", { name: "github.com/example/app" }),
    page.getByRole("link", { name: "claude-code" }),
    page.getByRole("button", { name: "Rename" }).first(),
    page.getByRole("button", { name: "Remove" }).first(),
    page.getByRole("button", { name: "Add a passkey" }),
    page.getByRole("button", { name: "Generate new codes" }),
    page.getByRole("button", { name: "Sign out other sign-ins" }),
  ];

  for (const target of targets) {
    await target.focus();
    await expect(target).toBeFocused();
    const outline = await target.evaluate((el) => getComputedStyle(el).outlineStyle);
    expect(outline, `${await target.textContent()} painted no visible outline`).not.toBe("none");
  }
});

test("RM-333: the header's account menu opens from the keyboard, has no violations open, and reaches /account", async ({
  page,
}) => {
  await installAccountMocks(page);
  await page.goto("/");
  const menuButton = page.getByRole("button", { name: "Dev Operator" });
  await expect(menuButton).toHaveAttribute("aria-haspopup", "menu");
  await menuButton.focus();
  await page.keyboard.press("ArrowDown");
  const accountItem = page.getByRole("menuitem", { name: "Account" });
  await expect(accountItem).toBeFocused();
  await expect(page.getByRole("menuitem", { name: "Sign out" })).toBeVisible();

  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(
    results.violations,
    results.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.length} node(s))`).join("\n"),
  ).toEqual([]);

  await page.keyboard.press("Escape");
  await expect(menuButton).toBeFocused();
  await menuButton.click();
  await page.getByRole("menuitem", { name: "Account" }).click();
  await expect(page.getByRole("heading", { name: "Account", exact: true })).toBeVisible();
});

test("RM-333: the minted enrolment token and its command have no violations", async ({ page }) => {
  await installFakePasskey(page);
  await installAccountMocks(page);
  await page.goto("/account");
  await page.getByRole("button", { name: "Connect a machine" }).click();
  await expect(page.getByRole("button", { name: "Copy command" })).toBeVisible();

  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(
    results.violations,
    results.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.length} node(s))`).join("\n"),
  ).toEqual([]);
});
