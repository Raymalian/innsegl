// SPDX-License-Identifier: Apache-2.0

/*
 * E28 (#486, #481): the invitation page and the organisation switcher, in a
 * real Chromium, with axe in both themes and the switcher driven from the
 * keyboard (FE-142, FE-143).
 */

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page, type Route } from "@playwright/test";

import { installAccountMocks } from "../support/account-mocks";

const CODE = "iv_" + "a".repeat(64);

async function json(route: Route, body: unknown, status = 200) {
  await route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}

async function noViolations(page: Page) {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(
    results.violations,
    results.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.length} node(s))`).join("\n"),
  ).toEqual([]);
}

async function invitationMocks(page: Page, signedIn: boolean, usable = true) {
  await page.route("**/api/v1/**", async (route) => {
    const p = new URL(route.request().url()).pathname;
    if (p === "/api/v1/auth/session") {
      return json(route, signedIn ? { authenticated: true, display_name: "Dev Operator" } : { authenticated: false });
    }
    if (p === "/api/v1/auth/setup") return json(route, { needed: false });
    if (p === "/api/v1/auth/invitation") {
      return usable
        ? json(route, {
            organisation_id: "b".repeat(32),
            organisation: "example-team",
            role: "member",
            expires_at: "2026-10-13T12:00:00Z",
          })
        : json(route, { error: { code: "not_found", message: "that invitation link is not usable" } }, 404);
    }
    return json(route, { error: { code: "unmocked", message: `no fixture for ${p}` } }, 500);
  });
}

for (const scheme of ["light", "dark"] as const) {
  test(`FE-143: the invitation page for a new person has no violations (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await invitationMocks(page, false);
    await page.goto(`/invite#${CODE}`);
    await expect(page.getByText(/invited to example-team as a member/)).toBeVisible();
    await expect(page.getByLabel("Display name")).toBeVisible();
    await noViolations(page);
  });

  test(`FE-143: the invitation page for a signed-in person has no violations (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await invitationMocks(page, true);
    await page.goto(`/invite#${CODE}`);
    await expect(page.getByRole("button", { name: "Join", exact: true })).toBeVisible();
    await noViolations(page);
  });
}

test("FE-143: an unusable invitation link says so, with no violations", async ({ page }) => {
  await invitationMocks(page, false, false);
  await page.goto(`/invite#${CODE}`);
  await expect(page.getByRole("heading", { name: "This invitation link is not usable" })).toBeVisible();
  await noViolations(page);
});

test("FE-142: the organisation switcher is labelled, keyboard-operable and violation-free", async ({ page }) => {
  await installAccountMocks(page);
  await page.route("**/api/v1/auth/session", (route) =>
    json(route, {
      authenticated: true,
      display_name: "Dev Operator",
      organisations: [
        { id: "a".repeat(32), name: "example-org", role: "owner", operator: true },
        { id: "b".repeat(32), name: "example-team", role: "member", operator: false },
      ],
    }),
  );
  await page.goto("/account");
  const switcher = page.getByRole("combobox", { name: "Organisation" });
  await expect(switcher).toBeVisible();
  await switcher.focus();
  const outline = await switcher.evaluate((el) => getComputedStyle(el).outlineStyle);
  expect(outline).not.toBe("none");
  await switcher.selectOption("b".repeat(32));
  await expect
    .poll(async () => (await page.context().cookies()).find((c) => c.name === "innsegl_organisation")?.value)
    .toBe("b".repeat(32));
  await noViolations(page);
});
