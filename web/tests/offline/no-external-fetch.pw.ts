// SPDX-License-Identifier: Apache-2.0

/*
 * FE-117 — no view issues a cross-origin request.
 *
 * doc 06 §5.2, amended 2026-09-14 by the operator:
 *
 *   "The families are bundled, never fetched. The dashboard ships as a
 *    container and is expected to work offline; a runtime request to a font
 *    host would be both an outside dependency and a record of who opened the
 *    page, sent to a third party. Self-hosted or it does not ship."
 *
 * FE-116 is the source half — it reads the stylesheets and refuses a remote
 * `@import` or `url()`. This is the half that cannot be argued with: a real
 * Chromium loads all six views and every request it makes is recorded. A font
 * pulled in transitively by a dependency, a stylesheet that resolved to a CDN
 * at build time, an image nobody noticed — none of them survive this, and none
 * of them would have been caught by reading web/src.
 *
 * The reasoning is not really about fonts. A dashboard whose subject is who
 * did what, which tells a third party who is reading it, is a product arguing
 * against its own thesis. The fonts are simply the most common way it happens.
 *
 * `data:` and `blob:` are not requests to anybody: they are bytes the page
 * already had. Everything else must be same-origin.
 */

import { expect, test } from "@playwright/test";

import { installApiMocks } from "../support/mock-routes";
import { VIEWS } from "../support/views";

/** A request that leaves nobody's machine. */
function isLocalScheme(url: string): boolean {
  return url.startsWith("data:") || url.startsWith("blob:") || url.startsWith("about:");
}

test.describe("FE-117: the dashboard fetches nothing from anybody else", () => {
  for (const view of VIEWS) {
    test(`${view.name} makes no cross-origin request`, async ({ page, baseURL }) => {
      const origin = new URL(baseURL ?? "http://127.0.0.1").origin;
      const foreign: string[] = [];

      // Every request the page makes, including the ones a stylesheet starts
      // — fonts, images, imports — not only the ones script issues.
      page.on("request", (request) => {
        const url = request.url();
        if (isLocalScheme(url)) return;
        if (new URL(url).origin !== origin) foreign.push(`${request.resourceType()} ${url}`);
      });

      await installApiMocks(page);
      await page.goto(view.path);
      await expect(page).toHaveTitle(view.title);
      // Faces are requested lazily, when something is laid out in them. Waiting
      // for the font set to settle is what makes this test about fonts at all.
      await page.evaluate(() => document.fonts.ready);

      expect(foreign, foreign.join("\n")).toEqual([]);
    });
  }
});

test.describe("FE-117: the faces the page renders in are the bundled ones", () => {
  test("all three families load, and they load from this origin", async ({
    page,
    baseURL,
  }) => {
    const origin = new URL(baseURL ?? "http://127.0.0.1").origin;
    const fonts: string[] = [];
    page.on("request", (request) => {
      if (request.resourceType() === "font") fonts.push(request.url());
    });

    await installApiMocks(page);
    await page.goto("/");
    await page.evaluate(() => document.fonts.ready);

    // A page that loaded no face at all would pass the cross-origin test above
    // while rendering in the reader's system stack — the exact silent failure
    // "bundled, never fetched" is written against, arrived at from the other
    // side.
    expect(fonts.length, "no face was loaded at all").toBeGreaterThan(0);
    for (const url of fonts) expect(new URL(url).origin).toEqual(origin);

    const loaded = await page.evaluate(() =>
      [...document.fonts].filter((face) => face.status === "loaded").map((face) => face.family),
    );
    expect([...new Set(loaded)].sort()).toEqual([
      "IBM Plex Mono",
      "IBM Plex Sans",
      "IBM Plex Serif",
    ]);
  });

  test("the view heading resolves to the serif and the body to the sans", async ({
    page,
  }) => {
    // Loading a face and RENDERING in it are two different facts, and the
    // second is the one doc 06 §5.2 is about. A token nothing resolves to is
    // the failure this closes: the sheet names the family, the theme exposes
    // it, the heading carries the utility — and none of that is a measurement
    // of what the browser actually drew.
    await installApiMocks(page);
    await page.goto("/");
    await page.evaluate(() => document.fonts.ready);

    const families = await page.evaluate(() => {
      const first = (node: Element | null) =>
        node === null ? "" : getComputedStyle(node).fontFamily.split(",")[0]?.trim() ?? "";
      return {
        heading: first(document.querySelector("h1")),
        body: first(document.body),
        identifier: first(document.querySelector("[data-identifier-display]")),
      };
    });

    expect(families.heading.replace(/["']/g, "")).toEqual("IBM Plex Serif");
    expect(families.body.replace(/["']/g, "")).toEqual("IBM Plex Sans");
    // doc 06 P4: an identifier is never proportional.
    expect(families.identifier.replace(/["']/g, "")).toEqual("IBM Plex Mono");
  });
});
