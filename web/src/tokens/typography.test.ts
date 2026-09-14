// SPDX-License-Identifier: Apache-2.0

/*
 * FE-115 and FE-116 — doc 06 §5.2, amended 2026-09-14 by the operator.
 *
 *   "Three families ... A display serif for view headings and the largest
 *    metric figures; a neutral sans for UI text; a monospace for every
 *    identifier, hash, PEM block, and log excerpt (P4)."
 *
 *   "The families are bundled, never fetched. The dashboard ships as a
 *    container and is expected to work offline; a runtime request to a font
 *    host would be both an outside dependency and a record of who opened the
 *    page, sent to a third party. Self-hosted or it does not ship."
 *
 * The second half is the one that needs a gate. A `@import` of a font host is
 * one line, it looks exactly like the line every tutorial shows, and it fails
 * in none of the ways a reviewer notices: the page renders, the tests pass,
 * the build succeeds, and the only symptom is a request to somebody else's
 * server carrying the reader's address — in a product whose whole subject is
 * who did what. So it is parsed rather than reviewed.
 *
 * This is the SOURCE half. FE-117 is the runtime half: a real browser loading
 * all six views and issuing no cross-origin request at all.
 */

import { readFileSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(here, "../..");

const TOKENS = readFileSync(resolve(here, "tokens.css"), "utf8");
const THEME = readFileSync(resolve(here, "tailwind-theme.css"), "utf8");
const ENTRY = readFileSync(resolve(webRoot, "src/app/index.css"), "utf8");
const FONTS_PATH = resolve(webRoot, "src/app/fonts.css");

/** The three families doc 06 §5.2 names, and the generic each must fall back
 * to when a face has not loaded — which is every deployment of the standalone
 * page in web/site/, which loads tokens.css and bundles nothing. */
const FAMILIES = [
  { token: "--innsegl-font-family-serif", bundled: "IBM Plex Serif", generic: "serif" },
  { token: "--innsegl-font-family-sans", bundled: "IBM Plex Sans", generic: "sans-serif" },
  { token: "--innsegl-font-family-mono", bundled: "IBM Plex Mono", generic: "monospace" },
] as const;

function declaration(sheet: string, token: string): string {
  const match = new RegExp(`${token}\\s*:\\s*([^;]+);`).exec(sheet);
  return match?.[1]?.trim() ?? "";
}

describe("FE-115 the three families are tokens", () => {
  it("declares a serif beside the sans and the mono", () => {
    for (const family of FAMILIES) {
      expect(declaration(TOKENS, family.token)).not.toEqual("");
    }
  });

  it("names the bundled face first and a generic last", () => {
    for (const family of FAMILIES) {
      const value = declaration(TOKENS, family.token);
      expect(value.startsWith(`"${family.bundled}"`)).toBe(true);
      expect(value.endsWith(family.generic)).toBe(true);
    }
  });

  it("reaches components only through the theme, one token to one utility", () => {
    for (const family of FAMILIES) {
      const utility = family.token.replace("--innsegl-font-family-", "--font-");
      expect(declaration(THEME, utility)).toEqual(`var(${family.token})`);
    }
  });
});

describe("FE-116 the families are bundled, never fetched", () => {
  it("has a stylesheet that declares the faces, and the entry loads it", () => {
    expect(existsSync(FONTS_PATH)).toBe(true);
    expect(ENTRY).toMatch(/@import\s+"\.\/fonts\.css"/);
  });

  it("pulls every face from a package in this build, not from a host", () => {
    const fonts = readFileSync(FONTS_PATH, "utf8");
    const imports = [...fonts.matchAll(/@import\s+"([^"]+)"/g)].map((m) => m[1] ?? "");
    // Three families, and every weight this product actually sets.
    expect(imports.length).toBeGreaterThanOrEqual(7);
    for (const specifier of imports) {
      expect(specifier).not.toMatch(/^(?:https?:)?\/\//);
      const file = resolve(webRoot, "node_modules", specifier);
      expect(existsSync(file)).toBe(true);
      // And the face file the @font-face points at is beside it on disk.
      const face = readFileSync(file, "utf8");
      const urls = [...face.matchAll(/url\(([^)]+)\)/g)].map((m) =>
        (m[1] ?? "").replace(/['"]/g, "").trim(),
      );
      expect(urls.length).toBeGreaterThan(0);
      for (const url of urls) {
        expect(url).not.toMatch(/^(?:https?:)?\/\//);
        expect(existsSync(resolve(dirname(file), url))).toBe(true);
      }
    }
  });

  it("names no font host anywhere a browser would read one", () => {
    const surfaces: readonly (readonly [string, string])[] = [
      ["src/tokens/tokens.css", TOKENS],
      ["src/tokens/tailwind-theme.css", THEME],
      ["src/app/index.css", ENTRY],
      ["src/app/fonts.css", readFileSync(FONTS_PATH, "utf8")],
      ["index.html", readFileSync(resolve(webRoot, "index.html"), "utf8")],
      ["site/public/tokens.css", readFileSync(resolve(webRoot, "site/public/tokens.css"), "utf8")],
      ["site/public/site.css", readFileSync(resolve(webRoot, "site/public/site.css"), "utf8")],
    ];
    // Any absolute or protocol-relative reference at all: naming the known
    // hosts would be a list somebody adds a new name to rather than a rule.
    const remote = /(?:@import|url\(|<link[^>]*href=)\s*['"]?(?:https?:)?\/\//i;
    expect(
      surfaces.filter(([, text]) => remote.test(text)).map(([name]) => name),
    ).toEqual([]);
  });

  it("the standalone page's copy of the sheet carries the same families", () => {
    const site = readFileSync(resolve(webRoot, "site/public/tokens.css"), "utf8");
    for (const family of FAMILIES) {
      expect(declaration(site, family.token)).toEqual(declaration(TOKENS, family.token));
    }
  });
});
