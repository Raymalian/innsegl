// SPDX-License-Identifier: Apache-2.0
/// <reference types="vite/client" />

/*
 * FE-035 (NEW — proposed for doc 07 TC-FE; see the report for #51).
 *
 *   U | Static scan of web/src/components/verification for colour that escaped
 *     the token sheet | No colour literal, no hue word, no Tailwind default
 *     colour utility, no `dark:` variant, no direct palette reference; every
 *     semantic colour named in styles.ts alone | FD §5.1, §5.3; ADR-0038
 *     decisions 3 and 4
 *
 * The sibling of FE-034, which scans web/src/components/common. It is a
 * separate ID rather than a widened glob because the two directories are
 * governed differently in exactly one place: FE-034 asserts that NOTHING in
 * common is green, and this directory is the one place in the product where a
 * green is legitimate. A single test could not say both.
 *
 * Everything else is the same rule, and the reason for the rule is the same:
 * one file to audit for doc 06 §5.3.
 */

const RAW = import.meta.glob("./*.{ts,tsx}", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

/** Comments out, code in. The specification is quoted verbatim above and in
 * several files here, hue words and all; what is forbidden is a colour in
 * CODE. */
function code(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

interface Source {
  readonly name: string;
  readonly raw: string;
  readonly code: string;
}

const files: readonly Source[] = Object.entries(RAW)
  .map(([path, raw]) => ({ name: path.replace(/^\.\//, ""), raw, code: code(raw) }))
  .filter((file) => !/\.test\.tsx?$/.test(file.name))
  .sort((a, b) => a.name.localeCompare(b.name));

function offenders(pattern: RegExp): readonly string[] {
  return files
    .filter((file) => pattern.test(file.code))
    .map((file) => `${file.name}: ${pattern.exec(file.code)?.[0] ?? ""}`);
}

describe("FE-035 colour discipline in web/src/components/verification", () => {
  it("is scanning real sources (a vacuous pass is not a pass)", () => {
    const names = files.map((f) => f.name);
    expect(names).toContain("styles.ts");
    expect(names).toContain("VerificationPanel.tsx");
    expect(files.length).toBeGreaterThan(5);
  });

  it("every file carries the SPDX header (doc 08 §1)", () => {
    expect(
      files
        .filter((f) => !f.raw.startsWith("// SPDX-License-Identifier: Apache-2.0"))
        .map((f) => f.name),
    ).toEqual([]);
  });

  it("names no colour value", () => {
    expect(offenders(/#[0-9a-fA-F]{3,8}\b/)).toEqual([]);
    expect(offenders(/\b(?:rgba?|hsla?|oklch|lab|color-mix)\(/)).toEqual([]);
  });

  it("names no hue", () => {
    expect(
      offenders(
        /\b(?:green|red|amber|yellow|orange|lime|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose|magenta)\b/i,
      ),
    ).toEqual([]);
  });

  it("uses no Tailwind default colour utility", () => {
    expect(
      offenders(
        /\b(?:bg|text|border|outline|fill|stroke|ring|divide|decoration|shadow|from|via|to)-[a-z]+-(?:50|[1-9]00|950)\b/,
      ),
    ).toEqual([]);
  });

  it("carries no dark: variant (ADR-0038 decision 3)", () => {
    expect(offenders(/\bdark:/)).toEqual([]);
  });

  it("reaches the palette only through the semantic layer", () => {
    expect(offenders(/--innsegl-palette-/)).toEqual([]);
  });

  it("keeps every surface and border colour in styles.ts", () => {
    const allowed = new Set(["border-solid"]);
    const escaped: string[] = [];
    for (const file of files) {
      if (file.name === "styles.ts") continue;
      for (const utility of file.code.match(/\b(?:bg|border)-[a-z][a-z-]*/g) ?? []) {
        if (!allowed.has(utility)) escaped.push(`${file.name}: ${utility}`);
      }
    }
    expect(escaped).toEqual([]);
  });

  it("spends the only green in the product from one file, and names it there", () => {
    // doc 06 §5.3's rule has one consumer in the whole build. A reviewer
    // asking "where is the green" reads styles.ts and is done.
    const spenders = files.filter((f) => /proof-verified/.test(f.code)).map((f) => f.name);
    expect(spenders).toEqual(["styles.ts"]);
  });
});
