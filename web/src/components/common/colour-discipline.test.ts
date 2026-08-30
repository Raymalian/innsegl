// SPDX-License-Identifier: Apache-2.0
/// <reference types="vite/client" />

/*
 * FE-034 (NEW — proposed for doc 07 TC-FE; see the report for #50).
 *
 *   U | Static scan of web/src/components/common for colour that escaped the
 *     token sheet | No colour literal, no hue word, no Tailwind default colour
 *     utility, no `dark:` variant, no direct palette reference | FD §5.1,
 *     §5.3; ADR-0038 decisions 3 and 4
 *
 * doc 07's FE-013 is the rendered-output half of this ("scan rendered views
 * for green tokens"), and it is the right check — but it cannot run until
 * there are views, and it finds a violation at the end of Phase 4. This is the
 * source half, it runs today, and it fails on the commit that introduces the
 * violation rather than at the review that comes months later.
 *
 * ADR-0038 leaves exactly one escape hatch open on purpose: Tailwind's
 * arbitrary-value syntax still compiles, so `bg-[#00ff00]` is legal CSS. It is
 * left open because it is greppable — and this is the grep.
 *
 * Comments are stripped before scanning. doc 06 §5.3 and ADR-0038 are quoted
 * verbatim in the comments of several files here, hue words and all; a rule
 * that forbade citing the specification would be a bad rule. What is forbidden
 * is naming a colour in CODE.
 *
 * The sources are read through Vite's `import.meta.glob(..., '?raw')` rather
 * than through `node:fs`, because @types/node is not a dependency of this
 * workspace and issue #50 may not add one.
 */

const RAW = import.meta.glob("./*.{ts,tsx}", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

/** Comments out, string and code content in. */
function code(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

interface Source {
  readonly name: string;
  readonly raw: string;
  readonly code: string;
}

/* Tests are excluded: they name the very things they forbid, which is what a
 * test for a naming rule has to do. */
const files: readonly Source[] = Object.entries(RAW)
  .map(([path, raw]) => ({ name: path.replace(/^\.\//, ""), raw, code: code(raw) }))
  .filter((file) => !/\.test\.tsx?$/.test(file.name))
  .sort((a, b) => a.name.localeCompare(b.name));

/** Report every offender at once; one name in a failure message is a worse
 * failure message than all of them. */
function offenders(pattern: RegExp): readonly string[] {
  return files
    .filter((file) => pattern.test(file.code))
    .map((file) => `${file.name}: ${pattern.exec(file.code)?.[0] ?? ""}`);
}

describe("FE-034 colour discipline in web/src/components/common", () => {
  it("is scanning real sources (a vacuous pass is not a pass)", () => {
    expect(files.map((f) => f.name)).toContain("styles.ts");
    expect(files.map((f) => f.name)).toContain("StatusBadge.tsx");
    expect(files.length).toBeGreaterThan(8);
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
    // `bg-slate-500` and friends: a prefix, a name, a numeric step.
    expect(
      offenders(
        /\b(?:bg|text|border|outline|fill|stroke|ring|divide|decoration|shadow|from|via|to)-[a-z]+-(?:50|[1-9]00|950)\b/,
      ),
    ).toEqual([]);
  });

  it("carries no dark: variant (ADR-0038 decision 3)", () => {
    // Every token is a light-dark() pair inside the sheet, so a dark: variant
    // in a component is a colour decision that escaped it.
    expect(offenders(/\bdark:/)).toEqual([]);
  });

  it("reaches the palette only through the semantic layer", () => {
    expect(offenders(/--innsegl-palette-/)).toEqual([]);
  });

  it("keeps every surface and border colour in styles.ts", () => {
    // One file to audit for doc 06 §5.3, which is the point of having it.
    const allowed = new Set(["bg-hover", "bg-raised", "border-solid"]);
    const escaped: string[] = [];
    for (const file of files) {
      if (file.name === "styles.ts") continue;
      for (const utility of file.code.match(/\b(?:bg|border)-[a-z][a-z-]*/g) ??
        []) {
        if (!allowed.has(utility)) escaped.push(`${file.name}: ${utility}`);
      }
    }
    expect(escaped).toEqual([]);
  });
});
