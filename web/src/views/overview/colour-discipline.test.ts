// SPDX-License-Identifier: Apache-2.0
/// <reference types="vite/client" />

/*
 * FE-077 (NEW — proposed for doc 07 TC-FE; see the report for #52).
 *
 *   U | Static scan of web/src/views/overview for colour that escaped the
 *     token sheet, and for any green at all | No colour literal, no hue word,
 *     no Tailwind default colour utility, no `dark:` variant, no direct
 *     palette reference, no `proof-verified` | FD §5.1, §5.3, §8/3; ADR-0038
 *
 * The same scan `components/common/colour-discipline.test.ts` (FE-034) runs
 * over that directory, with one rule added that belongs only to a view: this
 * directory may not spend a green AT ALL. `text-proof-verified` is the only
 * route to one in the build, doc 06 §5.3 gives it to cryptographic
 * verification alone, and this view performs none — it counts rows and reports
 * how late an anchor is. FE-013 is the rendered-output half and runs at the
 * end of Phase 4; this is the source half and fails on the commit that
 * introduces the violation.
 *
 * Comments are stripped before scanning: doc 06 §5.3 and ADR-0038 are quoted
 * verbatim in several files here, hue words and all. What is forbidden is
 * naming a colour in CODE.
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

const files: readonly Source[] = Object.entries(RAW)
  .map(([path, raw]) => ({ name: path.replace(/^\.\//, ""), raw, code: code(raw) }))
  .filter((file) => !/\.test\.tsx?$/.test(file.name))
  .sort((a, b) => a.name.localeCompare(b.name));

function offenders(pattern: RegExp): readonly string[] {
  return files
    .filter((file) => pattern.test(file.code))
    .map((file) => `${file.name}: ${pattern.exec(file.code)?.[0] ?? ""}`);
}

describe("FE-077 colour discipline in web/src/views/overview", () => {
  it("is scanning real sources (a vacuous pass is not a pass)", () => {
    const names = files.map((f) => f.name);
    expect(names).toContain("styles.ts");
    expect(names).toContain("PassRateCard.tsx");
    expect(names).toContain("AnchoringPulse.tsx");
    expect(files.length).toBeGreaterThan(6);
  });

  it("every file carries the SPDX header (doc 08 §1)", () => {
    expect(
      files
        .filter((f) => !f.raw.startsWith("// SPDX-License-Identifier: Apache-2.0"))
        .map((f) => f.name),
    ).toEqual([]);
  });

  it("spends no green: this view verifies nothing (§5.3, §8/3)", () => {
    expect(offenders(/proof-verified/)).toEqual([]);
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
    const allowed = new Set(["bg-hover", "bg-raised", "border-solid", "border-t"]);
    const escaped: string[] = [];
    for (const file of files) {
      if (file.name === "styles.ts") continue;
      for (const utility of file.code.match(/\b(?:bg|border)-[a-z][a-z-]*/g) ?? []) {
        if (!allowed.has(utility)) escaped.push(`${file.name}: ${utility}`);
      }
    }
    expect(escaped).toEqual([]);
  });
});
