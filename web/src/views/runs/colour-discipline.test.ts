// SPDX-License-Identifier: Apache-2.0
/// <reference types="vite/client" />

/*
 * FE-054 (NEW — proposed for doc 07 TC-FE; see the report for #53).
 *
 *   U | Static scan of web/src/views/runs for colour that escaped the token
 *     sheet | No colour literal, no hue word, no Tailwind default colour
 *     utility, no `dark:` variant, no direct palette reference; no file in the
 *     directory names a verification colour at all | FD §5.1, §5.3; ADR-0038
 *     decisions 3 and 4
 *
 * The third sibling of FE-034 (components/common) and FE-035
 * (components/verification), and it is a separate ID for the reason those two
 * are separate from each other: the directories are governed differently in
 * one place. FE-035's directory is allowed a green. This one is allowed none
 * — not `proof-verified`, not `proof-failed`, not `proof-unavailable` — and
 * that is the assertion at the bottom of this file.
 *
 * A runs row renders a verdict by handing a proof to VerificationSummary, and
 * in no other way. If a row ever spends a verdict colour directly it will be
 * because someone wanted a badge without the panel behind it, which is doc 06
 * §8's anti-pattern 4; this scan turns that into a failing test on the commit
 * rather than a finding in a review months later.
 *
 * Comments are stripped before scanning. doc 06 §5.3 and ADR-0038 are quoted
 * verbatim in several files here, hue words and all; what is forbidden is
 * naming a colour in CODE.
 */

const RAW = import.meta.glob("./*.{ts,tsx}", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

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

function offenders(pattern: RegExp): readonly string[] {
  return files
    .filter((file) => pattern.test(file.code))
    .map((file) => `${file.name}: ${pattern.exec(file.code)?.[0] ?? ""}`);
}

describe("FE-054 colour discipline in web/src/views/runs", () => {
  it("is scanning real sources (a vacuous pass is not a pass)", () => {
    const names = files.map((f) => f.name);
    expect(names).toContain("styles.ts");
    expect(names).toContain("RunsTable.tsx");
    expect(names).toContain("RunsView.tsx");
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

  it("spends no verdict colour anywhere, styles.ts included", () => {
    /* The rule this directory is governed by. A run row is not a
     * cryptographic verification: it reaches a verdict's colour only by
     * handing a proof to components/verification, which owns all three. */
    expect(offenders(/\bproof-(?:verified|failed|unavailable)\b/)).toEqual([]);
    expect(offenders(/\b(?:text|bg|border)-(?:degraded|integrity-alert|mismatch)\b/)).toEqual([]);
  });
});
