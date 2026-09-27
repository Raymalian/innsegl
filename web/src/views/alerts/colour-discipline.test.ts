// SPDX-License-Identifier: Apache-2.0
/// <reference types="vite/client" />

/*
 * FE-139 (NEW — proposed for doc 07 TC-FE; ADR-0054).
 *
 *   U | Static scan of web/src/views/alerts for colour that escaped the token
 *     sheet, and for any green at all | No colour literal, no hue word, no
 *     Tailwind default colour utility, no `dark:` variant, no direct palette
 *     reference, no `proof-verified` | FD §5.1, §5.3, §8/3; ADR-0038
 *
 * The same scan FE-077 runs over the overview, aimed at the notification menu
 * and the alert detail view. An alert is an integrity claim, never a
 * verification, so this directory may not spend a green at all.
 *
 * Comments are stripped before scanning: what is forbidden is naming a colour
 * in CODE.
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

const files: readonly Source[] = Object.entries(RAW)
  .map(([path, raw]) => ({ name: path.replace(/^\.\//, ""), raw, code: code(raw) }))
  .filter((file) => !/\.test\.tsx?$/.test(file.name))
  .sort((a, b) => a.name.localeCompare(b.name));

function offenders(pattern: RegExp): readonly string[] {
  return files
    .filter((file) => pattern.test(file.code))
    .map((file) => `${file.name}: ${pattern.exec(file.code)?.[0] ?? ""}`);
}

describe("FE-139 colour discipline in web/src/views/alerts", () => {
  it("is scanning real sources (a vacuous pass is not a pass)", () => {
    const names = files.map((f) => f.name);
    expect(names).toContain("styles.ts");
    expect(names).toContain("NotificationMenu.tsx");
    expect(names).toContain("AlertDetail.tsx");
    expect(files.length).toBeGreaterThan(5);
  });

  it("every file carries the SPDX header (doc 08 §1)", () => {
    expect(
      files
        .filter((f) => !f.raw.startsWith("// SPDX-License-Identifier: Apache-2.0"))
        .map((f) => f.name),
    ).toEqual([]);
  });

  it("spends no green: an alert is not a verification (§5.3, §8/3)", () => {
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
    const escaped: string[] = [];
    for (const file of files) {
      if (file.name === "styles.ts") continue;
      for (const utility of file.code.match(/\b(?:bg|border)-[a-z][a-z-]*/g) ?? []) {
        escaped.push(`${file.name}: ${utility}`);
      }
    }
    expect(escaped).toEqual([]);
  });
});
