// SPDX-License-Identifier: Apache-2.0
/// <reference types="vite/client" />

/*
 * FE-064 (NEW — proposed for doc 07 TC-FE; see the report for #56).
 *
 *   U | Static scan of web/src/views/public-verify for colour that escaped the
 *     token sheet | No colour literal, no hue word, no Tailwind default colour
 *     utility, no `dark:` variant, no direct palette reference; every surface
 *     and border colour in styles.ts; and NO GREEN anywhere in the directory |
 *     FD §5.1, §5.3, §8.3; ADR-0038 decisions 3 and 4
 *
 * The third sibling of FE-034 (components/common) and FE-035
 * (components/verification), and it is a separate ID for the same reason those
 * two are: the directories are governed differently in exactly one place.
 * FE-035's directory is where a green is legitimate. THIS one is not, and the
 * last assertion below is the whole reason this file exists rather than a
 * widened glob.
 *
 * doc 06 §5.3: "Green = cryptographic verification passed. Nothing else is
 * ever green." This view renders a great deal that a designer would reach for
 * a green for — an upstream that answered, a finding that agrees, a log entry
 * whose time the log signed. None of them is a cryptographic verification.
 * Every one of them is a fact ABOUT a verification, and doc 06 §8's
 * anti-pattern 3 is what it would be to colour them like the verification.
 *
 * So the only green on this page comes from the three-check panel, which this
 * view renders and does not restyle. FE-007 asserts that from rendered output
 * over ten failure modes; this asserts it from the sources, on every commit,
 * with no browser.
 */

const RAW = import.meta.glob("./*.{ts,tsx}", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

/** Comments out, code in. doc 06 §5.3 and ADR-0038 are quoted verbatim in
 * several files here, hue words and all; a rule that forbade citing the
 * specification would be a bad rule. What is forbidden is a colour in CODE. */
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

describe("FE-064 colour discipline in web/src/views/public-verify", () => {
  it("is scanning real sources (a vacuous pass is not a pass)", () => {
    const names = files.map((f) => f.name);
    expect(names).toContain("styles.ts");
    expect(names).toContain("PublicVerifyView.tsx");
    expect(names).toContain("ProofChain.tsx");
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
    const escaped: string[] = [];
    for (const file of files) {
      if (file.name === "styles.ts") continue;
      for (const utility of file.code.match(/\b(?:bg|border)-[a-z][a-z-]*/g) ?? []) {
        escaped.push(`${file.name}: ${utility}`);
      }
    }
    expect(escaped).toEqual([]);
  });

  /*
   * The assertion this file exists for.
   *
   * `proof-verified` is the only route to a green in the build (ADR-0038
   * decision 4). components/verification/styles.ts names it, and that is
   * correct there. Naming it HERE would be this view deciding that something
   * on this page is a cryptographic verification — and everything on this page
   * that is one is rendered by the panel.
   */
  it("spends no green: the verdict's colour belongs to the panel", () => {
    expect(offenders(/proof-verified/)).toEqual([]);
  });

  it("renders no verification tone of its own at all", () => {
    // Not just the green. A view that reached for `proof-failed` or
    // `proof-unavailable` would be putting a second verdict on the page beside
    // the panel's, which doc 06 §4.1 and §8's anti-pattern 4 are both about.
    expect(offenders(/\bproof-(?:failed|unavailable)\b/)).toEqual([]);
  });
});
