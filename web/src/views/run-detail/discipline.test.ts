// SPDX-License-Identifier: Apache-2.0
/// <reference types="vite/client" />

/*
 * FE-086 (NEW — proposed for doc 07 TC-FE; listed in the report for #54).
 *
 *   U | Static scan of web/src/views/run-detail for colour and copy that
 *     escaped the token sheet and the string catalogue | No colour literal, no
 *     hue word, no Tailwind default colour utility, no `dark:` variant, no
 *     direct palette reference, no reference to the verification green
 *     anywhere in the directory, every surface and border colour confined to
 *     styles.ts, and every catalogue string obeying doc 06 §6.1 and §5.4 |
 *     FD §5.1, §5.3, §6.1, §5.4; ADR-0038 decisions 3 and 4
 *
 * The same shape as FE-034 (components/common) and FE-035 (verification), with
 * one rule the other two do not have and cannot have:
 *
 *   **`proof-verified` appears nowhere in this directory.**
 *
 * ADR-0038 decision 4 makes `--innsegl-color-proof-verified-*` the one route
 * to a green in the entire build, and doc 06 §5.3 gives that green exactly one
 * meaning. This view renders a run's history: a run that finished, a chain
 * link that holds, a repair that worked. Not one of those is a cryptographic
 * verification, and §5.3 names two of them as things that are specifically not
 * green ("not 'run completed'"). The only green on this page arrives inside
 * the three-check panel, which this view composes and does not restyle — so
 * the honest way to state the rule is that this directory cannot reach a green
 * at all, and this is where that is enforced.
 */

import { describe, expect, it } from "vitest";

import { strings } from "./strings";

const RAW = import.meta.glob("./*.{ts,tsx}", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

/** Comments out, string and code content in: doc 06 §5.3 and ADR-0038 are
 * quoted verbatim in the comments here, hue words and all. What is forbidden
 * is naming a colour in CODE. */
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

describe("FE-086 colour discipline in web/src/views/run-detail", () => {
  it("is scanning real sources (a vacuous pass is not a pass)", () => {
    const names = files.map((file) => file.name);
    expect(names).toContain("styles.ts");
    expect(names).toContain("TimelineNode.tsx");
    expect(names).toContain("RunDetailView.tsx");
    expect(files.length).toBeGreaterThan(8);
  });

  it("every file carries the SPDX header (doc 08 §1)", () => {
    expect(
      files
        .filter((file) => !file.raw.startsWith("// SPDX-License-Identifier: Apache-2.0"))
        .map((file) => file.name),
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

  it("cannot reach the verification green at all", () => {
    // The rule this directory has that the other two do not. A run that ended
    // is doc 06 §5.3's "not 'run completed'" in as many words.
    expect(offenders(/proof-verified/)).toEqual([]);
  });

  it("keeps every surface and border colour in styles.ts", () => {
    const allowed = new Set(["bg-hover", "border-solid"]);
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

/* ── the catalogue (doc 06 §6.1, §5.4) ─────────────────────────────────── */

function flatten(value: unknown, path = ""): [string, string][] {
  if (typeof value === "string") return [[path, value]];
  if (typeof value === "function") {
    const produced = (value as (...args: never[]) => string)(
      ...([1, "reconciler", "12 min"] as never[]),
    );
    return [[path, produced]];
  }
  if (typeof value === "object" && value !== null) {
    return Object.entries(value).flatMap(([key, inner]) =>
      flatten(inner, path === "" ? key : `${path}.${key}`),
    );
  }
  return [];
}

const entries = flatten(strings);

/** Words that may carry a capital inside a sentence. */
const PROPER_NOUNS = new Set([
  "API",
  "Agent-Identity",
  "Fulcio",
  "Innsegl",
  "JSON",
  "MCP",
  "Rekor",
  "SHA",
  "SPIFFE",
  "Sigstore",
]);

describe("FE-086 the run-detail catalogue", () => {
  it("holds strings, every one trimmed and non-empty", () => {
    expect(entries.length).toBeGreaterThan(40);
    for (const [key, value] of entries) {
      expect(value.trim(), key).not.toBe("");
      expect(value, key).toBe(value.trim());
      expect(value, key).not.toMatch(/ {2}/);
    }
  });

  it.each(entries)("%s carries no banned vocabulary (doc 06 §6.1)", (key, value) => {
    expect(value, key).not.toMatch(/successful/i);
    expect(value, key).not.toMatch(/seamless/i);
    expect(value, key).not.toMatch(/trusted by/i);
    expect(value, key).not.toContain("!");
    expect(value, key).not.toMatch(
      /you're all set|all good|looks good|everything checks/i,
    );
  });

  it.each(entries)("%s is sentence case (doc 06 §5.4)", (key, value) => {
    for (const sentence of value.split(/(?<=[.?])\s+/)) {
      for (const raw of sentence.split(/\s+/).slice(1)) {
        const word = raw.replace(/^[("'“]+|[)"'”.,;:?]+$/g, "");
        if (word === "" || !/^[A-Z]/.test(word)) continue;
        expect(
          PROPER_NOUNS.has(word),
          `${key}: "${word}" is capitalised mid-sentence and is not a known proper noun`,
        ).toBe(true);
      }
    }
  });

  const leaf = (key: string) => key.slice(key.lastIndexOf(".") + 1);
  const isHelperText = (key: string) =>
    leaf(key).endsWith("Detail") ||
    leaf(key).endsWith("Meaning") ||
    [
      "absent",
      "bodyNotStored",
      "detail",
      "noCommit",
      "noCredentials",
      "noDigest",
      "noEnd",
      "stale",
    ].includes(leaf(key));

  it("gives helper text its full stop", () => {
    const helper = entries.filter(([key]) => isHelperText(key));
    expect(helper.length).toBeGreaterThan(10);
    for (const [key, value] of helper) {
      expect(value, key).toMatch(/[.?]$/);
    }
  });

  it("gives labels no terminal punctuation", () => {
    const labels = entries.filter(
      ([key]) => !isHelperText(key) && ["heading", "label", "title"].includes(leaf(key)),
    );
    expect(labels.length).toBeGreaterThan(0);
    for (const [key, value] of labels) {
      expect(value, key).not.toMatch(/[.!?]$/);
    }
  });

  it("keeps doc 02 §2's protected source values out of the copy itself", () => {
    // `source: reconciler` is assembled from the ledger's own enum value at
    // render time, so a translator cannot alter a protected string by editing
    // this catalogue. What is in the catalogue is the word around it.
    const literal = entries.filter(([, value]) => /^source: /.test(value));
    expect(literal.map(([key]) => key)).toEqual(["event.source"]);
  });
});
