// SPDX-License-Identifier: Apache-2.0
/// <reference types="vite/client" />

/*
 * FE-047 and FE-048 (NEW — proposed for doc 07 TC-FE; see the report for #55).
 *
 *   FE-047 | U | Static scan of web/src/views/repo and web/src/views/agent-type
 *     for colour that escaped the token sheet, and for any route to the
 *     verification green | No colour literal, no hue word, no Tailwind default
 *     colour utility, no `dark:` variant, no palette reference, and no
 *     `proof-verified` anywhere | FD §5.1, §5.3, §8 anti-pattern 3;
 *     ADR-0038 decisions 3 and 4
 *
 *   FE-048 | U | Both views' string catalogues obey doc 06 §6.1's voice and
 *     §5.4's casing and punctuation | No banned vocabulary, no exclamation,
 *     sentence case, labels without terminal punctuation, sentences with it |
 *     FD §6.1, §5.4, §8 anti-pattern 9
 *
 * The colour half is the source-level twin of doc 07's FE-013, which is a
 * rendered-output audit at the end of Phase 4. Both are worth having: this one
 * fails on the commit that introduces the violation.
 *
 * Both directories are scanned from one file because one agent owns both, and
 * a second copy of this file is a second place for the two to drift apart.
 * The vacuity guards below name a file from each, so a glob that stopped
 * matching one of them cannot leave this passing on the other alone.
 *
 * Comments are stripped before the colour scan: doc 06 §5.3 and ADR-0038 are
 * quoted verbatim in several of these files, hue words and all. What is
 * forbidden is naming a colour in CODE.
 */

import { describe, expect, it } from "vitest";

import { flattenStrings, type StringTree } from "../../app/strings";
import { strings as repoStrings } from "./strings";
import { strings as agentTypeStrings } from "../agent-type/strings";

/* ── the sources ──────────────────────────────────────────────────────────── */

const RAW: Record<string, string> = {
  ...(import.meta.glob("./*.{ts,tsx}", {
    query: "?raw",
    import: "default",
    eager: true,
  }) as Record<string, string>),
  ...(import.meta.glob("../agent-type/*.{ts,tsx}", {
    query: "?raw",
    import: "default",
    eager: true,
  }) as Record<string, string>),
};

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
  .map(([path, raw]) => ({
    name: path.replace(/^\.\//, "repo/").replace(/^\.\.\//, ""),
    raw,
    code: code(raw),
  }))
  .filter((file) => !/\.test\.tsx?$/.test(file.name))
  .sort((a, b) => a.name.localeCompare(b.name));

function offenders(pattern: RegExp): readonly string[] {
  return files
    .filter((file) => pattern.test(file.code))
    .map((file) => `${file.name}: ${pattern.exec(file.code)?.[0] ?? ""}`);
}

describe("FE-047 colour discipline in the repo and agent-type views", () => {
  it("is scanning real sources from both directories (a vacuous pass is not a pass)", () => {
    const names = files.map((f) => f.name);
    expect(names).toContain("repo/RepoView.tsx");
    expect(names).toContain("repo/styles.ts");
    expect(names).toContain("agent-type/AgentTypeView.tsx");
    expect(names).toContain("agent-type/styles.ts");
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

  it("names no route to the verification green (doc 06 §5.3)", () => {
    // Green belongs to the three-check panel alone. These two views hold no
    // proof, so there is nothing here a green could be about.
    expect(offenders(/proof-verified/)).toEqual([]);
    expect(offenders(/VerificationBadge|VerificationPanel|VerificationSummary/)).toEqual([]);
  });

  it("keeps every surface and border colour in each directory's styles.ts", () => {
    const allowed = new Set(["bg-hover", "bg-raised", "border-solid", "border-collapse"]);
    const escaped: string[] = [];
    for (const file of files) {
      if (file.name.endsWith("/styles.ts")) continue;
      for (const utility of file.code.match(/\b(?:bg|border)-[a-z][a-z-]*/g) ?? []) {
        if (!allowed.has(utility)) escaped.push(`${file.name}: ${utility}`);
      }
    }
    expect(escaped).toEqual([]);
  });
});

/* ── the copy ─────────────────────────────────────────────────────────────── */

const PROPER_NOUNS = new Set([
  "Innsegl",
  "Fulcio",
  "Rekor",
  "Sigstore",
  "SPIFFE",
  "Agent-Identity",
  // An acronym, which stays capitalised in sentence case. Adding a word here
  // is a deliberate edit to this gate, defended in review, not a side effect
  // of writing copy.
  "API",
]);

const catalogues: ReadonlyArray<[string, StringTree]> = [
  ["repo", repoStrings as unknown as StringTree],
  ["agent-type", agentTypeStrings as unknown as StringTree],
];

const entries: ReadonlyArray<[string, string]> = catalogues.flatMap(([name, tree]) =>
  flattenStrings(tree).map(([key, value]): [string, string] => [`${name}.${key}`, value]),
);

describe("FE-048 the catalogues are complete and reachable", () => {
  it("holds strings, and every leaf of both catalogues is one", () => {
    expect(entries.length).toBeGreaterThan(30);
    for (const [name, tree] of catalogues) {
      expect(Object.keys(tree), name).toEqual(["labels", "nouns", "sentences"]);
    }
    for (const [key, value] of entries) {
      expect(typeof value, key).toBe("string");
      expect(value.trim(), key).not.toBe("");
      expect(value, key).toBe(value.trim());
      expect(value, key).not.toMatch(/ {2}/);
    }
  });

  it("holds no value that is not a string, so nothing escapes the scan", () => {
    const walk = (tree: StringTree, prefix: string): void => {
      for (const [key, value] of Object.entries(tree)) {
        const path = `${prefix}.${key}`;
        expect(["string", "object"], path).toContain(typeof value);
        if (typeof value !== "string") walk(value, path);
      }
    };
    for (const [name, tree] of catalogues) walk(tree, name);
  });
});

describe("FE-048 banned vocabulary (doc 06 §6.1)", () => {
  it.each(entries)("%s carries none of it", (key, value) => {
    expect(value, key).not.toMatch(/successful/i);
    expect(value, key).not.toMatch(/seamless/i);
    expect(value, key).not.toMatch(/trusted by/i);
    expect(value, key).not.toContain("!");
  });

  it("also refuses the reassurance §8's anti-pattern 9 names", () => {
    for (const [key, value] of entries) {
      expect(value, key).not.toMatch(/you're all set|all good|looks good|great/i);
    }
  });
});

describe("FE-048 sentence case and punctuation (doc 06 §5.4)", () => {
  it.each(entries)("%s is sentence case", (key, value) => {
    for (const sentence of value.split(/(?<=[.?])\s+/)) {
      for (const raw of sentence.split(/\s+/).slice(1)) {
        const word = raw.replace(/^[("']+|[)"'.,;:?]+$/g, "");
        if (word === "" || !/^[A-Z]/.test(word)) continue;
        expect(
          PROPER_NOUNS.has(word),
          `${key}: "${word}" is capitalised mid-sentence and is not a known proper noun`,
        ).toBe(true);
      }
    }
  });

  it("labels carry no terminal punctuation", () => {
    for (const [key, value] of entries.filter(([k]) => k.includes(".labels."))) {
      expect(value, key).not.toMatch(/[.!?]$/);
      expect(value[0], key).toMatch(/[A-Z0-9]/);
    }
  });

  it("sentences end in a full stop", () => {
    for (const [key, value] of entries.filter(([k]) => k.includes(".sentences."))) {
      expect(value, key).toMatch(/\.$/);
      expect(value[0], key).toMatch(/[A-Z0-9]/);
    }
  });

  it("nouns are the fragments another sentence swallows, so they start lower case", () => {
    // `nouns` exists because LoadingState renders "Loading {what}…": what goes
    // in there is neither a label nor a sentence, and holding it to either
    // rule would produce a capital in the middle of a sentence.
    for (const [key, value] of entries.filter(([k]) => k.includes(".nouns."))) {
      expect(value, key).toMatch(/^[a-z]/);
      expect(value, key).not.toMatch(/[.!?]$/);
    }
  });
});
