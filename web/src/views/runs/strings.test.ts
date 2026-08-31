// SPDX-License-Identifier: Apache-2.0

/*
 * FE-056 (NEW — proposed for doc 07 TC-FE; see the report for #53).
 *
 *   U | The runs view's copy obeys doc 06 §6.1 and §5.4 | No banned
 *     vocabulary, sentence case, labels without terminal punctuation and
 *     helper text with it — over the catalogue AND over the strings that take
 *     an argument | FD §5.4, §6.1, §6.3
 *
 * FE-019 does this for the shell's catalogue. It cannot do it for this one:
 * `flattenStrings` walks a tree of strings, and this view's counts and captions
 * are functions, which a tree-walker skips silently. A rule that stops applying
 * the moment a string takes a number is a rule with a hole in exactly the place
 * doc 06 §6.2 cares about ("Counts are exact, never rounded vanity numbers").
 *
 * So the functions are called and their output is checked with the same rules.
 * The walker itself is imported from src/app rather than copied, so a change to
 * how the shell flattens a catalogue reaches this one too.
 */

import { describe, expect, it } from "vitest";

import { flattenStrings } from "../../app/strings";
import { strings } from "./strings";

const entries: Array<[string, string]> = [
  ...flattenStrings(strings.labels, "labels"),
  ...flattenStrings(strings.sentences, "sentences"),
];

/** What every format string produces, split the way §5.4 splits copy: a
 * caption and a count are labels, a stated bound is helper text. */
const formatted: Array<[string, string]> = [
  ["labels.formats.caption", strings.formats.caption(3, 4_000_000)],
  ["labels.formats.showing", strings.formats.showing(3, 4_000_000)],
  ["labels.formats.commits.one", strings.formats.commits(1)],
  ["labels.formats.commits.many", strings.formats.commits(0)],
  ["sentences.formats.bounded", strings.formats.bounded(200)],
];

const all = [...entries, ...formatted];

/* Words that may carry a capital inside a sentence, plus initialisms. Short on
 * purpose: adding one is a deliberate edit to this gate. */
const PROPER_NOUNS = new Set(["Innsegl", "Fulcio", "Rekor", "Sigstore", "SPIFFE"]);
const isInitialism = (word: string) => /^[A-Z]{2,}s?$/.test(word);

describe("FE-056 the catalogue is complete and reachable", () => {
  it("holds strings, and every one of them is a trimmed, non-empty string", () => {
    expect(entries.length).toBeGreaterThan(15);
    for (const [key, value] of all) {
      expect(typeof value, key).toBe("string");
      expect(value.trim(), key).not.toBe("");
      expect(value, key).toBe(value.trim());
      expect(value, key).not.toMatch(/ {2}/);
    }
  });

  it("separates labels from sentences, which is what makes §5.4 checkable", () => {
    expect(Object.keys(strings)).toEqual([
      "labels",
      "sentences",
      "fragments",
      "formats",
    ]);
    expect(entries.some(([k]) => k.startsWith("labels."))).toBe(true);
    expect(entries.some(([k]) => k.startsWith("sentences."))).toBe(true);
  });

  it("names doc 06 §3.2's five columns and no sixth", () => {
    expect(Object.keys(strings.labels.columns)).toEqual([
      "runId",
      "task",
      "repo",
      "commits",
      "status",
    ]);
  });

  it("offers a control for each of doc 06 §3.2's five filters", () => {
    for (const filter of ["repo", "agentType", "status", "from", "to", "search"]) {
      expect(Object.keys(strings.labels.filters)).toContain(filter);
    }
  });
});

describe("FE-056 banned vocabulary (doc 06 §6.1)", () => {
  it.each(all)("%s carries none of it", (key, value) => {
    expect(value, key).not.toMatch(/successful/i);
    expect(value, key).not.toMatch(/seamless/i);
    expect(value, key).not.toMatch(/trusted by/i);
    expect(value, key).not.toContain("!");
    expect(value, key).not.toMatch(/you're all set|all good|looks good|great/i);
  });
});

describe("FE-056 sentence case (doc 06 §5.4)", () => {
  it.each(all)("%s is sentence case", (key, value) => {
    for (const sentence of value.split(/(?<=[.?])\s+/)) {
      for (const raw of sentence.split(/\s+/).slice(1)) {
        const word = raw.replace(/^[("'—]+|[)"'.,;:?]+$/g, "");
        if (word === "" || !/^[A-Z]/.test(word)) continue;
        expect(
          PROPER_NOUNS.has(word) || isInitialism(word),
          `${key}: "${word}" is capitalised mid-sentence and is neither a known proper noun nor an initialism`,
        ).toBe(true);
      }
    }
  });

  it("starts every string with a capital or a number", () => {
    for (const [key, value] of all) {
      expect(value[0], key).toMatch(/[A-Z0-9]/);
    }
  });

  it("keeps the one fragment lower case, because it is never seen whole", () => {
    /* `fragments.what` is interpolated by LoadingState into "Loading runs…".
     * Capitalising it would put a capital in the middle of a sentence, which
     * is the rule above read backwards — so it lives outside `labels` rather
     * than being exempted from a check it would otherwise fail. */
    expect(strings.fragments.what).toBe(strings.fragments.what.toLowerCase());
    expect(strings.fragments.what).not.toMatch(/[.!?]$/);
  });
});

describe("FE-056 terminal punctuation (doc 06 §5.4)", () => {
  it("labels carry none", () => {
    for (const [key, value] of all.filter(([k]) => k.startsWith("labels."))) {
      expect(value, key).not.toMatch(/[.!?]$/);
    }
  });

  it("helper text ends in a full stop", () => {
    for (const [key, value] of all.filter(([k]) => k.startsWith("sentences."))) {
      expect(value, key).toMatch(/\.$/);
    }
  });
});

describe("FE-056 counts are exact (doc 06 §6.2)", () => {
  it("spells a large total in full rather than rounding it", () => {
    expect(strings.formats.showing(50, 4_182_913)).toContain("4182913");
    expect(strings.formats.caption(50, 4_182_913)).toContain("4182913");
  });

  it("agrees with itself about one commit and about none", () => {
    expect(strings.formats.commits(1)).toBe("1 commit");
    expect(strings.formats.commits(0)).toBe("0 commits");
    expect(strings.formats.commits(2)).toBe("2 commits");
  });
});
