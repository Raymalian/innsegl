// SPDX-License-Identifier: Apache-2.0

// FE-019 — system copy obeys doc 06 §6.1 and §5.4, checked mechanically.
//
// §6.1: "Banned vocabulary: 'successfully,' 'seamless,' 'trusted by,'
// exclamation marks in system copy." §5.4: "Sentence case everywhere. Labels
// without terminal punctuation; helper text with it."
//
// Those are rules a review enforces on the day someone looks. Because §6.3
// puts every string in one file, they can be enforced on every commit instead,
// which is the whole practical dividend of externalising the strings.

import { describe, expect, it } from "vitest";

import { en, flattenStrings } from "./strings";

const entries = flattenStrings(en);

// Words that may carry a capital inside a sentence. Short on purpose: adding
// one is a deliberate edit to this gate, defended in review, not a
// side effect of writing copy.
const PROPER_NOUNS = new Set([
  "Innsegl",
  "Fulcio",
  "Rekor",
  "Sigstore",
  "SPIFFE",
]);

const capitalised = (word: string) => /^[A-Z]/.test(word);

describe("FE-019 the catalogue is complete and reachable", () => {
  it("holds strings, and every one of them is a non-empty string", () => {
    expect(entries.length).toBeGreaterThan(10);
    for (const [key, value] of entries) {
      expect(typeof value, key).toBe("string");
      expect(value.trim(), key).not.toBe("");
      expect(value, key).toBe(value.trim());
      expect(value, key).not.toMatch(/ {2}/);
    }
  });

  it("separates labels from sentences, which is what makes §5.4 checkable", () => {
    expect(Object.keys(en)).toEqual(["labels", "sentences"]);
    expect(entries.some(([k]) => k.startsWith("labels."))).toBe(true);
    expect(entries.some(([k]) => k.startsWith("sentences."))).toBe(true);
  });
});

describe("FE-019 banned vocabulary (doc 06 §6.1)", () => {
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

describe("FE-019 sentence case (doc 06 §5.4)", () => {
  it.each(entries)("%s is sentence case", (key, value) => {
    // Sentence case is a property of each sentence, so a string carrying two
    // of them is split before the words after the first are examined.
    for (const sentence of value.split(/(?<=[.?])\s+/)) {
      for (const raw of sentence.split(/\s+/).slice(1)) {
        const word = raw.replace(/^[("']+|[)"'.,;:?]+$/g, "");
        if (word === "" || !capitalised(word)) continue;
        expect(
          PROPER_NOUNS.has(word),
          `${key}: "${word}" is capitalised mid-sentence and is not a known proper noun`,
        ).toBe(true);
      }
    }
  });

  it("starts every string with a capital or an identifier", () => {
    for (const [key, value] of entries) {
      expect(value[0], key).toMatch(/[A-Z0-9]/);
    }
  });
});

describe("FE-019 terminal punctuation (doc 06 §5.4)", () => {
  it("labels carry none", () => {
    for (const [key, value] of entries.filter(([k]) => k.startsWith("labels."))) {
      expect(value, key).not.toMatch(/[.!?]$/);
    }
  });

  it("sentences end in a full stop", () => {
    for (const [key, value] of entries.filter(([k]) =>
      k.startsWith("sentences."),
    )) {
      expect(value, key).toMatch(/\.$/);
    }
  });
});

describe("FE-019 the six views and the shell chrome are all named", () => {
  it("names every destination the nav rail offers", () => {
    expect(Object.keys(en.labels.views)).toEqual([
      "overview",
      "runs",
      "run",
      "repo",
      "agentType",
      "verify",
    ]);
  });
});
