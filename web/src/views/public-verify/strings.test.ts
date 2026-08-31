// SPDX-License-Identifier: Apache-2.0

/*
 * FE-065 (NEW — proposed for doc 07 TC-FE; see the report for #56).
 *
 *   U | The public page's catalogue obeys doc 06 §6.1 and §5.4 | No banned
 *     vocabulary, no reassurance in place of evidence, sentence case, labels
 *     without terminal punctuation, and doc 06 §6.1's model error copy used
 *     verbatim for the case it was written for | FD §6.1, §5.4, §8.9, §3.6
 *
 * The sibling of FE-019 (the shell's catalogue) and FE-038 (the panel's), and
 * the reason for a third is doc 06 §6.1 itself. That section gives exactly one
 * worked example of the voice it wants, and the example is about THIS PAGE:
 *
 *   "Errors state what failed and what the user can do: 'Fulcio unreachable —
 *    verification can't run. Retry, or verify offline with the material
 *    below.'"
 *
 * So this file does what the other two cannot: it holds the copy to the
 * specification's own sentence rather than to the specification's rules about
 * sentences. If someone later softens that wording, this is what says no.
 */

import { describe, expect, it } from "vitest";

import { strings, upstreamName } from "./strings";

/** Every leaf, with the path that reaches it. A function is called with a
 * proper noun, because the arguments this catalogue interpolates are upstream
 * names and a placeholder that is not one would fail the casing rule for a
 * reason that has nothing to do with the copy. */
function flatten(value: unknown, path = ""): [string, string][] {
  if (typeof value === "string") return [[path, value]];
  if (typeof value === "function") {
    return [[path, (value as (arg: string) => string)("Fulcio")]];
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
  "Innsegl",
  "Fulcio",
  "Rekor",
  "Sigstore",
  "SPIFFE",
  "SHA",
  "SHA-256",
  "ID",
  "UUID",
  "URI",
  "SAN",
  "Agent-Identity",
  "Agent-Run",
  "Agent-Task",
]);

describe("FE-065 the catalogue is complete and reachable", () => {
  it("holds strings, and every one of them is trimmed and non-empty", () => {
    expect(entries.length).toBeGreaterThan(30);
    for (const [key, value] of entries) {
      expect(value.trim(), key).not.toBe("");
      expect(value, key).toBe(value.trim());
      expect(value, key).not.toMatch(/ {2}/);
    }
  });
});

describe("FE-065 banned vocabulary (doc 06 §6.1)", () => {
  it.each(entries)("%s carries none of it", (key, value) => {
    expect(value, key).not.toMatch(/successful/i);
    expect(value, key).not.toMatch(/seamless/i);
    expect(value, key).not.toMatch(/trusted by/i);
    expect(value, key).not.toContain("!");
  });

  it("substitutes no reassurance for evidence (§8 anti-pattern 9)", () => {
    for (const [key, value] of entries) {
      expect(value, key).not.toMatch(
        /you're all set|all good|looks good|great|everything checks|don't worry/i,
      );
    }
  });
});

describe("FE-065 sentence case and punctuation (doc 06 §5.4)", () => {
  it.each(entries)("%s is sentence case", (key, value) => {
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

  /* §5.4's two halves are told apart by the leaf key, which is the naming
   * convention this catalogue is written to. A leaf outside both sets is left
   * unconstrained rather than guessed at: a rule that fires on a key nobody
   * classified is a rule that gets silenced. */
  const leaf = (key: string) => key.slice(key.lastIndexOf(".") + 1);
  const isLabel = (key: string) =>
    ["label", "heading", "title"].includes(leaf(key)) || /(?:Label|Title)$/.test(leaf(key));
  const isHelperText = (key: string) =>
    !isLabel(key) &&
    (["detail", "hint", "intro"].includes(leaf(key)) || /(?:Detail|Hint)$/.test(leaf(key)));

  it("gives labels no terminal punctuation", () => {
    const labels = entries.filter(([key]) => isLabel(key));
    expect(labels.length).toBeGreaterThan(8);
    for (const [key, value] of labels) {
      expect(value, key).not.toMatch(/[.!?]$/);
    }
  });

  it("gives helper text its full stop", () => {
    const helper = entries.filter(([key]) => isHelperText(key));
    expect(helper.length).toBeGreaterThan(8);
    for (const [key, value] of helper) {
      expect(value, key).toMatch(/[.?]$/);
    }
  });
});

describe("FE-065 doc 06 §6.1's model error copy, used where it was written for", () => {
  it("says what failed, in the specification's own words", () => {
    expect(strings.blocked.title("Fulcio")).toBe(
      "Fulcio unreachable — verification can't run",
    );
  });

  it("says what the reader can do, in the specification's own words", () => {
    expect(strings.blocked.detail).toBe(
      "Retry, or verify offline with the material below.",
    );
  });

  it("names both upstreams when both are gone", () => {
    expect(strings.blocked.title("Fulcio, Rekor")).toContain("Fulcio, Rekor");
  });

  /* An upstream the response never mentioned is neither "reachable" nor
   * "unreachable", and doc 06 P2 is the rule against giving it either word. */
  it("has separate copy for an upstream that reported nothing at all", () => {
    expect(strings.blocked.silent("Rekor")).not.toContain("unreachable");
    expect(strings.blocked.silent("Rekor")).toContain("did not report a live check");
  });
});

describe("FE-065 the page states what it cannot do", () => {
  it("tells the reader up front that no ledger answer is available here (I5)", () => {
    expect(strings.page.intro).toContain("no access to the ledger");
  });

  it("distinguishes an unreachable deployment from an unreadable answer (P2)", () => {
    expect(strings.failure.unreachableTitle).not.toBe(strings.failure.malformedTitle);
    expect(strings.failure.notFoundTitle).not.toBe(strings.failure.rejectedTitle);
    expect(
      new Set([
        strings.failure.unreachableTitle,
        strings.failure.malformedTitle,
        strings.failure.notFoundTitle,
        strings.failure.rejectedTitle,
      ]).size,
    ).toBe(4);
  });

  it("does not claim a re-derivation the response did not carry", () => {
    expect(strings.rederivation.absent).toContain("no re-derivation");
  });
});

describe("FE-065 upstream names", () => {
  it("reads internal/api's lower-case names as prose", () => {
    expect(upstreamName("fulcio")).toBe("Fulcio");
    expect(upstreamName("rekor")).toBe("Rekor");
  });

  it("leaves an upstream this build does not know under its own spelling", () => {
    // Renaming a dependency in the interface would hide which one it was.
    expect(upstreamName("ctlog")).toBe("ctlog");
  });
});
