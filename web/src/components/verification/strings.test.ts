// SPDX-License-Identifier: Apache-2.0

/*
 * FE-038 (NEW — proposed for doc 07 TC-FE; see the report for #51).
 *
 *   U | The verification catalogue obeys doc 06 §6.1 and §5.4 | No banned
 *     vocabulary, no reassurance in place of evidence, sentence case, labels
 *     without terminal punctuation | FD §6.1, §5.4, §8.9
 *
 * FE-019 does this for the shell's catalogue in web/src/app/strings.ts. The
 * same rules govern this component's copy and nothing was checking them here.
 *
 * §8's anti-pattern 9 — "Celebratory or reassuring copy substituting for
 * evidence" — is the one that matters most in this file of all files. This is
 * the component that says "verified", and the difference between a product
 * that means it and one that does not is visible in its wording.
 */

import { describe, expect, it } from "vitest";

import { strings } from "./strings";

/** Every leaf string, with the path that reaches it. Functions are called with
 * a placeholder so an interpolated sentence is checked too. */
function flatten(value: unknown, path = ""): [string, string][] {
  if (typeof value === "string") return [[path, value]];
  if (typeof value === "function") {
    const produced = (value as (...args: string[]) => string)("segment", "reason");
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

/** Words that may carry a capital inside a sentence. Same shape as FE-019's
 * list, plus the two protected strings this component has to name. */
const PROPER_NOUNS = new Set([
  "Innsegl",
  "Fulcio",
  "Rekor",
  "Sigstore",
  "SPIFFE",
  "Agent-Identity",
  "URI",
  "SAN",
]);

describe("FE-038 the catalogue is complete and reachable", () => {
  it("holds strings, and every one of them is trimmed and non-empty", () => {
    expect(entries.length).toBeGreaterThan(15);
    for (const [key, value] of entries) {
      expect(value.trim(), key).not.toBe("");
      expect(value, key).toBe(value.trim());
      expect(value, key).not.toMatch(/ {2}/);
    }
  });
});

describe("FE-038 banned vocabulary (doc 06 §6.1)", () => {
  it.each(entries)("%s carries none of it", (key, value) => {
    expect(value, key).not.toMatch(/successful/i);
    expect(value, key).not.toMatch(/seamless/i);
    expect(value, key).not.toMatch(/trusted by/i);
    expect(value, key).not.toContain("!");
  });

  it("substitutes no reassurance for evidence (§8 anti-pattern 9)", () => {
    for (const [key, value] of entries) {
      expect(value, key).not.toMatch(/you're all set|all good|looks good|great|everything checks/i);
    }
  });
});

describe("FE-038 sentence case and punctuation (doc 06 §5.4)", () => {
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

  /* §5.4: "Labels without terminal punctuation; helper text with it." The two
   * halves are told apart by the leaf key, which is the naming convention this
   * catalogue is written to: a `label`, a `heading` or a `title` is a label; a
   * `meaning`, a `detail` and every downgrade reason is helper text. A leaf
   * outside both sets is left unconstrained rather than guessed at, because a
   * rule that fires on a key nobody classified is a rule that gets silenced. */
  const leaf = (key: string) => key.slice(key.lastIndexOf(".") + 1);
  const isLabel = (key: string) => ["label", "heading", "title"].includes(leaf(key));
  const isHelperText = (key: string) =>
    ["meaning", "detail"].includes(leaf(key)) || key.startsWith("downgrade.");

  it("gives labels no terminal punctuation", () => {
    const labels = entries.filter(([key]) => isLabel(key));
    expect(labels.length).toBeGreaterThan(4);
    for (const [key, value] of labels) {
      expect(value, key).not.toMatch(/[.!?]$/);
    }
  });

  it("gives helper text its full stop", () => {
    const helper = entries.filter(([key]) => isHelperText(key));
    expect(helper.length).toBeGreaterThan(4);
    for (const [key, value] of helper) {
      expect(value, key).toMatch(/[.?]$/);
    }
  });
});

describe("FE-038 the three states are three words", () => {
  it("gives verified, failed and unavailable distinct labels", () => {
    const labels = [
      strings.verdict.verified.label,
      strings.verdict.failed.label,
      strings.verdict.unavailable.label,
      strings.verdict.unattributed.label,
    ];
    expect(new Set(labels).size).toBe(4);
  });

  it("never lets 'unavailable' read as either of the other two (doc 06 P2)", () => {
    const unavailable = strings.verdict.unavailable.label.toLowerCase();
    expect(unavailable).not.toContain("fail");
    expect(unavailable).not.toContain("verified");
  });

  it("names the three checks in doc 06 §4.1's own words", () => {
    expect(strings.checks.certificateChain).toBe("Fulcio certificate chain valid");
    expect(strings.checks.rekorInclusion).toBe("Rekor inclusion proven");
    expect(strings.checks.trailerIdentity).toBe("Trailer matches certificate identity");
  });
});
