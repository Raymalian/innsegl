// SPDX-License-Identifier: Apache-2.0

/*
 * FE-138 (NEW — proposed for doc 07 TC-FE; ADR-0054).
 *
 *   U | The notification menu's catalogue obeys doc 06 §6.1 and §5.4 | No
 *     banned vocabulary, no reassurance, sentence case, labels without
 *     terminal punctuation, helper text with it, and no word that offers to
 *     change an alert | FD §6.1, §5.4; ADR-0044
 *
 * The sibling of FE-019, FE-038 and FE-065, for the copy ADR-0054 added.
 */

import { describe, expect, it } from "vitest";

import { strings } from "./strings";

/** Every leaf. A function is called with a small count, a name and a time,
 * the only arguments this catalogue interpolates. */
function flatten(value: unknown, path = ""): [string, string][] {
  if (typeof value === "string") return [[path, value]];
  if (typeof value === "function") {
    const fn = value as (...args: unknown[]) => string;
    return [[path, fn(2, "operator", "2026-09-06 18:00:00 UTC")]];
  }
  if (typeof value === "object" && value !== null) {
    return Object.entries(value).flatMap(([key, inner]) =>
      flatten(inner, path === "" ? key : `${path}.${key}`),
    );
  }
  return [];
}

const entries = flatten(strings);

const PROPER_NOUNS = new Set(["Innsegl", "Fulcio", "Rekor", "Sigstore", "SPIFFE", "ID", "UTC"]);

const leaf = (key: string) => key.slice(key.lastIndexOf(".") + 1);
const isLabel = (key: string) =>
  ["label", "heading", "title"].includes(leaf(key)) || /(?:Label|Title)$/.test(leaf(key));
const isHelperText = (key: string) =>
  !isLabel(key) && (/(?:Detail|Status)$/.test(leaf(key)) || key.startsWith("alert.reasons."));

describe("FE-138 the catalogue is complete", () => {
  it("holds trimmed, non-empty strings", () => {
    expect(entries.length).toBeGreaterThan(20);
    for (const [key, value] of entries) {
      expect(value.trim(), key).not.toBe("");
      expect(value, key).toBe(value.trim());
      expect(value, key).not.toMatch(/ {2}/);
    }
  });
});

describe("FE-138 banned vocabulary (doc 06 §6.1) and read-only copy (ADR-0044)", () => {
  it.each(entries)("%s carries none of it", (key, value) => {
    expect(value, key).not.toMatch(/successful|seamless|trusted by/i);
    expect(value, key).not.toContain("!");
    expect(value, key).not.toMatch(/you're all set|all good|looks good|great|don't worry/i);
    expect(value, key).not.toMatch(/\bdismiss|mark as read|clear all/i);
  });
});

describe("FE-138 sentence case and punctuation (doc 06 §5.4)", () => {
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

  it("gives labels no terminal punctuation", () => {
    const labels = entries.filter(([key]) => isLabel(key));
    expect(labels.length).toBeGreaterThan(8);
    for (const [key, value] of labels) {
      expect(value, key).not.toMatch(/[.!?]$/);
    }
  });

  it("gives helper text its full stop", () => {
    const helper = entries.filter(([key]) => isHelperText(key));
    expect(helper.length).toBeGreaterThan(5);
    for (const [key, value] of helper) {
      expect(value, key).toMatch(/[.?]$/);
    }
  });
});
