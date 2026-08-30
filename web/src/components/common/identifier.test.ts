// SPDX-License-Identifier: Apache-2.0

/*
 * FE-008 (doc 07, TC-FE) — identifier chip, truncation half.
 *
 *   "Mono, middle truncation preserves trust domain + last segment, copy
 *    works, full value accessible to AT"  — proves FD P4, §4.3
 *
 * doc 06 P4 adds the rule the catalogue compresses: identifiers "truncate
 * intelligently (never mid-segment)", and doc 06 §8 anti-pattern 6 makes
 * "truncated so the trust domain is lost" a defect. This file tests the pure
 * function; IdentifierChip.test.tsx tests the rendered component.
 */

import {
  ELLIPSIS,
  trustDomainOf,
  truncateIdentifier,
} from "./identifier";

/* Realistic material, not toy strings: a full SPIFFE ID under the reference
 * trust domain doc 06 uses in examples, and a real-length 40-hex commit SHA. */
const SPIFFE =
  "spiffe://innsegl.dev/agent/fix-ci/run/01HQ8Z9K2MJT4V6XR3B7YN5PDC";
const TRUST_DOMAIN = "spiffe://innsegl.dev";
const LAST_SEGMENT = "01HQ8Z9K2MJT4V6XR3B7YN5PDC";
const SHA = "9f2c1a4e7b60d38f5c91ae02d746b8130fca5e29";

describe("FE-008 truncateIdentifier — segmented identifiers", () => {
  it("keeps the trust domain and the final segment at every width", () => {
    // Every width from absurdly narrow to wider than the value itself.
    for (let maxLength = 4; maxLength <= SPIFFE.length + 8; maxLength += 1) {
      const out = truncateIdentifier(SPIFFE, { kind: "spiffe", maxLength });
      expect(out.startsWith(TRUST_DOMAIN)).toBe(true);
      expect(out.endsWith(LAST_SEGMENT)).toBe(true);
    }
  });

  it("never cuts mid-segment: every retained run of characters is whole segments", () => {
    const wholeSegments = new Set(SPIFFE.split("/"));
    for (let maxLength = 4; maxLength <= SPIFFE.length; maxLength += 1) {
      const out = truncateIdentifier(SPIFFE, { kind: "spiffe", maxLength });
      if (!out.includes(ELLIPSIS)) {
        expect(out).toBe(SPIFFE);
        continue;
      }
      const [head, tail] = out.split(ELLIPSIS);
      // The join characters around the ellipsis are segment separators, so
      // stripping them must leave only segments that appear in the original.
      const headSegments = head!.replace(/\/$/, "").split("/");
      const tailSegments = tail!.replace(/^\//, "").split("/");
      for (const segment of [...headSegments, ...tailSegments]) {
        expect(wholeSegments.has(segment)).toBe(true);
      }
      // ...and the head/tail must still be a prefix/suffix of the original.
      expect(SPIFFE.startsWith(head!.replace(/\/$/, ""))).toBe(true);
      expect(SPIFFE.endsWith(tail!.replace(/^\//, ""))).toBe(true);
    }
  });

  it("truncates in the middle, not at either end", () => {
    const out = truncateIdentifier(SPIFFE, { kind: "spiffe", maxLength: 40 });
    expect(out).toContain(ELLIPSIS);
    expect(out.startsWith(ELLIPSIS)).toBe(false);
    expect(out.endsWith(ELLIPSIS)).toBe(false);
    expect(out.length).toBeLessThan(SPIFFE.length);
  });

  it("returns the value untouched when it already fits", () => {
    expect(
      truncateIdentifier(SPIFFE, { kind: "spiffe", maxLength: 200 }),
    ).toBe(SPIFFE);
  });

  it("refuses to cut rather than lose a segment it cannot shorten", () => {
    // Nothing between the trust domain and the final segment: there is no
    // middle to drop, so the honest answer is the whole value.
    const short = "spiffe://innsegl.dev/01HQ8Z9K2MJT4V6XR3B7YN5PDC";
    expect(truncateIdentifier(short, { kind: "spiffe", maxLength: 12 })).toBe(
      short,
    );
  });

  it("reads the trust domain as scheme plus authority", () => {
    expect(trustDomainOf(SPIFFE)).toBe(TRUST_DOMAIN);
    expect(trustDomainOf(SHA)).toBeNull();
  });
});

describe("FE-008 truncateIdentifier — single-token identifiers", () => {
  it("preserves both ends of a 40-character SHA", () => {
    const out = truncateIdentifier(SHA, { kind: "sha", maxLength: 16 });
    expect(out).toContain(ELLIPSIS);
    expect(out.length).toBe(16);
    const [head, tail] = out.split(ELLIPSIS);
    expect(head!.length).toBeGreaterThan(0);
    expect(tail!.length).toBeGreaterThan(0);
    expect(SHA.startsWith(head!)).toBe(true);
    expect(SHA.endsWith(tail!)).toBe(true);
  });

  it("keeps both ends of a SHA at every width it is given", () => {
    for (let maxLength = 5; maxLength <= SHA.length + 4; maxLength += 1) {
      const out = truncateIdentifier(SHA, { kind: "sha", maxLength });
      if (!out.includes(ELLIPSIS)) {
        expect(out).toBe(SHA);
        continue;
      }
      const [head, tail] = out.split(ELLIPSIS);
      expect(head!.length).toBeGreaterThan(0);
      expect(tail!.length).toBeGreaterThan(0);
      expect(SHA.startsWith(head!)).toBe(true);
      expect(SHA.endsWith(tail!)).toBe(true);
      expect(out.length).toBeLessThanOrEqual(maxLength);
    }
  });

  it("leaves a Rekor entry index alone — it already fits", () => {
    expect(truncateIdentifier("82914", { kind: "rekor" })).toBe("82914");
  });
});
