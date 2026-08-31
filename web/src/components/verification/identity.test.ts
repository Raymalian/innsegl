// SPDX-License-Identifier: Apache-2.0

/*
 * FE-004 (the comparison half) — which segment of the identity differs.
 *
 * doc 06 §4.1: "Trailer matches certificate identity (both values shown side
 * by side; on mismatch, the differing segment is highlighted)."
 *
 * Highlighting a segment means knowing which one it is, and this is where that
 * is decided. It mirrors `verify.DiffIdentity` in internal/verify/trailers.go:
 * the same grammar, the same six segment names, the same first-difference
 * rule, and the same refusal to compare two identities that do not both parse.
 * The names are a PROTECTED SURFACE (VERSIONING.md surface 3) and they are
 * what a reader sees, so they are asserted here character for character rather
 * than left to agree by luck.
 */

import { describe, expect, it } from "vitest";

import { FORGED_IDENTITY, PROVEN_IDENTITY } from "./fixtures";
import { SPIFFE_SEGMENT_NAMES, diffIdentity, segmentsOf } from "./identity";

describe("FE-004 the SPIFFE ID grammar", () => {
  it("names the six segments as internal/verify names them", () => {
    // internal/verify/trailers.go: spiffeSegmentNames.
    expect([...SPIFFE_SEGMENT_NAMES]).toEqual([
      "scheme",
      "trust-domain",
      "agent",
      "agent-type",
      "task-id",
      "run-id",
    ]);
  });

  it("splits an identity into those six, separators and all", () => {
    const segments = segmentsOf(PROVEN_IDENTITY, { kind: "same" });
    expect(segments.map((s) => s.value)).toEqual([
      "spiffe",
      "innsegl.dev",
      "agent",
      "fix-ci",
      "task-1481",
      "run-7f3a2c",
    ]);
    // Rendering the pieces back to back reproduces the identity exactly: the
    // comparison is a rendering of the value, never an edit of it.
    expect(segments.map((s) => s.separator + s.value).join("")).toBe(PROVEN_IDENTITY);
    expect(segments.every((s) => !s.differs)).toBe(true);
  });
});

describe("FE-004 the differing segment", () => {
  it("names the one segment a forged trailer changed", () => {
    const diff = diffIdentity(FORGED_IDENTITY, PROVEN_IDENTITY);
    expect(diff).toEqual({
      kind: "segment",
      index: 5,
      name: "run-id",
      trailer: "run-0e91bd",
      certificate: "run-7f3a2c",
    });
  });

  it("reports no difference between one identity and itself", () => {
    expect(diffIdentity(PROVEN_IDENTITY, PROVEN_IDENTITY)).toEqual({ kind: "same" });
  });

  it("names the FIRST segment that differs when several do", () => {
    const other = "spiffe://other.example/agent/fix-ci/task-1481/run-0e91bd";
    const diff = diffIdentity(other, PROVEN_IDENTITY);
    expect(diff.kind).toBe("segment");
    if (diff.kind !== "segment") throw new Error("unreachable");
    expect(diff.name).toBe("trust-domain");
  });

  it.each([
    ["a trailer with no scheme", "innsegl.dev/agent/fix-ci/task-1481/run-7f3a2c"],
    ["a trailer with too few segments", "spiffe://innsegl.dev/agent/fix-ci"],
    ["a trailer with too many", "spiffe://innsegl.dev/agent/fix-ci/task-1481/run-7f3a2c/x"],
    ["an empty trailer", ""],
  ])("refuses to compare %s segment by segment", (_name, trailer) => {
    expect(diffIdentity(trailer, PROVEN_IDENTITY).kind).toBe("uncomparable");
  });

  it("marks the whole value when the two cannot be compared", () => {
    const diff = diffIdentity("not-an-identity", PROVEN_IDENTITY);
    const segments = segmentsOf("not-an-identity", diff);
    expect(segments).toHaveLength(1);
    expect(segments[0]?.value).toBe("not-an-identity");
    expect(segments[0]?.differs).toBe(true);
  });

  it("marks the differing segment and only it", () => {
    const diff = diffIdentity(FORGED_IDENTITY, PROVEN_IDENTITY);
    for (const identity of [FORGED_IDENTITY, PROVEN_IDENTITY]) {
      const marked = segmentsOf(identity, diff).filter((s) => s.differs);
      expect(marked).toHaveLength(1);
      expect(marked[0]?.name).toBe("run-id");
    }
    expect(segmentsOf(FORGED_IDENTITY, diff).find((s) => s.differs)?.value)
      .toBe("run-0e91bd");
    expect(segmentsOf(PROVEN_IDENTITY, diff).find((s) => s.differs)?.value)
      .toBe("run-7f3a2c");
  });
});
