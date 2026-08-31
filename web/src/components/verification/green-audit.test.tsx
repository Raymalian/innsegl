// SPDX-License-Identifier: Apache-2.0

/*
 * FE-036 (NEW — proposed for doc 07 TC-FE; see the report for #51).
 *
 *   U | Green audit of the three-check panel's rendered output | The
 *     proof-verified tokens appear only where all three named checks ran live
 *     and passed; every other state renders none | FD §5.3, §8.3; ADR-0038
 *     decision 4
 *
 * doc 07's FE-013 is "scan rendered views for green tokens", and it runs at
 * the end of Phase 4 over six views. This is the same audit aimed at the one
 * component that is allowed to spend a green at all, and it runs today.
 *
 * doc 06 §5.3: "Green = cryptographic verification passed. Nothing else is
 * ever green." ADR-0038 made `--innsegl-color-proof-verified-*` the only route
 * to one in the entire build. So the audit reduces to a single question asked
 * of rendered markup: for which inputs does the string `proof-verified` appear
 * — and the answer must be "for a live verification, and for nothing else".
 */

import { render } from "@testing-library/react";
import { afterEach, cleanup, describe, expect, it } from "vitest";
import type { ReactElement } from "react";

import {
  forgedTrailerProof,
  proofWithResults,
  unavailableProof,
  verifiedProof,
} from "./fixtures";
import { VerificationPanel } from "./VerificationPanel";

afterEach(cleanup);

interface Case {
  readonly name: string;
  readonly ui: ReactElement;
  /** Whether this render is entitled to a green. */
  readonly green: boolean;
}

const CASES: readonly Case[] = [
  {
    name: "all three checks ran live and passed",
    ui: <VerificationPanel proof={verifiedProof()} id="p" />,
    green: true,
  },
  {
    name: "all three passed, said so live and explicitly",
    ui: <VerificationPanel proof={verifiedProof()} liveness={{ source: "live" }} id="p" />,
    green: true,
  },
  {
    name: "a check failed",
    ui: <VerificationPanel proof={proofWithResults(["verified", "failed", "verified"])} id="p" />,
    green: false,
  },
  {
    name: "a check could not run",
    ui: <VerificationPanel proof={unavailableProof()} id="p" />,
    green: false,
  },
  {
    name: "the trailer was forged",
    ui: <VerificationPanel proof={forgedTrailerProof()} id="p" />,
    green: false,
  },
  {
    name: "the verdict came from a cache",
    ui: <VerificationPanel proof={verifiedProof()} liveness={{ source: "cache" }} id="p" />,
    green: false,
  },
  {
    name: "the live check errored while the cache said verified",
    ui: (
      <VerificationPanel
        proof={verifiedProof()}
        liveness={{ source: "cache", liveError: "dial tcp: connection refused" }}
        id="p"
      />
    ),
    green: false,
  },
  {
    name: "an upstream the check needed was unreachable",
    ui: (
      <VerificationPanel
        proof={proofWithResults(["verified", "verified", "verified"], {
          upstreamsReachable: false,
        })}
        id="p"
      />
    ),
    green: false,
  },
  {
    name: "the response contradicts its own material",
    ui: (
      <VerificationPanel
        proof={verifiedProof()}
        findings={[{ name: "the log index is the one the response reports", result: "contradicts" }]}
        id="p"
      />
    ),
    green: false,
  },
  {
    name: "the commit claims nothing at all",
    ui: <VerificationPanel proof={{ ...verifiedProof(), verdict: "unattributed", checks: [] }} id="p" />,
    green: false,
  },
  {
    name: "the response asserts verified over a failed check",
    ui: (
      <VerificationPanel
        proof={proofWithResults(["failed", "verified", "verified"], { verdict: "verified" })}
        id="p"
      />
    ),
    green: false,
  },
];

describe("FE-036 green is spent only on a live cryptographic verification", () => {
  it.each(CASES.map((c) => [c.name, c] as const))("%s", (_name, testCase) => {
    const { container } = render(testCase.ui);
    expect(container.innerHTML.includes("proof-verified")).toBe(testCase.green);
  });

  it("has a case that does spend one, so the audit is not vacuous", () => {
    expect(CASES.some((c) => c.green)).toBe(true);
    expect(CASES.filter((c) => !c.green).length).toBeGreaterThan(5);
  });

  it("spends no green on a per-check row whose own check did not pass", () => {
    const { container } = render(
      <VerificationPanel proof={proofWithResults(["verified", "failed", "unavailable"])} id="p" />,
    );
    for (const row of container.querySelectorAll("[data-check]")) {
      const green = (row.getAttribute("class") ?? "").includes("proof-verified") ||
        row.innerHTML.includes("proof-verified");
      expect(green).toBe(row.getAttribute("data-check-result") === "verified");
    }
  });
});
