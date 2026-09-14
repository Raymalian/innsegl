// SPDX-License-Identifier: Apache-2.0

/*
 * FE-120 — the three checks read side by side, and the identity is named
 * under them.
 *
 * doc 06 §4.1 fixes the content of this panel and forbids collapsing it; what
 * the approved artboard fixes is its SHAPE. The verdict is a band across the
 * top carrying one word and the reason for it; the three checks sit in a row
 * beneath, each a card with its own name and its own sentence about what it
 * checked; the identity the whole thing is about is named last, in mono,
 * under a label that says the panel attributes this commit to it.
 *
 * The old panel stacked the three checks vertically, which made the second and
 * third scroll off a table cell, and never named the proven identity outside
 * the trailer/certificate comparison — so a reader who wanted the one fact the
 * page exists to deliver ("who produced this commit") had to read it out of a
 * mismatch widget.
 *
 * NOTHING HERE LOOSENS §5.3. The colour discipline is unchanged and asserted
 * elsewhere (green-audit.test.tsx, colour-discipline.test.ts); this asserts
 * structure. A check that passes inside a panel that did not verify still
 * loses its colour and keeps its word, which is the rollup's rule and not the
 * layout's.
 */

import { render, screen, within } from "@testing-library/react";

import { VerificationPanel } from "./VerificationPanel";
import { PROVEN_IDENTITY, proofWithResults } from "./fixtures";
import { strings } from "./strings";
import type { CheckResult } from "./types";

const LIVE = { source: "live" } as const;

function panel(results: readonly [CheckResult, CheckResult, CheckResult]) {
  return render(
    <VerificationPanel
      proof={proofWithResults(results)}
      liveness={LIVE}
      id="panel"
    />,
  );
}

describe("FE-120 the three checks read side by side", () => {
  it("puts all three in one row container, each its own card", () => {
    panel(["verified", "verified", "verified"]);
    const row = screen.getByTestId("proof-checks");
    expect(row.className).toMatch(/grid/);
    expect(within(row).getAllByRole("listitem")).toHaveLength(3);
  });

  it("names each check and says what it checked (doc 06 §4.1, P1)", () => {
    panel(["verified", "verified", "verified"]);
    const row = screen.getByTestId("proof-checks");
    for (const label of [
      strings.checks.certificateChain,
      strings.checks.rekorInclusion,
      strings.checks.trailerIdentity,
    ]) {
      expect(within(row).getByText(label)).toBeInTheDocument();
    }
    expect(within(row).getAllByText(/the check ran and the claim holds/)).toHaveLength(3);
  });

  it("states the verdict in one word, in the display serif (§5.2)", () => {
    panel(["verified", "verified", "verified"]);
    const headline = screen.getByTestId("proof-verdict-headline");
    expect(headline.textContent).toEqual(strings.verdict.verified.label);
    expect(headline.className).toMatch(/font-serif/);
  });
});

describe("FE-120 the identity the panel attributes the commit to", () => {
  it("names it under a label, in mono, outside the comparison (P4)", () => {
    panel(["verified", "verified", "verified"]);
    const block = screen.getByTestId("proof-attribution");
    expect(within(block).getByText(strings.attribution.heading)).toBeInTheDocument();
    expect(within(block).getAllByText(PROVEN_IDENTITY).length).toBeGreaterThan(0);
  });

  it("carries the run's own facts beside it (doc 06 §3.6)", () => {
    panel(["verified", "verified", "verified"]);
    const block = screen.getByTestId("proof-attribution");
    expect(within(block).getByText("fix-ci")).toBeInTheDocument();
    expect(within(block).getByText("task-1481")).toBeInTheDocument();
  });

  it("links to the run, so the reader can see what it did", () => {
    panel(["verified", "verified", "verified"]);
    const block = screen.getByTestId("proof-attribution");
    const link = within(block).getByRole("link", { name: strings.attribution.seeRun });
    expect(link.getAttribute("href")).toEqual("/runs/run-7f3a2c");
  });

  it("says so rather than showing an empty block when nothing proved an identity", () => {
    render(
      <VerificationPanel
        proof={proofWithResults(["unavailable", "unavailable", "unavailable"], {
          certificateIdentity: "",
          claimIdentity: "",
        })}
        liveness={LIVE}
        id="panel"
      />,
    );
    const block = screen.getByTestId("proof-attribution");
    expect(within(block).getByText(strings.attribution.none)).toBeInTheDocument();
  });
});
