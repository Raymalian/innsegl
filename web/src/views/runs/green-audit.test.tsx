// SPDX-License-Identifier: Apache-2.0

/*
 * FE-055 (NEW — proposed for doc 07 TC-FE; see the report for #53).
 *
 *   U | Green audit of the runs table's rendered output | The proof-verified
 *     tokens appear in a row only where that row's own proof ran live and all
 *     three checks passed; every other row renders none | FD §5.3, §8.3;
 *     ADR-0038 decision 4
 *
 * doc 07's FE-013 is "scan rendered views for green tokens" and runs at the
 * end of Phase 4 over all six views. This is the same audit aimed at this
 * view, and it runs today.
 *
 * ADR-0038 made `--innsegl-color-proof-verified-*` the only route to a green
 * in the entire build, and `text-proof-verified` the only Tailwind utility
 * that reaches it. So the audit reduces to one question asked of rendered
 * markup — for which rows does the string `proof-verified` appear — and the
 * answer must be "for a live verification of that row's commit, and for
 * nothing else". Not for a run that finished. Not for an active agent. Not for
 * a page that loaded.
 *
 * FE-054 is the source half of the same rule and cannot replace this one: a
 * component that spends no green itself still renders one if it hands the
 * wrong liveness to a component that can.
 */

import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { ReactElement } from "react";

import {
  forgedTrailerProof,
  proofWithResults,
  unavailableProof,
  verifiedProof,
} from "../../components/verification/fixtures";

import { RunsTable } from "./RunsTable";
import { RunsView } from "./RunsView";
import { runPage, runSummary, threeRuns } from "./fixtures";
import type { CommitProof } from "./proofs";

afterEach(cleanup);

const RUN = runSummary({ run_id: "run-7f3a2c", commits: 1 });

const withProof = (commit: CommitProof): ReactElement => (
  <RunsTable runs={[RUN]} total={1} proofs={() => [commit]} />
);

interface Case {
  readonly name: string;
  readonly ui: ReactElement;
  /** Whether this render is entitled to a green. */
  readonly green: boolean;
}

const CASES: readonly Case[] = [
  {
    name: "a row whose commit verified, live",
    ui: withProof({ proof: verifiedProof(), liveness: { source: "live" } }),
    green: true,
  },
  {
    name: "a row with no proof at all — the normal case for this table",
    ui: <RunsTable runs={threeRuns()} total={3} />,
    green: false,
  },
  {
    name: "a row whose proof came from a cache",
    ui: withProof({ proof: verifiedProof(), liveness: { source: "cache" } }),
    green: false,
  },
  {
    name: "a row whose live check errored while the retained proof said verified",
    ui: withProof({
      proof: verifiedProof(),
      liveness: { source: "cache", liveError: "dial tcp: connection refused" },
    }),
    green: false,
  },
  {
    name: "a row with a failing check",
    ui: withProof({
      proof: proofWithResults(["verified", "failed", "verified"]),
      liveness: { source: "live" },
    }),
    green: false,
  },
  {
    name: "a row whose check could not run",
    ui: withProof({ proof: unavailableProof(), liveness: { source: "live" } }),
    green: false,
  },
  {
    name: "a row with a forged trailer",
    ui: withProof({ proof: forgedTrailerProof(), liveness: { source: "live" } }),
    green: false,
  },
];

describe("FE-055 green means a live cryptographic verification, and nothing else", () => {
  it.each(CASES)("$name", ({ ui, green }) => {
    const { container } = render(ui);
    expect(container.innerHTML.includes("proof-verified")).toBe(green);
  });

  it("has a case that DOES render green, so the audit can fail", () => {
    expect(CASES.some((c) => c.green)).toBe(true);
    expect(CASES.filter((c) => !c.green).length).toBeGreaterThan(4);
  });
});

describe("FE-055 nothing else in the view is ever green", () => {
  it("not an active run, not a retired one, not an expired one", () => {
    const { container } = render(<RunsTable runs={threeRuns()} total={3} />);
    // All three statuses are on screen; doc 06 §5.3 puts every one of them in
    // neutral grey, because none of them is a verdict about cryptography.
    expect(
      [...container.querySelectorAll("[data-status]")].map((n) =>
        n.getAttribute("data-status"),
      ),
    ).toEqual(["active", "retired", "expired"]);
    expect(container.innerHTML).not.toContain("proof-verified");
  });

  it("not the chrome around the table either", async () => {
    const page = runPage();
    const { container, findByRole } = render(
      <RunsView source={() => Promise.resolve(page)} />,
    );
    await findByRole("table");
    expect(container.innerHTML).not.toContain("proof-verified");
  });
});
