// SPDX-License-Identifier: Apache-2.0

/*
 * FE-053 (NEW — proposed for doc 07 TC-FE; see the report for #53).
 *
 *   U | A runs row cannot render a verdict without saying where it came from |
 *     `liveness.source` is required at compile time for a row's proof; a row
 *     with no proof renders no verdict at all; a retained proof renders
 *     unavailable, never verified | FD §3.2, §4.1, §8.1, §8.4; ADR-0038
 *
 * FE-039 made `liveness` a required PROP on the verification components,
 * because a view that caches and stays silent must not compile. `source`
 * itself is still optional there, so `liveness={{}}` compiles and means live.
 *
 * A runs table is where that残 silence would do the most damage: it is the
 * busiest view, it is the one most likely to end up behind a data-fetching
 * library, and a row is the densest place for a stale green to hide. So this
 * directory narrows the contract — proofs.ts requires the source to be
 * spelled — and the first assertion below is the compiler's.
 *
 * The other half is what a row does when nobody verified anything, which is
 * the normal case: this table performs no verification (proofs.ts explains
 * why), and it renders no badge, no icon and no colour for a check that never
 * ran. doc 06 P2's three states are outcomes of a check; "nobody asked" is not
 * one of them, and dressing it as one would be a claim about work never done.
 */

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import {
  proofWithResults,
  verifiedProof,
} from "../../components/verification/fixtures";

import type { CommitProof, RunProofSource } from "./proofs";
import { RunsTable } from "./RunsTable";
import { runSummary } from "./fixtures";
import { strings } from "./strings";

afterEach(cleanup);

const RUN = runSummary({ run_id: "run-7f3a2c", commits: 1 });

function tableWith(proofs?: RunProofSource) {
  return render(<RunsTable runs={[RUN]} total={1} proofs={proofs} />);
}

const verdicts = (container: HTMLElement): string[] =>
  [...container.querySelectorAll("[data-verdict]")].map(
    (node) => node.getAttribute("data-verdict") ?? "",
  );

describe("FE-053 liveness is stated, not assumed", () => {
  it("refuses a proof that will not say where it came from", () => {
    const stated: CommitProof = {
      proof: verifiedProof(),
      liveness: { source: "live" },
    };
    const silent: CommitProof = {
      proof: verifiedProof(),
      // @ts-expect-error `{}` is a live claim by omission. A view that
      // retains a response is the only thing that knows it did, and under a
      // default it reports a cache by saying nothing at all (doc 06 §8.1). If
      // this line stops erroring, the narrowing in proofs.ts has been undone.
      liveness: {},
    };
    expect(stated.liveness.source).toBe("live");
    expect(silent.proof.commit_sha).toBe(verifiedProof().commit_sha);
  });

  it("accepts either source when it is spelled out", () => {
    const live: CommitProof = { proof: verifiedProof(), liveness: { source: "live" } };
    const cached: CommitProof = { proof: verifiedProof(), liveness: { source: "cache" } };
    expect([live.liveness.source, cached.liveness.source]).toEqual(["live", "cache"]);
  });
});

describe("FE-053 a row with no proof renders no verdict", () => {
  it("says no live check ran, and shows no badge of any kind", () => {
    const { container } = tableWith();
    expect(verdicts(container)).toEqual([]);
    expect(
      screen.getByText(strings.labels.verification.notChecked),
    ).toBeInTheDocument();
    // The exact count is still there: doc 06 §3.2 asks for it either way.
    expect(screen.getByText(strings.formats.commits(1))).toBeInTheDocument();
  });

  it("explains what a verification would be, to whoever is listening", () => {
    tableWith();
    expect(
      screen.getAllByText(strings.sentences.verification.notChecked).length,
    ).toBeGreaterThan(0);
  });
});

describe("FE-053 a proof in a row is rolled up under doc 06 §4.1's rules", () => {
  it("renders verified only for a proof that says it is live", () => {
    const { container } = tableWith(() => [
      { proof: verifiedProof(), liveness: { source: "live" } },
    ]);
    expect(verdicts(container)).toContain("verified");
  });

  it("renders unavailable for a retained proof, whatever the checks said", () => {
    const { container } = tableWith(() => [
      { proof: verifiedProof(), liveness: { source: "cache" } },
    ]);
    expect(verdicts(container)).toContain("unavailable");
    expect(verdicts(container)).not.toContain("verified");
  });

  it("renders failed for a failing check, and does not soften it when the network is out", () => {
    const { container } = tableWith(() => [
      {
        proof: proofWithResults(["verified", "verified", "failed"]),
        liveness: { source: "cache", liveError: "dial tcp: connection refused" },
      },
    ]);
    // doc 06 §8 anti-pattern 2: failed and unavailable never collapse, and the
    // downgrade runs one way only.
    expect(verdicts(container)).toContain("failed");
    expect(verdicts(container)).not.toContain("verified");
  });

  it("expands the rollup to the three checks — anti-pattern 4 has nowhere to hide", () => {
    const { container } = tableWith(() => [
      { proof: verifiedProof(), liveness: { source: "live" } },
    ]);
    const disclosure = container.querySelector("details");
    expect(disclosure).not.toBeNull();
    // The badge is the disclosure's summary and the panel is its body, so the
    // expansion is structural: there is no prop that turns the panel off.
    expect(disclosure?.querySelector("summary [data-verdict]")).not.toBeNull();
    expect(
      [...(disclosure?.querySelectorAll("[data-check]") ?? [])].map((node) =>
        node.getAttribute("data-check"),
      ),
    ).toEqual(["certificateChain", "rekorInclusion", "trailerIdentity"]);
  });

  it("gives a row's several commits a badge each, and no invented run-level verdict", () => {
    const two = runSummary({ run_id: "run-many", commits: 2 });
    const second = proofWithResults(["verified", "failed", "verified"]);
    const { container } = render(
      <RunsTable
        runs={[two]}
        total={1}
        proofs={() => [
          { proof: verifiedProof(), liveness: { source: "live" } },
          {
            proof: {
              ...second,
              commit_sha: "1a2b3c4d5e6f70819a2b3c4d5e6f708192a3b4c5",
            },
            liveness: { source: "live" },
          },
        ]}
      />,
    );
    /* Two commits, two rollups, each expanding to its own evidence — and no
     * third badge rolling the pair up into a verdict doc 06 §4.1 does not
     * define and nothing could expand. */
    const rollups = container.querySelectorAll(
      "td details > summary [data-verdict]",
    );
    expect(rollups).toHaveLength(2);
    expect([...rollups].map((n) => n.getAttribute("data-verdict"))).toEqual([
      "verified",
      "failed",
    ]);
  });
});
