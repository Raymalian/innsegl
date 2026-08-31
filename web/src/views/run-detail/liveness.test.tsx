// SPDX-License-Identifier: Apache-2.0

/*
 * FE-085 (NEW — proposed for doc 07 TC-FE; listed in the report for #54).
 *
 *   U | Run detail's per-commit panel never reports a retained proof as a live
 *     one | No proof is fetched until a reader opens the panel; a proof held
 *     past the freshness bound, or one whose re-check errored, is passed
 *     `{ source: "cache" }` and the rollup reports unavailable with the reason
 *     in words; closing the panel discards the proof | FD §8 anti-pattern 1,
 *     P2; doc 07 FE-003
 *
 * doc 07's FE-003 puts this case to the panel with a fixture. This puts it to
 * the VIEW, which is where the mistake is actually made: the panel cannot know
 * whether the proof it was handed is the result of a check that just ran, and
 * a detail view showing eight commits is exactly the place someone fetches
 * eight proofs once and keeps them.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { verifiedProof } from "../../components/verification/fixtures";
import { CommitVerification } from "./CommitVerification";
import { COMMIT_SHA } from "./fixtures";

/** A proof source that counts its calls and never touches the network. */
function prover(fail = false) {
  const calls: string[] = [];
  const verify = vi.fn(async (commitSHA: string) => {
    calls.push(commitSHA);
    if (fail) throw new Error("dial tcp: connection refused");
    return verifiedProof();
  });
  return { calls, verify };
}

const open = async () => {
  await userEvent.click(screen.getByRole("button", { name: "Verify this commit" }));
};

describe("FE-085 a retained proof is never reported as a live one", () => {
  it("fetches nothing until a reader asks", () => {
    const { verify } = prover();
    render(
      <CommitVerification commitSHA={COMMIT_SHA} verifyCommit={verify} />,
    );
    expect(verify).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Verify this commit" })).toHaveAttribute(
      "aria-expanded",
      "false",
    );
  });

  it("reports a just-fetched proof as verified, because a check just ran", async () => {
    const { verify } = prover();
    render(
      <CommitVerification
        commitSHA={COMMIT_SHA}
        verifyCommit={verify}
        freshnessMs={60_000}
      />,
    );
    await open();
    await waitFor(() => expect(verify).toHaveBeenCalledTimes(1));
    // Four "Verified": the rollup badge and the three checks. doc 06 §4.1
    // forbids the three collapsing into the rollup, so the count is part of
    // what is being asserted, not an artefact of the query.
    await waitFor(() => expect(screen.getAllByText("Verified")).toHaveLength(4));
    expect(screen.queryByText("Verification unavailable")).not.toBeInTheDocument();
    expect(screen.queryByText("Reported as unavailable")).not.toBeInTheDocument();
  });

  it("stops reporting it as verified once it is older than the bound", async () => {
    const { verify } = prover();
    render(
      <CommitVerification commitSHA={COMMIT_SHA} verifyCommit={verify} freshnessMs={0} />,
    );
    await open();
    // The same proof, the same three passing checks. Only the claim that a
    // live check confirmed them has expired — and that is enough (§8.1).
    expect(await screen.findByText("Verification unavailable")).toBeInTheDocument();
    expect(screen.getByText("Reported as unavailable")).toBeInTheDocument();
    expect(
      screen.getByText(
        "This result was not produced by a live check, so it is reported as unavailable rather than repeated as a verdict.",
      ),
    ).toBeInTheDocument();
    // The three checks keep their own words — doc 06 §4.1 and §8's second
    // anti-pattern: what changed is the rollup, not what each check reported.
    expect(screen.getAllByText("Verified")).toHaveLength(3);
  });

  it("discards the proof when the panel is closed, and re-checks when it reopens", async () => {
    const { verify } = prover();
    render(
      <CommitVerification
        commitSHA={COMMIT_SHA}
        verifyCommit={verify}
        freshnessMs={60_000}
      />,
    );
    await open();
    await waitFor(() => expect(screen.getAllByText("Verified")).toHaveLength(4));
    await open(); // close
    expect(screen.queryAllByText("Verified")).toHaveLength(0);
    await open(); // reopen
    await waitFor(() => expect(verify).toHaveBeenCalledTimes(2));
  });

  it("keeps the evidence and withdraws the claim when a re-check errors", async () => {
    let attempt = 0;
    const verify = vi.fn(async () => {
      attempt += 1;
      if (attempt > 1) throw new Error("dial tcp: connection refused");
      return verifiedProof();
    });
    render(
      <CommitVerification
        commitSHA={COMMIT_SHA}
        verifyCommit={verify}
        freshnessMs={60_000}
      />,
    );
    await open();
    await waitFor(() => expect(screen.getAllByText("Verified")).toHaveLength(4));

    await userEvent.click(screen.getByRole("button", { name: "Run the checks again" }));

    // The proof is still on screen — it is evidence, and hiding it helps
    // nobody. What is gone is the claim that a live check confirms it.
    expect(await screen.findByText("Verification unavailable")).toBeInTheDocument();
    expect(screen.getByText("dial tcp: connection refused")).toBeInTheDocument();
    expect(screen.getAllByText("Verified")).toHaveLength(3);
  });

  it("says the read failed when there is no proof at all, rather than nothing", async () => {
    const { verify } = prover(true);
    render(<CommitVerification commitSHA={COMMIT_SHA} verifyCommit={verify} />);
    await open();
    expect(await screen.findByText("the proof for this commit")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });
});
