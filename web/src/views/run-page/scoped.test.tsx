// SPDX-License-Identifier: Apache-2.0

/*
 * FE-144 (RM-307, #486): the API answers a run another organisation recorded
 * exactly as a run that does not exist. The page must not then claim the
 * ledger holds no such run: it holds runs this reader cannot see. One
 * sentence covers both cases, so the page is no oracle either.
 */

import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { RunDetailView, RunNotFound } from "../run-detail/RunDetailView";
import { NOW } from "../run-detail/fixtures";
import { RunPage } from "./RunPage";
import { RunRecordNotFound } from "./api";
import { AGENT_NOW, AGENT_RUN_ID, stepOneDiff } from "./fixtures";
import { verifiedProof } from "../../components/verification/fixtures";

beforeEach(() => {
  window.history.pushState(null, "", "/runs/" + AGENT_RUN_ID);
});

afterEach(() => {
  window.history.pushState(null, "", "/");
});

function expectScopedAbsence(text: string) {
  expect(text).toMatch(/organisation/i);
  expect(text).not.toMatch(/ledger holds no/i);
}

describe("FE-144 a run out of scope reads as no run you can see", () => {
  it("the run page", async () => {
    render(
      <RunPage
        route={{ view: "run", runId: AGENT_RUN_ID }}
        fetchRunRecord={async (id) => {
          throw new RunRecordNotFound(id);
        }}
        fetchStepDiff={async () => stepOneDiff()}
        fetchProof={async () => verifiedProof()}
        now={AGENT_NOW}
      />,
    );
    const title = await screen.findByText("No record for this run");
    expectScopedAbsence(title.closest("section, div")?.textContent ?? "");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("the chain view", async () => {
    render(
      <RunDetailView
        route={{ view: "run", runId: "run-7f3a2c" }}
        fetchRun={async () => {
          throw new RunNotFound("run-7f3a2c");
        }}
        now={NOW}
      />,
    );
    const title = await screen.findByText("No run with this identifier");
    expectScopedAbsence(title.closest("section, div")?.textContent ?? "");
  });
});
