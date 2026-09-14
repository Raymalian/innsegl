// SPDX-License-Identifier: Apache-2.0

/*
 * FE-127 — doc 07's new row, verbatim:
 *
 *   U | The activity log's integrity count is outside the tab control | A run
 *     whose activity log holds a body that does not match the ledger renders a
 *     red chip on the tab row carrying the exact count and an icon; the chip is
 *     visible with either tab open and is inside neither panel; a run with no
 *     such body renders no chip | FD P3, §4.5, §5.3, §6.2
 *
 * ── THE SAME ARGUMENT FE-113 MAKES ABOUT THE BANNER ────────────────────────
 *
 * FE-113 put the integrity banner outside both tab panels because "a condition
 * behind an unselected tab is a condition the reader is not told about at all".
 * A tool-call body that does not hash to the digest the ledger recorded is
 * exactly such a condition, and it lives in the tab that is NOT open by
 * default: the timeline is tab one, and the timeline cannot see it — doc 02 §3
 * gives a `tool_call` event no member for its body, so the ledger's own
 * timeline has nothing to compare.
 *
 * It is therefore reported on the tab row itself, where it is on screen with
 * either tab open, and it is red because doc 06 §5.3 gives red to "verification
 * failed", which is what a digest that does not match is. It is never green
 * when the count is zero: silence is what the calm state looks like (P3), and
 * §5.3 spends the green on the three-check panel alone.
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { RunDetailView } from "./RunDetailView";
import { NOW, RUN_ID, healthyTimeline, runDetail } from "./fixtures";

const ROUTE = { view: "run", runId: RUN_ID } as const;

const ENTRY = {
  chain_position: 3,
  tool_name: "edit_file",
  ts: "2026-08-31T11:43:00.000Z",
  payload_digest:
    "sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
  body: { tool_input: { file_path: "internal/ledger/append.go" } },
};

function runLog(altered: number) {
  return {
    run_id: RUN_ID,
    retention_days: 90,
    entries: [
      { ...ENTRY, integrity: "verified" as const },
      ...(altered > 0
        ? [{ ...ENTRY, chain_position: 4, integrity: "altered" as const }]
        : []),
    ],
    verified: 1,
    altered,
    expired: 0,
  };
}

function stubLog(altered: number) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({ ok: true, json: async () => runLog(altered) })),
  );
}

function view() {
  return render(
    <RunDetailView
      route={ROUTE}
      fetchRun={async () => runDetail(healthyTimeline())}
      now={NOW}
    />,
  );
}

beforeEach(() => stubLog(0));
afterEach(() => vi.unstubAllGlobals());

describe("FE-127 the mismatch count is on the tab row", () => {
  it("reports the exact count, with an icon beside it", async () => {
    stubLog(1);
    const { container } = view();
    const chip = await screen.findByText("1 call does not match");
    expect(chip).toBeVisible();
    const marked = chip.closest("[data-integrity-chip]") as HTMLElement;
    expect(marked, "the chip is not marked as one").not.toBeNull();
    // Never colour alone (doc 06 §6.4): the icon is the second channel and the
    // words are the third.
    expect(marked.querySelector("[data-icon]")).not.toBeNull();
    expect(container.querySelectorAll("[data-integrity-chip]")).toHaveLength(1);
  });

  it("is red, because a body that does not match is a failed check", async () => {
    stubLog(1);
    view();
    const chip = (await screen.findByText("1 call does not match")).closest(
      "[data-integrity-chip]",
    ) as HTMLElement;
    expect(chip.className).toMatch(/\bintegrity-alert\b/);
    // doc 06 §5.3 and FE-086: this directory cannot reach the verification
    // green at all, and a mismatch is the last place it would belong.
    expect(chip.className).not.toMatch(/proof-verified/);
  });

  it("says calls in the plural when there is more than one", async () => {
    stubLog(3);
    view();
    expect(await screen.findByText("3 calls do not match")).toBeVisible();
  });

  it("renders nothing at all when every body matches", async () => {
    stubLog(0);
    const { container } = view();
    await screen.findByRole("tablist");
    expect(await screen.findByRole("tab", { name: /Timeline/ })).toBeInTheDocument();
    expect(container.querySelectorAll("[data-integrity-chip]")).toHaveLength(0);
  });
});

describe("FE-127 the chip is outside both panels", () => {
  it("sits in neither tabpanel", async () => {
    stubLog(1);
    const { container } = view();
    const chip = (await screen.findByText("1 call does not match")).closest(
      "[data-integrity-chip]",
    ) as HTMLElement;
    for (const panel of Array.from(container.querySelectorAll('[role="tabpanel"]'))) {
      expect(panel.contains(chip), "the chip is inside a tab panel").toBe(false);
    }
  });

  it("stays on screen with the timeline open and with the activity log open", async () => {
    stubLog(1);
    view();
    expect(await screen.findByText("1 call does not match")).toBeVisible();
    const activity = screen.getByRole("tab", { name: /What this agent did/ });
    await userEvent.click(activity);
    expect(activity).toHaveAttribute("aria-selected", "true");
    expect(screen.getByText("1 call does not match")).toBeVisible();
  });

  it("does not take the tablist's place in the accessibility tree", async () => {
    // A chip announced as a tab would make the control lie about how many tabs
    // it has, which is the promise `role="tab"` makes (FE-113).
    stubLog(1);
    view();
    await screen.findByText("1 call does not match");
    expect(screen.getAllByRole("tab")).toHaveLength(2);
  });
});
