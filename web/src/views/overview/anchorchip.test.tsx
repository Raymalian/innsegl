// SPDX-License-Identifier: Apache-2.0

/*
 * RM-331 (#507) — the header's anchoring status is a short chip, and the whole
 * sentence stays reachable: in the chip's accessible name and tooltip, and on
 * the overview's Anchoring section. doc 06 §3.1: never hidden.
 */

import { render, screen } from "@testing-library/react";

import { AnchoringEvidence, AnchoringPulse } from "./AnchoringPulse";
import type { AnchorHeartbeat } from "./types";

const NOW = new Date("2026-08-30T14:44:05Z");
const BOUND_MS = 15 * 60 * 1000;

function sealed(sealedAt: string, anchored: boolean): AnchorHeartbeat {
  return {
    present: true,
    segment_id: "sha256:9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f",
    first_position: 8001,
    last_position: 8421,
    sealed_at: sealedAt,
    anchored,
    rekor_log_index: anchored ? 82914 : undefined,
  };
}

function chip(anchor: AnchorHeartbeat | null | undefined) {
  render(<AnchoringPulse anchor={anchor} lagBoundMs={BOUND_MS} now={NOW} />);
  return screen.getByTestId("overview-heartbeat");
}

describe("RM-331 the anchoring chip", () => {
  it("is a few words when anchored on time", () => {
    const shown = chip(sealed("2026-08-30T14:41:05Z", true));
    expect(shown.querySelector("[data-chip-text]")).toHaveTextContent(
      /^Anchored 3 min ago$/,
    );
  });

  it("says how far behind it is, in a few words, when past the bound", () => {
    const shown = chip(sealed("2026-07-28T12:41:05Z", true));
    expect(shown.querySelector("[data-chip-text]")).toHaveTextContent(
      /^Anchoring 33 d behind$/,
    );
    expect(shown.innerHTML).toMatch(/degraded/);
  });

  it("says unreadable plainly when the API did not answer", () => {
    const shown = chip(null);
    expect(shown.querySelector("[data-chip-text]")).toHaveTextContent(
      /^Anchoring unknown$/,
    );
    expect(shown.innerHTML).toMatch(/degraded/);
  });

  it("carries the whole sentence as its tooltip and accessible name", () => {
    const shown = chip(sealed("2026-07-28T12:41:05Z", true));
    const full = shown.querySelector("[title]") as HTMLElement;
    expect(full.getAttribute("title")).toMatch(
      /Ledger segment 8421 anchored 33 d 2 h ago — 33 d 1 h beyond the 15 min anchoring-lag bound/,
    );
    expect(shown.querySelector(".sr-only")?.textContent).toBe(
      full.getAttribute("title"),
    );
  });

  it("does not call a sealed, unanchored segment anchored", () => {
    const shown = chip(sealed("2026-08-30T14:41:05Z", false));
    const text = shown.querySelector("[data-chip-text]")?.textContent ?? "";
    expect(text).toMatch(/not anchored/i);
    expect(text).not.toMatch(/^Anchored/);
  });

  it("is never empty, in any state", () => {
    for (const anchor of [undefined, null, { present: false, anchored: false }]) {
      const { unmount } = render(
        <AnchoringPulse anchor={anchor} lagBoundMs={BOUND_MS} now={NOW} />,
      );
      expect(screen.getByTestId("overview-heartbeat").textContent?.trim()).not.toBe("");
      unmount();
    }
  });
});

describe("RM-331 the Anchoring section carries the full sentence", () => {
  it("states it, with the sealed time", () => {
    render(
      <AnchoringEvidence
        anchor={sealed("2026-07-28T12:41:05Z", true)}
        lagBoundMs={BOUND_MS}
        now={NOW}
      />,
    );
    expect(screen.getByTestId("anchoring-sentence")).toHaveTextContent(
      /Ledger segment 8421 anchored 33 d 2 h ago — 33 d 1 h beyond the 15 min anchoring-lag bound/,
    );
  });
});
