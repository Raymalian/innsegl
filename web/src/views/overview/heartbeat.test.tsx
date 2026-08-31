// SPDX-License-Identifier: Apache-2.0

/*
 * FE-005 (doc 07, TC-FE) — anchoring heartbeat beyond the lag bound.
 *
 *   "Header turns amber with lag duration"  — proves FD §3.1
 *
 * doc 06 §3.1: "Anchoring heartbeat in the persistent header (all views):
 * 'Ledger segment N anchored M min ago.' Exceeding the configured
 * anchoring-lag bound turns this amber with the lag duration; it is the
 * system's public tamper-evidence pulse and is never hidden."
 *
 * FE-005 already exists one level down, over the shared component
 * (components/common/AnchoringHeartbeat.test.tsx, RM-042). This is the other
 * half of the same test ID and it is not a duplicate: the component is handed
 * a segment number, an anchor time and a bound, and the question those tests
 * cannot ask is whether the VIEW that owns the data hands it the right three —
 * and what it does with the states the component has no vocabulary for.
 *
 * `internal/api`'s AnchorHeartbeat is the newest `segment_sealed` event, and
 * doc 02 §3 puts the anchoring members on a SUPERSEDING segment_sealed event
 * once Rekor confirms. So `anchored: false` is a real and ordinary state — a
 * segment sealed and waiting — and it is neither "anchored M min ago" nor "no
 * segment anchored yet". Rendering it as either would be a lie in the one
 * component whose whole job is to be believed (P2).
 *
 * NEW test IDs proposed for doc 07 (not added to it by this issue):
 *   FE-070 | U | Overview supplies the header heartbeat from the query API's
 *          |   | AnchorHeartbeat, in every state, and never hides it | FD §3.1
 *   FE-071 | U | Newest sealed segment not yet anchored | Rendered as neither
 *          |   | anchored nor never-anchored; amber past the bound | FD §3.1, P2
 */

import { render, screen } from "@testing-library/react";

import { AnchoringPulse } from "./AnchoringPulse";
import { perceptible } from "./perceptible";
import type { AnchorHeartbeat } from "./types";

const NOW = new Date("2026-08-30T14:44:05Z");
const RECENT = "2026-08-30T14:41:05Z"; // 3 min before NOW
const LATE = "2026-08-30T13:57:05Z"; // 47 min before NOW
const BOUND_MS = 30 * 60 * 1000;

/** The newest sealed segment, with Rekor's confirmation attached. */
function anchored(sealedAt: string): AnchorHeartbeat {
  return {
    present: true,
    segment_id: "sha256:9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f",
    first_position: 8001,
    last_position: 8421,
    sealed_at: sealedAt,
    anchored: true,
    rekor_log_index: 82914,
  };
}

/** The same segment, sealed, with no anchor yet (doc 02 §3). */
function sealedOnly(sealedAt: string): AnchorHeartbeat {
  return { ...anchored(sealedAt), anchored: false, rekor_log_index: undefined };
}

/** Nothing has ever been sealed. */
const NOTHING_SEALED: AnchorHeartbeat = { present: false, anchored: false };

function pulse(anchor: AnchorHeartbeat | null) {
  return render(
    <AnchoringPulse anchor={anchor} lagBoundMs={BOUND_MS} now={NOW} />,
  );
}

describe("FE-005 the overview's anchoring heartbeat", () => {
  it("reads the pulse plainly when the anchor is inside the bound", () => {
    pulse(anchored(RECENT));
    expect(screen.getByTestId("overview-heartbeat")).toHaveTextContent(
      /ledger segment 8421 anchored 3 min ago/i,
    );
  });

  it("stays calm inside the bound — no degraded colour, no alarm (P3)", () => {
    const { container } = pulse(anchored(RECENT));
    expect(container.innerHTML).not.toMatch(/degraded/);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("turns amber beyond the bound and states the lag duration", () => {
    const { container } = pulse(anchored(LATE));
    const shown = screen.getByTestId("overview-heartbeat");
    expect(container.innerHTML).toMatch(/degraded/);
    expect(shown).toHaveTextContent(/47 min/); // since the anchor
    expect(shown).toHaveTextContent(/17 min/); // past the bound
    expect(shown).toHaveTextContent(/30 min/); // the bound itself
  });

  it("spends no green on a heartbeat, in any state (§5.3)", () => {
    for (const anchor of [
      anchored(RECENT),
      anchored(LATE),
      sealedOnly(RECENT),
      sealedOnly(LATE),
      NOTHING_SEALED,
      null,
    ]) {
      const { container, unmount } = pulse(anchor);
      expect(container.innerHTML).not.toMatch(/proof-verified/);
      unmount();
    }
  });

  it("renders in every state: it is never hidden (§3.1)", () => {
    for (const anchor of [
      anchored(RECENT),
      anchored(LATE),
      sealedOnly(RECENT),
      sealedOnly(LATE),
      NOTHING_SEALED,
      null,
    ]) {
      const view = pulse(anchor);
      const shown = view.getByTestId("overview-heartbeat");
      expect(shown).toBeVisible();
      expect(shown.textContent?.trim()).not.toBe("");
      view.unmount();
    }
  });

  it("says nothing has been anchored only when nothing has been sealed (P2)", () => {
    pulse(NOTHING_SEALED);
    expect(screen.getByTestId("overview-heartbeat")).toHaveTextContent(
      /no segment anchored yet/i,
    );
  });

  it("FE-071 does not call a sealed, unanchored segment anchored", () => {
    pulse(sealedOnly(RECENT));
    const text = screen.getByTestId("overview-heartbeat").textContent ?? "";
    expect(text).toMatch(/ledger segment 8421 sealed 3 min ago/i);
    expect(text).toMatch(/not yet anchored/i);
    // The two lies this state invites, refused by name.
    expect(text).not.toMatch(/anchored 3 min ago/i);
    expect(text).not.toMatch(/no segment anchored yet/i);
  });

  it("FE-071 turns amber when the pending anchor is past the bound", () => {
    const { container } = pulse(sealedOnly(LATE));
    const shown = screen.getByTestId("overview-heartbeat");
    expect(container.innerHTML).toMatch(/degraded/);
    expect(shown).toHaveTextContent(/47 min/);
    expect(shown).toHaveTextContent(/17 min/);
    expect(shown).toHaveTextContent(/30 min/);
  });

  it("FE-071 stays calm while a pending anchor is inside the bound (P3)", () => {
    const { container } = pulse(sealedOnly(RECENT));
    expect(container.innerHTML).not.toMatch(/degraded/);
  });

  it("says the pulse is unreadable rather than calm when the API did not answer", () => {
    const { container } = pulse(null);
    const text = screen.getByTestId("overview-heartbeat").textContent ?? "";
    expect(container.innerHTML).toMatch(/degraded/);
    expect(text).toMatch(/couldn't read/i);
    expect(text).not.toMatch(/no segment anchored yet/i);
  });

  it("carries an icon and a text label everywhere, never colour alone (§6.4)", () => {
    for (const anchor of [anchored(LATE), sealedOnly(LATE), NOTHING_SEALED, null]) {
      const view = pulse(anchor);
      expect(view.container.querySelector("svg[aria-hidden='true']")).not.toBeNull();
      expect(view.getByTestId("overview-heartbeat").textContent).toBeTruthy();
      view.unmount();
    }
  });

  it("exposes the anchor time absolutely, with its timezone (§6.2)", () => {
    pulse(anchored(LATE));
    const when = screen.getByText(/47 min ago/);
    expect(when).toHaveAttribute("datetime", "2026-08-30T13:57:05.000Z");
    expect(when).toHaveAttribute("title", "2026-08-30 13:57:05 UTC");
  });

  /*
   * The mutation guard. A previous agent on this project proved two states
   * differed by comparing markup with `class` and `style` stripped and a
   * `data-*` attribute left in — which made the comparison impossible to fail,
   * because the data attribute differed whatever the pixels did. So this
   * strips everything a sighted reader CANNOT perceive and compares what is
   * left: text, classes, inline style, and the title a hover reveals.
   */
  it("renders the breach differently from the calm state, to the eye", () => {
    const calm = perceptible(pulse(anchored(RECENT)).container.innerHTML);
    const breach = perceptible(pulse(anchored(LATE)).container.innerHTML);
    expect(calm).not.toEqual(breach);
    expect(calm).not.toMatch(/degraded/);
    expect(breach).toMatch(/degraded/);
  });

  it("its own difference test can fail: identical renders compare equal", () => {
    const a = perceptible(pulse(anchored(RECENT)).container.innerHTML);
    const b = perceptible(pulse(anchored(RECENT)).container.innerHTML);
    expect(a).toEqual(b);
  });
});
