// SPDX-License-Identifier: Apache-2.0

/*
 * FE-033 (NEW — proposed for doc 07 TC-FE; see the report for #50).
 *
 *   U | Every semantic colour in the shared components is paired with an icon
 *     and a text label | No element carrying a semantic colour class is
 *     without both | FD §5.3, §6.4, issue #50 acceptance
 *
 * doc 06 §5.3: "Every semantic color is paired with an icon and a text label
 * (6.4)." doc 06 §6.4: "Never color alone."
 *
 * The reason it is one cross-component test rather than an assertion inside
 * each component's own file: the rule is about the SET. A per-component
 * assertion is satisfied by whoever remembers to write it, and the component
 * that most needs it is the one added later by someone who did not. This test
 * walks the rendered output of every semantic state these components can
 * produce, finds every element that carries a colour with a meaning, and
 * requires both channels to be present on it.
 *
 * It is deliberately not a snapshot. A snapshot records what the markup was;
 * this records what it must contain for a reader who cannot see the hue.
 */

import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { AlertBanner } from "./AlertBanner";
import { AnchoringHeartbeat } from "./AnchoringHeartbeat";
import { ErrorState } from "./ErrorState";
import { LoadingState } from "./LoadingState";
import { StalenessIndicator, StalenessProvider } from "./StalenessIndicator";
import { StatusBadge } from "./StatusBadge";

/* Any class that resolves, through tailwind-theme.css, to a colour that makes
 * a claim. The neutral chrome (`text-ink`, `bg-surface`, `border-line`) is
 * absent on purpose: it claims nothing, so it needs no second channel. */
const SEMANTIC_COLOUR =
  /(?:^|\s)(?:text|bg|border)-(?:proof-(?:verified|failed|unavailable)|degraded|integrity-alert|status-(?:active|retired|expired))\b/;

const NOW = new Date("2026-08-30T14:44:05Z");

interface Case {
  readonly name: string;
  readonly ui: ReactElement;
  /** True where the state MUST carry a semantic colour, so the walk below
   * cannot pass by finding nothing to check. */
  readonly semantic: boolean;
}

const CASES: readonly Case[] = [
  { name: "status: active", ui: <StatusBadge status="active" />, semantic: true },
  { name: "status: retired", ui: <StatusBadge status="retired" />, semantic: true },
  { name: "status: expired", ui: <StatusBadge status="expired" />, semantic: true },
  {
    name: "staleness marker",
    ui: (
      <StalenessProvider degraded asOf={new Date("2026-08-30T14:32:05Z")} now={NOW}>
        <StalenessIndicator />
      </StalenessProvider>
    ),
    semantic: true,
  },
  {
    name: "heartbeat: beyond bound",
    ui: (
      <AnchoringHeartbeat
        segment={412}
        anchoredAt={new Date("2026-08-30T13:57:05Z")}
        lagBoundMs={30 * 60 * 1000}
        now={NOW}
      />
    ),
    semantic: true,
  },
  {
    name: "heartbeat: within bound",
    ui: (
      <AnchoringHeartbeat
        segment={412}
        anchoredAt={new Date("2026-08-30T14:41:05Z")}
        lagBoundMs={30 * 60 * 1000}
        now={NOW}
      />
    ),
    semantic: false, // P3: the calm state claims nothing, so it colours nothing
  },
  {
    name: "alert: integrity",
    ui: (
      <AlertBanner
        alerts={[
          {
            id: "a",
            kind: "integrity",
            title: "Chain verification failed",
            detail: "Segment 411 does not link to segment 410.",
            evidenceHref: "/segments/411",
          },
        ]}
      />
    ),
    semantic: true,
  },
  {
    name: "alert: degraded",
    ui: (
      <AlertBanner
        alerts={[
          {
            id: "b",
            kind: "degraded",
            title: "Anchoring lag beyond bound",
            detail: "Segment 412 anchored 47 min ago.",
            evidenceHref: "/overview#anchoring",
          },
        ]}
      />
    ),
    semantic: true,
  },
  { name: "dependency error", ui: <ErrorState />, semantic: true },
  { name: "loading", ui: <LoadingState what="runs" />, semantic: false },
];

describe("FE-033 never colour alone", () => {
  it.each(CASES.map((c) => [c.name, c] as const))(
    "%s pairs every semantic colour with an icon and a label",
    (_name, testCase) => {
      const { container, unmount } = render(testCase.ui);
      const coloured = Array.from(
        container.querySelectorAll<HTMLElement>("[class]"),
      ).filter((el) => SEMANTIC_COLOUR.test(el.getAttribute("class") ?? ""));

      expect(coloured.length > 0).toBe(testCase.semantic);

      for (const el of coloured) {
        // Channel two: a shape, distinguishable without hue.
        expect(el.querySelector("svg[aria-hidden='true']")).not.toBeNull();
        // Channel three: words.
        expect((el.textContent ?? "").trim().length).toBeGreaterThan(0);
      }
      unmount();
    },
  );

  it("spends no green anywhere in this directory (§5.3, ADR-0038 decision 4)", () => {
    for (const testCase of CASES) {
      const { container, unmount } = render(testCase.ui);
      // The only route to a green in the whole build is `proof-verified`, and
      // nothing here is a cryptographic verification.
      expect(container.innerHTML).not.toMatch(/proof-verified/);
      unmount();
    }
  });
});
