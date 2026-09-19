// SPDX-License-Identifier: Apache-2.0

/*
 * FE-129 (NEW — proposed for doc 07 TC-FE; see the report for #256).
 *
 *   U | The four run lifecycle states | Active, Lapsed, Abandoned and Retired
 *     each render a distinct word, icon and outline; the four survive every
 *     colour being removed; "Expired" is not among them | #256, FD §3.2,
 *     §4.2, §5.3, §6.4
 *
 * ── WHY FOUR ───────────────────────────────────────────────────────────────
 *
 * Three words could not tell a run that is QUIET from one that is OVER, and
 * the word they collapsed into — "Expired" — was read as a claim that an agent
 * had died. Nothing in this system can see an agent end: one waiting on a
 * provider limit, running a long build, or on a sleeping machine is silent and
 * alive. So the withdrawal of a credential and the ending of a run are now two
 * different words, and the withdrawal is split again by whether the identity
 * can still be restored.
 *
 * ── AND WHY THE COMPARISON STRIPS EVERYTHING PERCEPTIBLE ───────────────────
 *
 * doc 06 §5.3 puts every run status in neutral grey, so hue cannot carry the
 * distinction even in principle. FE-030 learned the second half of this the
 * hard way: stripping `class` and `style` alone left `data-status` behind — an
 * attribute no reader can see — and the comparison could not fail. The strip
 * here removes that too.
 */

import { render, screen } from "@testing-library/react";

import { RUN_STATUSES } from "../../app/routes";
import type { RunStatus } from "./StatusBadge";
import { StatusBadge } from "./StatusBadge";
import { strings } from "./strings";

const ALL: readonly RunStatus[] = ["active", "lapsed", "abandoned", "retired"];

/** The two states a withdrawal put the run in. They share an outline, because
 * what they share is a recorded fact: the reaper took the credential. */
const WITHDRAWN: readonly RunStatus[] = ["lapsed", "abandoned"];

function stripPresentation(html: string): string {
  return html
    .replace(/ (?:class|style)="[^"]*"/g, "")
    .replace(/ data-status="[^"]*"/g, "");
}

function markupOf(status: RunStatus): string {
  const { container, unmount } = render(<StatusBadge status={status} />);
  const html = container.innerHTML;
  unmount();
  return html;
}

function iconOf(status: RunStatus): string | null {
  const { container, unmount } = render(<StatusBadge status={status} />);
  const icon =
    container.querySelector("svg[data-icon]")?.getAttribute("data-icon") ?? null;
  unmount();
  return icon;
}

function classOf(status: RunStatus): string {
  const { container, unmount } = render(<StatusBadge status={status} />);
  const badge = container.querySelector(`[data-status='${status}']`);
  const cls = badge?.getAttribute("class") ?? "";
  unmount();
  return cls;
}

describe("FE-129 the four lifecycle states", () => {
  it("are exactly four, spelled as internal/api spells them", () => {
    // The dashboard's filter vocabulary and the badge's vocabulary are one
    // set. Two lists that have to agree by hand are two lists that drift, and
    // the value reaches the query API in a URL.
    expect([...RUN_STATUSES]).toEqual([...ALL]);
  });

  it("names them Active, Lapsed, Abandoned and Retired", () => {
    render(
      <>
        {ALL.map((status) => (
          <StatusBadge key={status} status={status} />
        ))}
      </>,
    );
    for (const status of ALL) {
      expect(screen.getByText(strings.status[status].label)).toBeInTheDocument();
    }
    expect(
      ALL.map((status) => strings.status[status].label),
    ).toEqual(["Active", "Lapsed", "Abandoned", "Retired"]);
  });

  it("does not offer Expired as a state a run can be in", () => {
    // It survives as the name of the `run_expired` EVENT in the timeline,
    // which is a protected string (doc 02 §3) and is not this component's.
    expect(Object.keys(strings.status)).not.toContain("expired");
    for (const status of ALL) {
      expect(strings.status[status].label).not.toMatch(/expired/i);
    }
  });

  it("renders each with an icon and a word (§6.4, never colour alone)", () => {
    for (const status of ALL) {
      const { container, unmount } = render(<StatusBadge status={status} />);
      expect(container.querySelector("svg[aria-hidden='true']")).not.toBeNull();
      expect((container.textContent ?? "").trim().length).toBeGreaterThan(0);
      unmount();
    }
  });

  it("keeps all four apart with every perceptible presentation removed", () => {
    const markup = ALL.map(markupOf).map(stripPresentation);
    expect(new Set(markup).size).toBe(ALL.length);
  });

  it("gives each its own icon silhouette", () => {
    const icons = ALL.map(iconOf);
    expect(icons.every((name) => name !== null && name !== "")).toBe(true);
    expect(new Set(icons).size).toBe(ALL.length);
  });

  it("marks the two withdrawn states with the sheet's dashed outline", () => {
    for (const status of WITHDRAWN) {
      expect(classOf(status)).toContain(
        "var(--innsegl-border-style-status-expired)",
      );
    }
    for (const status of ["active", "retired"] as const) {
      expect(classOf(status)).not.toContain(
        "var(--innsegl-border-style-status-expired)",
      );
    }
  });

  it("says what each state MEANS, in the badge's title and to assistive tech", () => {
    for (const status of ALL) {
      const { container, unmount } = render(<StatusBadge status={status} />);
      const badge = container.querySelector(`[data-status='${status}']`);
      const meaning = strings.status[status].meaning;
      expect(badge).toHaveAttribute("title", meaning);
      expect(container.textContent).toContain(meaning);
      unmount();
    }
  });

  it("is neutral: no state is a verdict colour (§5.3)", () => {
    for (const status of ALL) {
      const { container, unmount } = render(<StatusBadge status={status} />);
      expect(container.innerHTML).not.toMatch(
        /proof-verified|proof-failed|proof-unavailable|degraded|integrity-alert/,
      );
      unmount();
    }
  });

  it("is inert — a state is a fact, not a control (P6)", () => {
    render(
      <>
        {ALL.map((status) => (
          <StatusBadge key={status} status={status} />
        ))}
      </>,
    );
    expect(screen.queryAllByRole("button")).toHaveLength(0);
    expect(screen.queryAllByRole("link")).toHaveLength(0);
  });
});
