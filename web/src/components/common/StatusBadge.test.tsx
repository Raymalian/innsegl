// SPDX-License-Identifier: Apache-2.0

/*
 * FE-030 (NEW — proposed for doc 07 TC-FE; see the report for #50).
 *
 *   U | Run status badges Active / Retired / Expired | Three distinct renders;
 *     Expired and Retired still differ with every colour removed | FD §3.2,
 *     §4.2, §5.3, §6.4
 *
 * doc 06 §3.2: "status badge (Active / Retired / Expired — expired styled
 * distinctly from retired, since it means an agent died unretired)."
 *
 * That parenthesis is the whole test. Retired and Expired are two different
 * facts about a run — one ended deliberately, one ended by running out of
 * credential — and doc 06 §5.3 assigns BOTH to neutral grey, because neither
 * is a verdict. So the distinction cannot be carried by hue even in principle,
 * and the assertion below removes every class and inline style before
 * comparing the two: whatever tells them apart has to survive a greyscale
 * printout and a colour-blind reader (§6.4, "never color alone").
 */

import { render, screen } from "@testing-library/react";
import type { RunStatus } from "./StatusBadge";
import { StatusBadge } from "./StatusBadge";

const ALL: readonly RunStatus[] = ["active", "retired", "expired"];

/** Everything a colour could hide in. */
function stripPresentation(html: string): string {
  return html.replace(/ (?:class|style)="[^"]*"/g, "");
}

function markupOf(status: RunStatus): string {
  const { container, unmount } = render(<StatusBadge status={status} />);
  const html = container.innerHTML;
  unmount();
  return html;
}

describe("FE-030 StatusBadge", () => {
  it("renders each status with an icon and a text label (§6.4)", () => {
    for (const status of ALL) {
      const { container, unmount } = render(<StatusBadge status={status} />);
      expect(container.querySelector("svg[aria-hidden='true']")).not.toBeNull();
      expect((container.textContent ?? "").trim().length).toBeGreaterThan(0);
      unmount();
    }
  });

  it("labels them Active, Retired and Expired", () => {
    render(
      <>
        <StatusBadge status="active" />
        <StatusBadge status="retired" />
        <StatusBadge status="expired" />
      </>,
    );
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByText("Retired")).toBeInTheDocument();
    expect(screen.getByText("Expired")).toBeInTheDocument();
  });

  it("EXPIRED still differs from RETIRED with every colour removed", () => {
    const retired = stripPresentation(markupOf("retired"));
    const expired = stripPresentation(markupOf("expired"));
    expect(expired).not.toBe(retired);
  });

  it("distinguishes them by icon, not only by word", () => {
    const iconOf = (status: RunStatus): string | null => {
      const { container, unmount } = render(<StatusBadge status={status} />);
      const icon = container
        .querySelector("svg[data-icon]")
        ?.getAttribute("data-icon") ?? null;
      unmount();
      return icon;
    };
    const icons = ALL.map(iconOf);
    expect(new Set(icons).size).toBe(3);
    expect(icons.every((name) => name !== null)).toBe(true);
  });

  it("gives Expired the dashed outline the token sheet defines for it", () => {
    const { container } = render(<StatusBadge status="expired" />);
    const badge = container.querySelector("[data-status='expired']");
    expect(badge?.getAttribute("class")).toContain(
      "var(--innsegl-border-style-status-expired)",
    );
  });

  it("says what each status MEANS, not just its name (§6.1)", () => {
    const { container } = render(<StatusBadge status="expired" />);
    const badge = container.querySelector("[data-status='expired']");
    expect(badge).toHaveAttribute("title", expect.stringMatching(/unretired/i));
    expect(container.textContent).toMatch(/unretired/i);
  });

  it("is neutral: no status is a verdict colour (§5.3)", () => {
    for (const status of ALL) {
      const { container, unmount } = render(<StatusBadge status={status} />);
      expect(container.innerHTML).not.toMatch(
        /proof-verified|proof-failed|proof-unavailable|degraded|integrity-alert/,
      );
      unmount();
    }
  });

  it("is inert — a badge is a fact, not a control (P6)", () => {
    render(
      <>
        <StatusBadge status="active" />
        <StatusBadge status="retired" />
        <StatusBadge status="expired" />
      </>,
    );
    expect(screen.queryAllByRole("button")).toHaveLength(0);
    expect(screen.queryAllByRole("link")).toHaveLength(0);
  });
});
