// SPDX-License-Identifier: Apache-2.0

/*
 * FE-081 (NEW — proposed for doc 07 TC-FE; listed in the report for #54).
 *
 *   U | Every relative time in run detail carries its absolute timestamp with
 *     timezone, reachable by pointer, by keyboard and by assistive technology
 *     | Native title for a pointer; a tooltip on hover AND on focus; a
 *     click/tap that pins it, which is the only route a touch device has; the
 *     absolute value in the control's accessible name | FD §6.2, §6.4
 *
 * doc 06 §6.2 says "on hover", and this issue's acceptance criterion repeats
 * it. Taken literally it is satisfied by a `title` attribute and it excludes
 * every keyboard user, every touch user and every screen-reader user — in an
 * audit console, where "3 minutes ago" on its own is not a timestamp anybody
 * can put in a report. doc 06 §6.4 is titled "(gating, not aspirational)" and
 * asks for full keyboard operability; §6.4's last line asks for abbreviated
 * material to reach assistive technology. So the criterion is met four ways
 * and this test holds all four, because three of them are the ones that get
 * dropped.
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { Instant, RelativeTime } from "./RelativeTime";

const NOW = new Date("2026-08-31T12:00:00.000Z");
const AT = new Date("2026-08-31T11:42:05.000Z");
const ABSOLUTE = "2026-08-31 11:42:05 UTC";

function renderOne() {
  return render(<RelativeTime at={AT} now={NOW} label="Registered" />);
}

describe("FE-081 a relative time always carries its absolute one", () => {
  it("shows the relative time, which is what a reader scans", () => {
    const { container } = renderOne();
    expect(container.textContent).toContain("17 min ago");
  });

  it("gives a pointer the absolute value with no JavaScript at all", () => {
    renderOne();
    // The native tooltip. It survives a failed script, which the other three
    // routes do not.
    expect(screen.getByRole("button")).toHaveAttribute("title", ABSOLUTE);
  });

  it("gives a keyboard the absolute value, with no pointer anywhere", async () => {
    renderOne();
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
    await userEvent.tab();
    expect(screen.getByRole("button")).toHaveFocus();
    expect(screen.getByRole("tooltip")).toHaveTextContent(ABSOLUTE);
  });

  it("gives a touch device the absolute value, which hover and focus cannot", async () => {
    renderOne();
    const trigger = screen.getByRole("button");
    await userEvent.click(trigger);
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("tooltip")).toHaveTextContent(ABSOLUTE);
    await userEvent.click(trigger);
    expect(trigger).toHaveAttribute("aria-expanded", "false");
  });

  it("gives assistive technology the absolute value in the control's own name", () => {
    renderOne();
    // Never the relative time alone: the announcement names what the time is,
    // then the timestamp, then how long ago (doc 06 §6.1, say what happened).
    expect(
      screen.getByRole("button", {
        name: `Registered: ${ABSOLUTE}, 17 min ago`,
      }),
    ).toBeInTheDocument();
  });

  it("names the timezone, because a timestamp without one is not evidence", () => {
    renderOne();
    expect(screen.getByRole("button").getAttribute("title")).toContain("UTC");
  });

  it("carries the machine-readable instant on a real <time> element", () => {
    const { container } = renderOne();
    const time = container.querySelector("time");
    expect(time).toHaveAttribute("dateTime", "2026-08-31T11:42:05.000Z");
  });

  it("says 'in' for an instant that has not happened yet", () => {
    // A credential expiry is in the future. "0 s ago" for it would be false,
    // and doc 06 §6.2 asks for exact.
    const { container } = render(
      <RelativeTime
        at={new Date("2026-08-31T12:30:00.000Z")}
        now={NOW}
        label="Expires"
      />,
    );
    expect(container.textContent).toContain("in 30 min");
    expect(container.textContent).not.toContain("ago");
  });
});

describe("FE-081 a timestamp the dashboard cannot read", () => {
  it("shows the raw value and says it could not be read, rather than the epoch", () => {
    const { container } = render(
      <Instant value="not-a-timestamp" now={NOW} label="Registered" />,
    );
    expect(container.textContent).toContain("not-a-timestamp");
    expect(container.textContent).toContain("Timestamp the dashboard could not read");
    expect(container.textContent).not.toContain("1970");
  });

  it("renders nothing at all for an absent one, rather than inventing a time", () => {
    const { container } = render(<Instant value={undefined} now={NOW} label="Retired" />);
    expect(container).toBeEmptyDOMElement();
  });
});
