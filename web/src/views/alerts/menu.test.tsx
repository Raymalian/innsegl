// SPDX-License-Identifier: Apache-2.0

/*
 * The header's notification menu — ADR-0054, doc 06 P1, P2, P3, §6.4.
 *
 * NEW test IDs proposed for doc 07 (not added to it by this change):
 *   FE-134 | U | Open alerts live in the persistent header | A bell with a
 *          |   | count badge, red when any alert is open, absent at zero; a
 *          |   | dropdown of open alerts, newest first, each with a title, a
 *          |   | one-line summary and a time, no raw hash | ADR-0054, P3
 *   FE-135 | U | The menu is keyboard-operable and announced | aria-expanded,
 *          |   | aria-haspopup, Enter/Space open, arrows move, Escape closes
 *          |   | and returns focus, a polite live region names new alerts | §6.4
 *   FE-137 | U | The menu degrades honestly and stays read-only | Count-only
 *          |   | fallback when the list read fails; no resolve or dismiss
 *          |   | control anywhere | P2, ADR-0044
 */

import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { HeaderAlerts } from "./HeaderAlerts";
import { NotificationMenu } from "./NotificationMenu";
import type { NotificationMenuProps } from "./NotificationMenu";
import { DRIFT, NOW, SEGMENT_DRIFT, UNATTRIBUTED } from "./fixtures";
import { strings } from "./strings";

function menu(over: Partial<NotificationMenuProps> = {}) {
  return render(
    <NotificationMenu
      alerts={[DRIFT, UNATTRIBUTED]}
      openCount={2}
      now={NOW}
      {...over}
    />,
  );
}

const bell = () => screen.getByRole("button", { name: /alerts/i });

describe("FE-134 the bell and its badge", () => {
  it("is a real button that says it opens a menu, closed at first", () => {
    menu();
    expect(bell()).toHaveAttribute("aria-haspopup", "menu");
    expect(bell()).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("carries a red count badge when an alert is open", () => {
    const { container } = menu();
    const badge = container.querySelector("[data-alert-badge]");
    expect(badge).not.toBeNull();
    expect(badge).toHaveTextContent("2");
    expect(badge!.className).toMatch(/\bbg-integrity-alert-surface\b/);
    expect(bell()).toHaveAccessibleName(strings.menu.buttonLabel(2));
  });

  it("counts from the aggregate when more are open than the feed page holds", () => {
    const { container } = menu({ openCount: 57 });
    expect(container.querySelector("[data-alert-badge]")).toHaveTextContent("57");
  });

  it("shows no badge at all when nothing is open (P3: the calm state is quiet)", () => {
    const { container } = menu({ alerts: [{ ...DRIFT, resolved: true }], openCount: 0 });
    expect(container.querySelector("[data-alert-badge]")).toBeNull();
    expect(container.innerHTML).not.toMatch(/integrity-alert/);
    expect(bell()).toHaveAccessibleName(strings.menu.buttonLabel(0));
  });

  it("is not a page banner: it raises no role=alert", () => {
    menu();
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

describe("FE-134 the dropdown", () => {
  it("lists open alerts newest first, with a title, a summary and a time", async () => {
    const user = userEvent.setup();
    menu({ alerts: [DRIFT, UNATTRIBUTED, SEGMENT_DRIFT], openCount: 3 });
    await user.click(bell());
    expect(bell()).toHaveAttribute("aria-expanded", "true");
    const items = within(screen.getByRole("menu")).getAllByRole("menuitem");
    expect(items).toHaveLength(3);
    // Newest first, by chain position: 40, 32, 25.
    expect(items[0]).toHaveTextContent(strings.alert.driftTitle);
    expect(items[1]).toHaveTextContent(strings.alert.unattributedTitle);
    expect(items[2]).toHaveTextContent(strings.alert.driftTitle);
    for (const item of items) {
      expect(item.querySelector("time")).not.toBeNull();
    }
    expect(items[1]).toHaveTextContent(/3 min ago|16 min ago/);
  });

  it("links each item to its own detail view", async () => {
    const user = userEvent.setup();
    menu();
    await user.click(bell());
    const items = screen.getAllByRole("menuitem");
    expect(items[0]).toHaveAttribute("href", `/alerts/${UNATTRIBUTED.event_id}`);
    expect(items[1]).toHaveAttribute("href", `/alerts/${DRIFT.event_id}`);
  });

  it("puts no raw hash and no JSON in the list", async () => {
    const user = userEvent.setup();
    menu({ alerts: [DRIFT, UNATTRIBUTED, SEGMENT_DRIFT], openCount: 3 });
    await user.click(bell());
    const text = screen.getByRole("menu").textContent ?? "";
    expect(text).not.toMatch(/[0-9a-f]{16,}/i);
    expect(text).not.toContain(UNATTRIBUTED.rekor_entry_uuid!);
    expect(text).not.toContain(DRIFT.subject_event_id!);
    expect(text).not.toMatch(/[{}]/);
    expect(text).not.toContain("_");
  });

  it("gives a drift alert a human summary rather than the reason's field names", async () => {
    const user = userEvent.setup();
    menu({ alerts: [DRIFT], openCount: 1 });
    await user.click(bell());
    const item = screen.getByRole("menuitem");
    expect(item).toHaveTextContent(strings.alert.reasons.noLogEntry);
  });

  it("leaves resolved alerts out of the list", async () => {
    const user = userEvent.setup();
    menu({ alerts: [DRIFT, { ...UNATTRIBUTED, resolved: true }], openCount: 1 });
    await user.click(bell());
    expect(screen.getAllByRole("menuitem")).toHaveLength(1);
  });

  it("notes the rest when more are open than the list holds, linking to the alerts page", async () => {
    const user = userEvent.setup();
    menu({ openCount: 5 });
    await user.click(bell());
    const more = screen.getByRole("menuitem", { name: strings.menu.moreDetail(3) });
    expect(more).toHaveAttribute("href", "/alerts");
  });

  it("says so when nothing is open, rather than showing an empty box", async () => {
    const user = userEvent.setup();
    menu({ alerts: [], openCount: 0 });
    await user.click(bell());
    expect(screen.getByRole("menu")).toHaveTextContent(strings.menu.emptyDetail);
  });
});

describe("FE-137 the menu degrades honestly and stays read-only", () => {
  it("falls back to the count when the list read did not answer (P2)", async () => {
    const user = userEvent.setup();
    const { container } = menu({ alerts: null, openCount: 4 });
    expect(container.querySelector("[data-alert-badge]")).toHaveTextContent("4");
    await user.click(bell());
    const item = screen.getByRole("menuitem");
    expect(item).toHaveTextContent(strings.menu.countOnlyDetail(4));
    expect(item).toHaveAttribute("href", "/alerts");
  });

  it("says the count is unknown when neither read answered, never zero", () => {
    const { container } = menu({ alerts: null, openCount: null });
    const badge = container.querySelector("[data-alert-badge]");
    expect(badge).not.toBeNull();
    expect(badge!.className).toMatch(/\bbg-degraded-surface\b/);
    expect(bell()).toHaveAccessibleName(strings.menu.buttonUnknownLabel);
  });

  it("offers no resolve and no dismiss control (ADR-0044)", async () => {
    const user = userEvent.setup();
    menu();
    await user.click(bell());
    expect(screen.getAllByRole("button")).toHaveLength(1);
    expect(document.body.textContent).not.toMatch(/resolve|dismiss|mark as read/i);
  });
});

describe("FE-135 keyboard and announcements", () => {
  it("opens on Enter and puts focus on the first item", async () => {
    const user = userEvent.setup();
    menu();
    bell().focus();
    await user.keyboard("{Enter}");
    expect(screen.getAllByRole("menuitem")[0]).toHaveFocus();
  });

  it("opens on Space too", async () => {
    const user = userEvent.setup();
    menu();
    bell().focus();
    await user.keyboard(" ");
    expect(screen.getByRole("menu")).toBeInTheDocument();
  });

  it("moves through items with the arrow keys, wrapping at the ends", async () => {
    const user = userEvent.setup();
    menu();
    bell().focus();
    await user.keyboard("{Enter}");
    const items = screen.getAllByRole("menuitem");
    await user.keyboard("{ArrowDown}");
    expect(items[1]).toHaveFocus();
    await user.keyboard("{ArrowDown}");
    expect(items[0]).toHaveFocus();
    await user.keyboard("{ArrowUp}");
    expect(items[1]).toHaveFocus();
  });

  it("closes on Escape and returns focus to the bell", async () => {
    const user = userEvent.setup();
    menu();
    bell().focus();
    await user.keyboard("{Enter}");
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("menu")).toBeNull();
    expect(bell()).toHaveFocus();
    expect(bell()).toHaveAttribute("aria-expanded", "false");
  });

  it("closes when an item is followed", async () => {
    const user = userEvent.setup();
    menu();
    await user.click(bell());
    await user.click(screen.getAllByRole("menuitem")[0]!);
    expect(screen.queryByRole("menu")).toBeNull();
    expect(window.location.pathname).toBe(`/alerts/${UNATTRIBUTED.event_id}`);
  });

  it("announces a new open alert through a polite live region", () => {
    const view = menu({ alerts: [DRIFT], openCount: 1 });
    const live = view.container.querySelector('[aria-live="polite"]');
    expect(live).not.toBeNull();
    view.rerender(
      <NotificationMenu
        alerts={[DRIFT, UNATTRIBUTED]}
        openCount={2}
          now={NOW}
      />,
    );
    expect(live).toHaveTextContent(strings.menu.announceNew(1));
  });
});

/* The header reads for itself, so the menu is on every page. */
function ok(body: unknown): Response {
  return { ok: true, status: 200, json: async () => body } as unknown as Response;
}
function dead(status: number): Response {
  return { ok: false, status, json: async () => ({}) } as unknown as Response;
}

const OVERVIEW = {
  active_runs: 0,
  lapsed_runs: 0,
  abandoned_runs: 0,
  retired_runs: 0,
  commits_recorded: 0,
  open_alerts: 2,
  anchor: { present: false, anchored: false },
  data_as_of: "2026-09-06T18:13:00Z",
};

function api(route: (url: string) => Response) {
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown) => Promise.resolve(route(String(input)))),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("FE-134 the header reads open alerts itself", () => {
  it("counts and lists what the alerts feed returned", async () => {
    api((url) =>
      url.includes("/alerts")
        ? ok({ alerts: [DRIFT, UNATTRIBUTED], total: 2, limit: 50, data_as_of: "" })
        : ok(OVERVIEW),
    );
    const { container } = render(<HeaderAlerts now={NOW} pollMs={0} />);
    await waitFor(() =>
      expect(container.querySelector("[data-alert-badge]")).toHaveTextContent("2"),
    );
  });

  it("falls back to the overview's count when the alerts feed fails", async () => {
    api((url) => (url.includes("/alerts") ? dead(502) : ok({ ...OVERVIEW, open_alerts: 3 })));
    const user = userEvent.setup();
    const { container } = render(<HeaderAlerts now={NOW} pollMs={0} />);
    await waitFor(() =>
      expect(container.querySelector("[data-alert-badge]")).toHaveTextContent("3"),
    );
    await user.click(bell());
    expect(screen.getByRole("menuitem")).toHaveTextContent(strings.menu.countOnlyDetail(3));
  });

  it("reads again on an interval, so a new alert reaches an open page", async () => {
    let feed = [DRIFT];
    api((url) =>
      url.includes("/alerts")
        ? ok({ alerts: feed, total: feed.length, limit: 50, data_as_of: "" })
        : ok({ ...OVERVIEW, open_alerts: feed.length }),
    );
    const { container } = render(<HeaderAlerts now={NOW} pollMs={20} />);
    await waitFor(() =>
      expect(container.querySelector("[data-alert-badge]")).toHaveTextContent("1"),
    );
    act(() => {
      feed = [DRIFT, UNATTRIBUTED];
    });
    await waitFor(() =>
      expect(container.querySelector("[data-alert-badge]")).toHaveTextContent("2"),
    );
  });
});
