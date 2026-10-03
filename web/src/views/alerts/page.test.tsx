// SPDX-License-Identifier: Apache-2.0

/*
 * RM-330 (#506) — the alerts page.
 *
 * Every alert, open and resolved, grouped by what raised it, with counts;
 * filtered by kind and by run through the URL; each row a link to the alert's
 * own page; a group's open alerts resolvable together. Keyboard-operable.
 */

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useRoute } from "../../app/router";
import { parseRoute, type Route } from "../../app/routes";
import type { AlertRecord } from "../overview/types";
import { AlertsPage } from "./AlertsPage";
import { AlertsView } from "./AlertsView";
import { DRIFT, NOW, UNATTRIBUTED } from "./fixtures";
import { strings } from "./strings";

const WITNESS = (n: number, extra: Partial<AlertRecord> = {}): AlertRecord => ({
  ...DRIFT,
  event_id: `01a07900-0000-7000-8000-00000000010${n}`,
  chain_position: 100 + n,
  reason: "the harness's own OTLP telemetry recorded no tool_result for this tool call",
  ...extra,
});

const RESOLVED_UNATTRIBUTED: AlertRecord = {
  ...UNATTRIBUTED,
  resolved: true,
  resolved_by: "Operator",
  resolved_at: "2026-09-06T18:00:00Z",
  resolved_reason: "a key rotation",
};

const ALL = [DRIFT, WITNESS(1), WITNESS(2), WITNESS(3, { run_id: "run-other" }), RESOLVED_UNATTRIBUTED];

function page(route: Route, alerts: readonly AlertRecord[] = ALL, complete = true) {
  if (route.view !== "alerts") throw new Error("not an alerts route");
  return render(
    <AlertsPage
      alerts={alerts}
      complete={complete}
      filters={route.filters}
      now={NOW}
      onResolved={vi.fn()}
    />,
  );
}

/** The page at whatever the address bar says, re-rendered on navigation. */
function AtAddress() {
  const route = useRoute();
  return route.view === "alerts" ? (
    <AlertsPage alerts={ALL} complete filters={route.filters} now={NOW} onResolved={vi.fn()} />
  ) : null;
}

function group(title: string): HTMLElement {
  return screen.getByRole("region", { name: title });
}

beforeEach(() => {
  window.history.replaceState(null, "", "/alerts");
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("RM-330 the alerts page", () => {
  it("has its heading and lists open alerts by default, grouped by cause", () => {
    page(parseRoute("/alerts"));
    expect(screen.getByRole("heading", { level: 1, name: strings.page.heading })).toBeInTheDocument();
    const witness = group(strings.explain.noTelemetryWitness.title);
    expect(within(witness).getAllByRole("link")).toHaveLength(3);
    expect(within(witness).getByText(strings.page.openCount(3))).toBeInTheDocument();
    // The resolved unattributed alert is not listed under "open".
    expect(screen.queryByRole("region", { name: strings.explain.unattributed.title })).toBeNull();
  });

  it("links every row to the alert's own page", () => {
    page(parseRoute("/alerts"));
    const rekor = group(strings.explain.rekorMismatch.title);
    expect(within(rekor).getByRole("link")).toHaveAttribute("href", `/alerts/${DRIFT.event_id}`);
  });

  it("explains each group's cause and what to do", () => {
    page(parseRoute("/alerts"));
    const witness = group(strings.explain.noTelemetryWitness.title);
    expect(witness).toHaveTextContent(strings.explain.noTelemetryWitness.todoDetail);
  });

  it("lists resolved alerts with who resolved them, when asked", () => {
    page(parseRoute("/alerts?kind=resolved"));
    const regions = screen.getAllByRole("region");
    expect(regions).toHaveLength(1);
    expect(regions[0]).toHaveTextContent(strings.page.rowResolvedStatus("Operator"));
    expect(regions[0]).toHaveTextContent(strings.page.resolvedCount(1));
  });

  it("narrows to one run", () => {
    page(parseRoute("/alerts?run=run-other"));
    const witness = group(strings.explain.noTelemetryWitness.title);
    expect(within(witness).getAllByRole("link")).toHaveLength(1);
    expect(screen.queryByRole("region", { name: strings.explain.rekorMismatch.title })).toBeNull();
  });

  it("puts kind and run in the URL, operable from the keyboard", async () => {
    render(<AtAddress />);
    const user = userEvent.setup();
    const resolved = screen.getByRole("button", { name: strings.page.kinds.resolved });
    expect(screen.getByRole("button", { name: strings.page.kinds.open })).toHaveAttribute("aria-pressed", "true");
    resolved.focus();
    await user.keyboard("{Enter}");
    expect(window.location.search).toBe("?kind=resolved");
    expect(screen.getByRole("button", { name: strings.page.kinds.resolved })).toHaveAttribute("aria-pressed", "true");

    await user.selectOptions(screen.getByLabelText(strings.page.runLabel), "run-other");
    expect(window.location.search).toBe("?kind=resolved&run=run-other");
  });

  it("says plainly when nothing matches, rather than showing an empty box", () => {
    page(parseRoute("/alerts"), [RESOLVED_UNATTRIBUTED]);
    expect(screen.getByText(strings.page.emptyOpenDetail)).toBeInTheDocument();
  });

  it("says so when it could not read every alert", () => {
    page(parseRoute("/alerts"), ALL, false);
    expect(screen.getByText(strings.page.incompleteDetail(ALL.length))).toBeInTheDocument();
  });

  it("opens a resolve form for a group's open alerts", async () => {
    page(parseRoute("/alerts"));
    const user = userEvent.setup();
    const witness = group(strings.explain.noTelemetryWitness.title);
    await user.click(within(witness).getByRole("button", { name: strings.page.resolveGroupLabel(3) }));
    expect(within(witness).getByRole("form", { name: strings.resolve.groupHeading(3) })).toBeInTheDocument();
  });

  it("offers no resolve for a group with nothing open", () => {
    page(parseRoute("/alerts?kind=resolved"));
    expect(screen.queryByRole("button", { name: /^Resolve (this|these)/ })).toBeNull();
  });
});

describe("RM-330 the alerts page, wired", () => {
  it("reads every page of the feed and renders the groups", async () => {
    const urls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        urls.push(url);
        const body = url.includes("cursor=")
          ? { alerts: [WITNESS(1)], total: 2, limit: 200, data_as_of: "2026-10-03T00:00:00Z" }
          : { alerts: [DRIFT], total: 2, limit: 200, next_cursor: "25", data_as_of: "2026-10-03T00:00:00Z" };
        return new Response(JSON.stringify(body), { status: 200 });
      }),
    );
    render(<AlertsView route={parseRoute("/alerts")} now={NOW} />);
    await waitFor(() =>
      expect(screen.getByRole("region", { name: strings.explain.noTelemetryWitness.title })).toBeInTheDocument(),
    );
    expect(urls).toEqual(["/api/v1/alerts?limit=200", "/api/v1/alerts?limit=200&cursor=25"]);
  });

  it("says what failed rather than showing an empty page", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 503 })));
    render(<AlertsView route={parseRoute("/alerts")} now={NOW} />);
    expect(await screen.findByText(/answered 503/)).toBeInTheDocument();
  });
});
