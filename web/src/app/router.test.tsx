// SPDX-License-Identifier: Apache-2.0

// FE-017 — navigation: the URL is the state, the back button works, and every
// destination is a real link that the keyboard alone can operate (FD §6.4,
// "Full keyboard operability … Visible focus states").

import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";

import { Link, currentPath, navigate, useRoute } from "./router";
import { emptyRunsFilters, routeToPath, type Route } from "./routes";

function Probe() {
  const route = useRoute();
  return <output data-testid="route">{JSON.stringify(route)}</output>;
}

const shownRoute = (): Route =>
  JSON.parse(screen.getByTestId("route").textContent ?? "null") as Route;

// navigate() and history.back() both drive React from outside an event
// handler, so the test has to let React flush before it looks. history
// traversal is a task in jsdom, hence the tick.
const go = (...args: Parameters<typeof navigate>) =>
  act(() => {
    navigate(...args);
  });

const goBack = () =>
  act(async () => {
    window.history.back();
    await new Promise((resolve) => setTimeout(resolve, 20));
  });

beforeEach(() => {
  window.history.replaceState(null, "", "/");
});

describe("FE-017 navigation", () => {
  it("reads the route out of the address bar on first render", () => {
    window.history.replaceState(null, "", "/runs?repo=acme%2Fwidgets");
    render(<Probe />);
    expect(shownRoute()).toEqual({
      view: "runs",
      filters: { ...emptyRunsFilters(), repo: "acme/widgets" },
    });
  });

  it("re-renders subscribers when navigate pushes a new path", async () => {
    render(<Probe />);
    expect(shownRoute().view).toBe("overview");
    await go({ view: "run", runId: "run-7f3a" });
    expect(currentPath()).toBe("/runs/run-7f3a");
    expect(shownRoute()).toEqual({ view: "run", runId: "run-7f3a" });
  });

  it("restores the previous view when the browser goes back", async () => {
    render(<Probe />);
    await go({ view: "runs", filters: { ...emptyRunsFilters(), status: "expired" } });
    await go({ view: "run", runId: "run-7f3a" });
    expect(shownRoute().view).toBe("run");

    await goBack();
    expect(currentPath()).toBe("/runs?status=expired");
    expect(shownRoute()).toEqual({
      view: "runs",
      filters: { ...emptyRunsFilters(), status: "expired" },
    });
  });

  it("replaces rather than stacks when asked, so a filter change is not a back-button trap", async () => {
    render(<Probe />);
    await go({ view: "runs", filters: emptyRunsFilters() });
    await go(
      { view: "runs", filters: { ...emptyRunsFilters(), status: "active" } },
      { replace: true },
    );
    expect(currentPath()).toBe("/runs?status=active");

    await goBack();
    expect(currentPath()).toBe("/");
  });

  it("renders a destination as a real anchor carrying the full href", () => {
    render(
      <Link to={{ view: "repo", repo: "acme/widgets", from: "", to: "" }}>
        <span>x</span>
      </Link>,
    );
    const anchor = screen.getByRole("link");
    expect(anchor.tagName).toBe("A");
    expect(anchor.getAttribute("href")).toBe(
      routeToPath({ view: "repo", repo: "acme/widgets", from: "", to: "" }),
    );
  });

  it("is operable by keyboard alone: tab to the link, press Enter, the route changes", async () => {
    const user = userEvent.setup();
    render(
      <>
        <Link to={{ view: "run", runId: "run-7f3a" }}>
          <span>x</span>
        </Link>
        <Probe />
      </>,
    );
    await user.tab();
    expect(screen.getByRole("link")).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(currentPath()).toBe("/runs/run-7f3a");
    expect(shownRoute()).toEqual({ view: "run", runId: "run-7f3a" });
  });

  it("leaves a modified click to the browser, so open-in-new-tab still works", async () => {
    const user = userEvent.setup();
    render(
      <Link to={{ view: "run", runId: "run-7f3a" }}>
        <span>x</span>
      </Link>,
    );
    await user.keyboard("{Meta>}");
    await user.click(screen.getByRole("link"));
    await user.keyboard("{/Meta}");
    expect(currentPath()).toBe("/");
  });

  it("marks the section, not the page, when a detail of that section is open", () => {
    window.history.replaceState(null, "", "/runs/run-7f3a");
    render(
      <Link to={{ view: "runs", filters: emptyRunsFilters() }}>
        <span>a</span>
      </Link>,
    );
    expect(screen.getByRole("link")).toHaveAttribute("aria-current", "true");
  });

  it("marks the current destination with aria-current, not with colour alone", () => {
    window.history.replaceState(null, "", "/runs");
    render(
      <>
        <Link to={{ view: "runs", filters: emptyRunsFilters() }}>
          <span>a</span>
        </Link>
        <Link to={{ view: "overview" }}>
          <span>b</span>
        </Link>
      </>,
    );
    const [runs, overview] = screen.getAllByRole("link");
    expect(runs).toHaveAttribute("aria-current", "page");
    expect(overview).not.toHaveAttribute("aria-current");
  });
});
