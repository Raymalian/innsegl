// SPDX-License-Identifier: Apache-2.0

// FE-021 — the shell: flat navigation across the six views, landmarks a
// screen reader can move between, keyboard-only operability, a theme override
// that reaches the document, and copy that comes from the catalogue rather
// than from the components.

import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { App } from "./App";
import { StringsProvider } from "./i18n";
import { en, type Strings } from "./strings";
import { THEME_STORAGE_KEY } from "./theme";

class MemoryStorage implements Storage {
  private entries = new Map<string, string>();
  get length(): number {
    return this.entries.size;
  }
  clear(): void {
    this.entries.clear();
  }
  getItem(key: string): string | null {
    return this.entries.get(key) ?? null;
  }
  key(index: number): string | null {
    return [...this.entries.keys()][index] ?? null;
  }
  removeItem(key: string): void {
    this.entries.delete(key);
  }
  setItem(key: string, value: string): void {
    this.entries.set(key, value);
  }
}

const originalStorage = Object.getOwnPropertyDescriptor(window, "localStorage");

/** Tab until the element has focus, or fail — never loop forever. */
async function tabTo(
  user: ReturnType<typeof userEvent.setup>,
  target: Element,
): Promise<void> {
  for (let i = 0; i < 20; i += 1) {
    if (document.activeElement === target) return;
    await user.tab();
  }
  throw new Error("element was not reachable by Tab within 20 stops");
}

beforeEach(() => {
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: new MemoryStorage(),
  });
  window.history.replaceState(null, "", "/");
  document.documentElement.removeAttribute("data-theme");
});

afterEach(() => {
  if (originalStorage) {
    Object.defineProperty(window, "localStorage", originalStorage);
  }
});

describe("FE-021 landmarks and structure", () => {
  it("gives a screen reader a banner, a named navigation region and a main region", () => {
    render(<App />);
    expect(screen.getByRole("banner")).toBeInTheDocument();
    expect(
      screen.getByRole("navigation", { name: en.labels.nav.region }),
    ).toBeInTheDocument();
    expect(screen.getByRole("main")).toBeInTheDocument();
  });

  it("carries the wordmark doc 06 names, as text rather than as an image", () => {
    render(<App />);
    const banner = screen.getByRole("banner");
    expect(within(banner).getByText(en.labels.app.name)).toBeInTheDocument();
    expect(within(banner).queryByRole("img")).toBeNull();
  });

  it("reserves the header slot doc 06 §3.1 gives the anchoring heartbeat", () => {
    render(<App heartbeat={<span>segment 41</span>} />);
    const region = screen.getByRole("status", { name: en.labels.header.anchoring });
    expect(within(region).getByText("segment 41")).toBeInTheDocument();
  });

  it("offers a skip link to the main region as the first focusable thing", async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.tab();
    const skip = screen.getByRole("link", { name: en.labels.app.skipToContent });
    expect(skip).toHaveFocus();
    expect(skip.getAttribute("href")).toBe(`#${screen.getByRole("main").id}`);
  });
});

describe("FE-021 flat navigation", () => {
  it("offers only destinations that have an address of their own", () => {
    render(<App />);
    const nav = screen.getByRole("navigation", { name: en.labels.nav.region });
    expect(within(nav).getAllByRole("link").map((a) => a.textContent)).toEqual([
      en.labels.views.overview,
      en.labels.views.runs,
      en.labels.views.verify,
    ]);
  });

  it("nests no deeper than view → detail: every nav href is one segment", () => {
    render(<App />);
    const nav = screen.getByRole("navigation", { name: en.labels.nav.region });
    for (const link of within(nav).getAllByRole("link")) {
      const path = (link.getAttribute("href") ?? "").split("?")[0] ?? "";
      expect(path.split("/").filter((s) => s !== "").length).toBeLessThanOrEqual(1);
    }
  });

  it.each([
    ["/", en.labels.views.overview],
    ["/runs", en.labels.views.runs],
    ["/runs/run-7f3a", en.labels.views.run],
    ["/repos/acme%2Fwidgets", en.labels.views.repo],
    ["/agent-types/fix-ci", en.labels.views.agentType],
    ["/verify?commit=9d4e1f0c", en.labels.views.verify],
  ])("routes %s to the %s view", (path, heading) => {
    window.history.replaceState(null, "", path);
    render(<App />);
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(heading);
  });

  it("says so plainly when no view matches the address", () => {
    window.history.replaceState(null, "", "/nope");
    render(<App />);
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
      en.labels.notFound.heading,
    );
    expect(screen.getByText(en.sentences.notFound.body)).toBeInTheDocument();
  });

  it("never presents a placeholder as evidence (P2)", () => {
    render(<App />);
    expect(screen.getByText(en.sentences.placeholder.unbuilt)).toBeInTheDocument();
    expect(
      screen.getByText(en.sentences.placeholder.notEvidence),
    ).toBeInTheDocument();
  });

  it("renders an injected view instead of the placeholder, which is the seam wave 4 uses", () => {
    render(<App views={{ overview: () => <h1>the real overview</h1> }} />);
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
      "the real overview",
    );
  });

  it("is operable by keyboard alone: tab to a destination, press Enter, the view changes", async () => {
    const user = userEvent.setup();
    render(<App />);
    const runs = screen.getByRole("link", { name: en.labels.views.runs });
    await tabTo(user, runs);
    await user.keyboard("{Enter}");
    expect(window.location.pathname).toBe("/runs");
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
      en.labels.views.runs,
    );
    expect(runs).toHaveAttribute("aria-current", "page");
  });

  it("marks the runs destination current while a run detail is open", () => {
    window.history.replaceState(null, "", "/runs/run-7f3a");
    render(<App />);
    expect(
      screen.getByRole("link", { name: en.labels.views.runs }),
    ).toHaveAttribute("aria-current", "true");
  });

  it("names the open view in the document title, so a bookmark says what it is", () => {
    window.history.replaceState(null, "", "/runs");
    render(<App />);
    expect(document.title).toBe(`${en.labels.views.runs} · ${en.labels.app.name}`);
  });
});

describe("FE-021 theme control", () => {
  it("presents the three preferences as one named group of radios", () => {
    render(<App />);
    const group = screen.getByRole("group", { name: en.labels.theme.region });
    expect(within(group).getAllByRole("radio")).toHaveLength(3);
    expect(
      within(group).getByRole("radio", { name: en.labels.theme.system }),
    ).toBeChecked();
  });

  it("applies and persists a manual override", async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole("radio", { name: en.labels.theme.dark }));
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
  });

  it("hands the page back to the system, clearing what it stored", async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole("radio", { name: en.labels.theme.dark }));
    await user.click(screen.getByRole("radio", { name: en.labels.theme.system }));
    expect(document.documentElement.hasAttribute("data-theme")).toBe(false);
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBeNull();
  });

  it("shows the stored override as the chosen one on load", () => {
    window.localStorage.setItem(THEME_STORAGE_KEY, "light");
    render(<App />);
    expect(
      screen.getByRole("radio", { name: en.labels.theme.light }),
    ).toBeChecked();
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
  });

  it("is reachable by keyboard alone", async () => {
    const user = userEvent.setup();
    render(<App />);
    // Within a radio group only the checked radio is a tab stop; the arrow
    // keys move between the options. That is the browser's behaviour and the
    // test asserts it rather than working around it.
    const system = screen.getByRole("radio", { name: en.labels.theme.system });
    await tabTo(user, system);
    await user.keyboard("{ArrowDown}");
    expect(
      screen.getByRole("radio", { name: en.labels.theme.light }),
    ).toBeChecked();
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
  });
});

describe("FE-021 the copy really is external", () => {
  it("renders a replacement catalogue, which is what §6.3 is asking for", () => {
    const translated = JSON.parse(JSON.stringify(en)) as Strings;
    (translated.labels.views as { runs: string }).runs = "Kjøringer";
    render(
      <StringsProvider strings={translated}>
        <App />
      </StringsProvider>,
    );
    expect(
      screen.getByRole("link", { name: "Kjøringer" }),
    ).toBeInTheDocument();
  });
});
