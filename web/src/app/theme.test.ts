// SPDX-License-Identifier: Apache-2.0

// FE-018 — theming: a manual override that beats prefers-color-scheme,
// persists across a reload, and is applied before the first paint.
//
// doc 06 §5.1: "Light and dark mode from day one, token-driven, honoring
// prefers-color-scheme with a manual override." ADR-0038 decision 3 already
// made both modes structural in CSS, so the shell's whole job is the
// data-theme attribute — there is no colour in this file and no theme logic in
// JavaScript beyond setting one attribute.

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import indexHtml from "../../index.html?raw";
import tokensCss from "../tokens/tokens.css?raw";
import themeSource from "./theme.ts?raw";
import {
  THEME_BOOTSTRAP,
  THEME_PREFERENCES,
  THEME_STORAGE_KEY,
  applyPreference,
  readPreference,
  storePreference,
  type ThemePreference,
} from "./theme";



// This vitest/jsdom environment exposes no working localStorage: `window` is
// the Node global object, and Node's own experimental `localStorage` getter —
// which returns undefined without --localstorage-file — shadows the jsdom
// window's. jsdom 27 itself implements Storage correctly (verified directly).
// So the tests below install a real in-memory Storage; the code under test is
// unchanged and reads `window.localStorage` exactly as a browser serves it.
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

beforeEach(() => {
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: new MemoryStorage(),
  });
  document.documentElement.removeAttribute("data-theme");
});

afterEach(() => {
  if (originalStorage) {
    Object.defineProperty(window, "localStorage", originalStorage);
  }
});

describe("FE-018 theme override", () => {
  it("offers exactly three preferences: follow the system, or override either way", () => {
    expect([...THEME_PREFERENCES]).toEqual(["system", "light", "dark"]);
  });

  it("sets data-theme on the root element for a manual choice", () => {
    applyPreference("dark");
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    applyPreference("light");
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
  });

  it("removes the attribute for `system`, handing the page back to prefers-color-scheme", () => {
    applyPreference("dark");
    applyPreference("system");
    expect(document.documentElement.hasAttribute("data-theme")).toBe(false);
  });

  it("overrides the system preference through the attribute the token sheet listens for", () => {
    // The override is structural CSS, not JavaScript: the sheet resolves every
    // colour with light-dark() under color-scheme, and these three rules are
    // the whole switching mechanism. If the shell set some other attribute the
    // override would be inert, so the seam is asserted rather than assumed.
    expect(tokensCss).toMatch(/:root\s*\{[^}]*color-scheme:\s*light dark;/);
    expect(tokensCss).toMatch(
      /:root\[data-theme="light"\]\s*\{\s*color-scheme:\s*light;\s*\}/,
    );
    expect(tokensCss).toMatch(
      /:root\[data-theme="dark"\]\s*\{\s*color-scheme:\s*dark;\s*\}/,
    );

    applyPreference("light");
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
  });

  it("does not reimplement theming in JavaScript: no colour value appears in this module", () => {
    expect(themeSource).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    expect(themeSource).not.toMatch(/\b(rgb|hsl|oklch|light-dark)\s*\(/);
  });
});

describe("FE-018 theme persistence", () => {
  it("survives a reload: the choice is stored and read back", () => {
    storePreference("dark");
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
    expect(readPreference()).toBe("dark");
  });

  it("defaults to `system` when nothing was ever chosen", () => {
    expect(readPreference()).toBe("system");
  });

  it("ignores a stored value that is not one of the three", () => {
    window.localStorage.setItem(THEME_STORAGE_KEY, "midnight");
    expect(readPreference()).toBe("system");
  });

  it("clears the stored value for `system` rather than persisting a third state", () => {
    storePreference("dark");
    storePreference("system");
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBeNull();
  });

  it("falls back to `system` when storage throws, rather than failing to render", () => {
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      get() {
        throw new Error("storage is blocked");
      },
    });
    expect(readPreference()).toBe("system");
    expect(() => {
      storePreference("dark");
    }).not.toThrow();
  });
});

describe("FE-018 no flash of the wrong theme", () => {
  it("carries the bootstrap as a blocking inline script in the document head", () => {
    const head = indexHtml.slice(0, indexHtml.indexOf("</head>"));
    expect(head).toContain(THEME_BOOTSTRAP);
    // A module, deferred or async script runs after the first paint, which is
    // the flash this test exists to prevent.
    const tag = head.slice(0, head.indexOf(THEME_BOOTSTRAP)).lastIndexOf("<script");
    const openTag = head.slice(tag, head.indexOf(">", tag) + 1);
    expect(openTag).toBe("<script>");
  });

  it("runs before the application entry script", () => {
    expect(indexHtml.indexOf(THEME_BOOTSTRAP)).toBeLessThan(
      indexHtml.indexOf("/src/app/main.tsx"),
    );
  });

  it("restores the stored theme when executed against a fresh document", () => {
    window.localStorage.setItem(THEME_STORAGE_KEY, "dark");
    expect(document.documentElement.hasAttribute("data-theme")).toBe(false);
    new Function(THEME_BOOTSTRAP)();
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
  });

  it("leaves the attribute off when the reader never overrode anything", () => {
    new Function(THEME_BOOTSTRAP)();
    expect(document.documentElement.hasAttribute("data-theme")).toBe(false);
  });

  it("does not throw when storage is unavailable to it", () => {
    window.localStorage.setItem(THEME_STORAGE_KEY, "light");
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      get() {
        throw new Error("storage is blocked");
      },
    });
    expect(() => new Function(THEME_BOOTSTRAP)()).not.toThrow();
  });

  it("agrees with the module on the storage key, so the two cannot drift", () => {
    expect(THEME_BOOTSTRAP).toContain(JSON.stringify(THEME_STORAGE_KEY));
    const preferences: ThemePreference[] = ["light", "dark"];
    for (const p of preferences) expect(THEME_BOOTSTRAP).toContain(`"${p}"`);
  });
});
