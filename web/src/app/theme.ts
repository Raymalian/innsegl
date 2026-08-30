// SPDX-License-Identifier: Apache-2.0

// The theme override, which is one HTML attribute and nothing else.
//
// doc 06 §5.1 asks for "light and dark mode from day one, token-driven,
// honoring prefers-color-scheme with a manual override". ADR-0038 decision 3
// already answered the hard half of that in CSS: every semantic colour in
// tokens.css resolves through `color-scheme`, `:root` carries `color-scheme:
// light dark` so the operating system decides by default, and two
// `[data-theme]` rules are the override. So the shell's entire contribution is
// to set, clear and persist that attribute.
//
// This module therefore holds no colour value and no mode-dependent branch,
// and FE-018 asserts that by scanning this file: a theme implemented twice,
// once in the sheet and once in JavaScript, is two things that can disagree,
// and the one that disagrees silently is the one nobody looks at.
//
// The other half of the requirement is that the override must not flash.
// A theme applied by React runs after the first paint, so a reader who chose
// the dark override sees a light page first on every load. THEME_BOOTSTRAP is
// the smallest thing that fixes that: a blocking inline script in the document
// head, running before anything is painted. It is exported from here rather
// than written into the HTML by hand so that the storage key has exactly one
// definition, and FE-018 asserts that index.html carries this exact text.

/** Follow the operating system, or override it either way. */
export const THEME_PREFERENCES = ["system", "light", "dark"] as const;

export type ThemePreference = (typeof THEME_PREFERENCES)[number];

/** Where the override lives across reloads. */
export const THEME_STORAGE_KEY = "innsegl.theme";

/**
 * The pre-paint bootstrap, inlined into index.html's head.
 *
 * Deliberately unminified-looking and dependency-free: it is read by whoever
 * views source on the deployed page, and a reader who trusts nothing about
 * this deployment (doc 06 §1) should be able to see that the first script the
 * page runs reads one storage key and sets one attribute.
 *
 * The try/catch is not decoration. Reading localStorage throws outright in a
 * browser configured to block site data, and an exception here would abort the
 * script that follows it.
 */
export const THEME_BOOTSTRAP =
  'try{var t=localStorage.getItem("innsegl.theme");' +
  'if(t==="light"||t==="dark"){document.documentElement.setAttribute("data-theme",t)}}catch(e){}';

const isPreference = (v: unknown): v is ThemePreference =>
  typeof v === "string" && (THEME_PREFERENCES as readonly string[]).includes(v);

/**
 * The stored override, or `system` when there is none — including when there
 * is one this version does not understand, and when storage cannot be read at
 * all. A page that will not render because a preference was unreadable is a
 * worse outcome than a page in the wrong mode.
 */
export function readPreference(): ThemePreference {
  let stored: string | null = null;
  try {
    stored = window.localStorage.getItem(THEME_STORAGE_KEY);
  } catch {
    return "system";
  }
  return isPreference(stored) && stored !== "system" ? stored : "system";
}

/**
 * Persist the override. `system` removes the entry rather than storing a third
 * value, so "never chose" and "chose to follow the system" are the same state
 * and cannot drift apart.
 */
export function storePreference(preference: ThemePreference): void {
  try {
    if (preference === "system") {
      window.localStorage.removeItem(THEME_STORAGE_KEY);
    } else {
      window.localStorage.setItem(THEME_STORAGE_KEY, preference);
    }
  } catch {
    // A reader who blocks site data gets a theme for this page load only.
  }
}

/**
 * Apply the override to the document. Removing the attribute is what returns
 * the page to `prefers-color-scheme`; nothing else has to be undone, because
 * nothing else was ever set.
 */
export function applyPreference(
  preference: ThemePreference,
  root: HTMLElement = document.documentElement,
): void {
  if (preference === "system") {
    root.removeAttribute("data-theme");
  } else {
    root.setAttribute("data-theme", preference);
  }
}
