// SPDX-License-Identifier: Apache-2.0

/*
 * The mark, beside the wordmark, in the persistent header — doc 06 §3, §6.4.
 *
 * doc 06's preamble asks for the product name "in UI chrome: Innsegl (wordmark
 * only; no logo requirement for Phase 4)". That is a floor, not a ceiling: it
 * says the shell does not HAVE to draw a mark, and until now it did not, so the
 * only place the seal appeared was a 16px browser tab. The drawing exists, it
 * is the thing the product is named after, and the header is where it belongs.
 *
 * ── THREE DECISIONS ────────────────────────────────────────────────────────
 *
 * 1. DRAWN INLINE, NOT FETCHED. `Icon.tsx` states the rule this chrome
 *    follows — "Nothing here is fetched" — and ADR-0038 decision 7 is the
 *    reason: the shell's chrome does not spend a request on itself. An
 *    `<img src="/innsegl-mark.svg">` would put one back on every page load for
 *    a drawing that is under a kilobyte of markup.
 *
 *    That buys a second copy of the geometry, and a second copy drifts.
 *    `public/innsegl-mark.svg` stays the source of truth and FE-112 reads it:
 *    every element and every geometry attribute below must be the one the file
 *    carries, in the same order. Change the seal in one place and the test
 *    fails rather than the two seals quietly becoming different drawings.
 *
 * 2. THE READING-SIZE WEIGHT. There are two files and they are one drawing at
 *    two stroke weights — `favicon.svg` is heavier because at 16px the rim and
 *    the rune disappear. This renders above 32px, so it takes
 *    `innsegl-mark.svg`'s weights. FE-112 asserts it is not the other one.
 *
 * 3. SILENT. `aria-hidden` always, exactly as `Icon.tsx` puts it: "The icon
 *    duplicates the label for sighted readers; announcing it as well would
 *    read the same fact twice." The label beside it already says Innsegl.
 *    The file itself carries `role="img"`, an `aria-label` and a `<title>` —
 *    correct for a file somebody opens on its own, and wrong here, so none of
 *    the three is copied across. `focusable="false"` keeps it out of the tab
 *    order, which is the one thing `aria-hidden` does not do.
 *
 * ── THE COLOUR, AND WHY IT IS NOT A §5.3 PROBLEM ───────────────────────────
 *
 * The wax is the same value the verification palette holds, and doc 06 §5.3
 * reserves green: "Green = cryptographic verification passed. Nothing else is
 * ever green." §5.3 governs colour used to make a CLAIM — a verdict, a state,
 * a trend. This mark makes none. It is identical on a run that verified and a
 * run that failed, it never changes, and it carries no data, so there is no
 * reading of it under which a green says something true or false about the
 * page. It is also the seal the product is named for, and it has been in the
 * browser tab in this colour since the shell existed; drawing it in a
 * different colour beside the wordmark than in the tab would make the header
 * and the tab two different marks.
 *
 * The values are written out rather than taken from the sheet on purpose. A
 * token would let the mark change when the palette changed — which is exactly
 * what must not happen to an identity mark — and reaching the verification
 * family from outside the `proof-verified` group is what `check-tokens.sh`
 * refuses. This is a drawing with fixed pigments, held to the asset by FE-112,
 * not a themed surface.
 */

export interface AppMarkProps {
  /** Size and spacing only. The pigments are fixed; see above. */
  readonly className?: string;
}

export function AppMark({ className }: AppMarkProps) {
  return (
    <svg
      data-app-mark
      aria-hidden="true"
      focusable="false"
      viewBox="0 0 32 32"
      width="1.25em"
      height="1.25em"
      className={className}
    >
      {/* The wax, squeezed out unevenly. */}
      <path
        d="M16.00 1.00C18.07 1.00 20.28 2.15 22.20 3.12C24.13 4.08 26.31 5.15 27.57 6.77C28.83 8.40 29.25 10.77 29.75 12.86C30.24 14.95 30.94 17.30 30.53 19.32C30.11 21.33 28.59 23.26 27.26 24.98C25.93 26.69 24.43 28.73 22.55 29.60C20.68 30.47 18.15 30.26 16.00 30.20C13.85 30.14 11.45 30.16 9.62 29.24C7.80 28.33 6.41 26.38 5.05 24.73C3.70 23.07 2.01 21.31 1.47 19.32C0.94 17.32 1.40 14.88 1.86 12.77C2.33 10.66 2.95 8.26 4.27 6.65C5.59 5.04 7.84 4.06 9.80 3.12C11.75 2.17 13.93 1.00 16.00 1.00Z"
        fill="#167a49"
      />
      {/* The rim the die pressed into it. */}
      <circle cx="16" cy="16" r="10.5" fill="none" stroke="#fff" strokeWidth="1.3" />
      {/* The bind-rune: one stave carrying two arms. */}
      <g
        fill="none"
        stroke="#fff"
        strokeWidth="2.3"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M16 9.2v13.6" />
        <path d="M19.8 11 16 14l3.8 3" />
        <path d="M12.2 15 16 18l-3.8 3" />
      </g>
    </svg>
  );
}
