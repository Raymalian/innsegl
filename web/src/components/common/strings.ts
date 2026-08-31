// SPDX-License-Identifier: Apache-2.0

/*
 * Every user-visible string these components can render.
 *
 * doc 06 §6.3: "English-first; all strings externalized from components so
 * translation is possible." A component below imports from here and holds no
 * literal copy of its own, so a translator changes this file and nothing else.
 * RM-041 (#49) owns the shell's string catalogue and the eventual i18n
 * mechanism; this is the shared-component half of the same rule, shaped so it
 * can be folded into that catalogue without touching a component.
 *
 * doc 06 §6.1 governs the wording and is not negotiable:
 *   - Factual, unvarnished, specific. Say what was checked and what happened.
 *   - Errors state what failed and what the reader can do.
 *   - Banned: "successfully", "seamless", "trusted by", exclamation marks.
 * doc 06 §5.4: sentence case everywhere; labels carry no terminal punctuation,
 * helper text does.
 */

export const strings = {
  identifier: {
    /* What kind of atom this is (doc 06 P4). Spoken before the value, so a
     * screen-reader user knows whether they are hearing an identity or a
     * commit before hearing 40 characters of hex. */
    kind: {
      spiffe: "SPIFFE ID",
      sha: "Commit SHA",
      run: "Run ID",
      rekor: "Rekor entry index",
      generic: "Identifier",
    },
    copy: "Copy",
    copied: "Copied",
    /* P2: never claim a copy that did not happen. */
    copyFailed: "Couldn't copy — select the value and copy it by hand.",
    open: "Open",
  },

  status: {
    active: {
      label: "Active",
      /* Read by assistive technology and shown on hover: the badge word alone
       * does not distinguish two facts a reader must not confuse. */
      meaning: "Registered, credential current",
    },
    retired: {
      label: "Retired",
      meaning: "Retired deliberately; identity removed",
    },
    expired: {
      label: "Expired",
      meaning: "Credential expired before retirement; the agent died unretired",
    },
  },

  staleness: {
    prefix: "Data as of",
    ago: (duration: string) => `(${duration} ago)`,
    reason: "The ledger read path is degraded, so this view may be behind.",
  },

  heartbeat: {
    within: (segment: number, ago: string) =>
      `Ledger segment ${segment} anchored ${ago} ago`,
    beyond: (segment: number, ago: string, over: string, bound: string) =>
      `Ledger segment ${segment} anchored ${ago} ago — ${over} beyond the ${bound} anchoring-lag bound`,
    /* The same sentences, split where the component interleaves a <time>
     * element. The whole-sentence forms above are what assistive technology
     * receives; these are what the eye reads, and they exist because the
     * component previously rewrote the sentence inline to wrap the timestamp
     * — which put three English words back into a .tsx file and out of reach
     * of translation. FE-020's scanner did not see them: a template literal
     * WITH substitutions was not recognised as copy until RM-044 found the
     * hole. Splitting here keeps one source for the words. */
    withinPrefix: (segment: number) => `Ledger segment ${segment} anchored `,
    agoSuffix: (ago: string) => `${ago} ago`,
    beyondSuffix: (over: string, bound: string) =>
      ` — ${over} beyond the ${bound} anchoring-lag bound`,
    unknown: "No segment anchored yet",
    /* Named for assistive technology so the pulse is not an unlabelled string
     * of numbers in the header. */
    regionLabel: "Anchoring heartbeat",
  },

  loading: {
    busy: (what: string) => `Loading ${what}…`,
    /* Deliberately not "Loading X …" any more: the sentence a reader sees
     * after the bound must not be the sentence they saw before it. */
    timedOut: (what: string, waited: string) =>
      `Couldn't load ${what} — timed out after ${waited}`,
    retry: "Retry",
  },

  empty: {
    /* doc 06 §4.6 wants a per-view empty state; the wording is the view's, and
     * this is the fallback for a view that names none. */
    title: "Nothing to show",
    detail: "No records match this view.",
  },

  error: {
    title: "Can't reach the ledger",
    detail: "Showing nothing rather than guessing.",
    retry: "Retry",
    evidence: "See the evidence",
  },

  alert: {
    regionLabel: "System alert",
    evidence: "See the evidence",
  },
} as const;

export type Strings = typeof strings;
