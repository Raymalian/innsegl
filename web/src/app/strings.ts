// SPDX-License-Identifier: Apache-2.0

// Every user-visible string in the dashboard shell.
//
// doc 06 §6.3: "English-first; all strings externalized from components so
// translation is possible. No text baked into images." That is the acceptance
// criterion for this issue, and it is worth being precise about what it buys.
// A translator needs one file. But the larger dividend is that doc 06 §6.1's
// voice rules and §5.4's casing rule stop being things a reviewer has to hold
// in their head:
//
//   §6.1 — "Banned vocabulary: 'successfully,' 'seamless,' 'trusted by,'
//   exclamation marks in system copy."
//   §5.4 — "Sentence case everywhere. Labels without terminal punctuation;
//   helper text with it."
//
// With every string in one place those are checkable on every commit, and
// FE-019 checks them. That is why the catalogue is split into `labels` and
// `sentences` rather than grouped only by feature: the split is what makes
// §5.4's two halves distinguishable to a machine.
//
// FE-020 checks the other direction — that no component holds a user-visible
// literal — by parsing the shell's TSX and refusing JSX text and visible
// attributes. A rule enforced only by review is the thing this project keeps
// finding broken.

export const en = {
  labels: {
    app: {
      /** doc 06's preamble: "Product name in UI chrome: Innsegl (wordmark
       * only; no logo requirement for Phase 4)." Not translatable copy. */
      name: "Innsegl",
      skipToContent: "Skip to main content",
    },
    nav: {
      /** The accessible name of the navigation landmark (doc 06 §3). */
      region: "Views",
    },
    header: {
      /** The header slot doc 06 §3.1 reserves for the anchoring heartbeat.
       * The heartbeat itself belongs to RM-044; the shell owns the landmark. */
      anchoring: "Anchoring",
    },
    views: {
      overview: "Overview",
      runs: "Runs",
      run: "Run detail",
      repo: "Repositories",
      agentType: "Agent types",
      verify: "Verify a commit",
    },
    theme: {
      region: "Theme",
      system: "Follow the system",
      light: "Light",
      dark: "Dark",
    },
    notFound: {
      heading: "Page not found",
    },
  },
  sentences: {
    placeholder: {
      unbuilt: "This view is not built yet.",
      /** doc 06 P2: a placeholder must never be mistakable for evidence. */
      notEvidence: "Nothing on this page is data from the ledger.",
    },
    notFound: {
      body: "No address matches this link. Check it, or start from the overview.",
    },
  },
} as const;

export type Strings = typeof en;

/** The separator between a view name and the product name in the document
 * title. Punctuation rather than copy, so it is not in the catalogue and not
 * subject to FE-019's casing rules — but it is still out of the components. */
const TITLE_SEPARATOR = " · ";

/**
 * The document title for a view. Shareability (doc 06 §7) is mostly a property
 * of the URL, but a browser tab and a bookmark are named by this.
 */
export function documentTitle(viewLabel: string, strings: Strings = en): string {
  return `${viewLabel}${TITLE_SEPARATOR}${strings.labels.app.name}`;
}

export type StringTree = { readonly [key: string]: string | StringTree };

/**
 * Every leaf of a catalogue as a `[dotted.key, value]` pair. FE-019 walks this
 * rather than a hand-written list, so a string added tomorrow is checked
 * tomorrow without anybody remembering to add it to the gate.
 */
export function flattenStrings(
  tree: StringTree,
  prefix = "",
): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  for (const [key, value] of Object.entries(tree)) {
    const path = prefix === "" ? key : `${prefix}.${key}`;
    if (typeof value === "string") {
      out.push([path, value]);
    } else {
      out.push(...flattenStrings(value, path));
    }
  }
  return out;
}
