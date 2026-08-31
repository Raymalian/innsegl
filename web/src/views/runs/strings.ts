// SPDX-License-Identifier: Apache-2.0

/*
 * Every user-visible string the runs view can render.
 *
 * doc 06 §6.3: "English-first; all strings externalized from components so
 * translation is possible." src/app's FE-020 scanner parses every `.tsx` under
 * `web/src` and refuses JSX text and perceivable attributes, so this file is
 * not a convention a reviewer has to enforce — a component that holds copy
 * does not pass.
 *
 * The `labels` / `sentences` split is the same one src/app/strings.ts makes,
 * and it is what lets a machine check doc 06 §5.4's two halves: "Sentence case
 * everywhere. Labels without terminal punctuation; helper text with it."
 * FE-056 walks both with the app catalogue's own `flattenStrings`.
 *
 * doc 06 §6.1 governs the wording: factual, unvarnished, specific; errors say
 * what failed and what the reader can do; banned vocabulary is "successfully",
 * "seamless", "trusted by", and exclamation marks.
 *
 * What is NOT here: the three run statuses, the copy affordance, the loading
 * and dependency-error wording. Those belong to the shared components' own
 * catalogue and this view reads them from there rather than restating them —
 * two catalogues that disagree about what "Expired" means is a worse failure
 * than one catalogue that is long.
 */

export const strings = {
  labels: {
    view: {
      /** The <h1> of the view (doc 06 §3.2). */
      heading: "Runs",
    },

    /* doc 06 §3.2's five columns, in its order. */
    columns: {
      runId: "Run ID",
      task: "Task",
      repo: "Repositories",
      commits: "Commits and verification",
      status: "Status",
    },

    filters: {
      region: "Filters",
      repo: "Repository",
      agentType: "Agent type",
      status: "Status",
      anyStatus: "Any status",
      from: "Registered from",
      to: "Registered to",
      search: "Search IDs and tasks",
      apply: "Apply filters",
      clear: "Clear filters",
    },

    page: {
      region: "Pages",
      next: "Next page",
      first: "First page",
    },

    table: {
      noRepos: "No repository recorded",
    },

    verification: {
      /** doc 06 P2: what this row does NOT claim. Not a verdict — a statement
       * that no verdict was sought here. */
      notChecked: "No live check ran for this row",
      openRun: "Open the run",
    },

    empty: {
      /** doc 06 §4.6 gives this view's empty state in as many words. A title,
       * so it carries no terminal punctuation (§5.4). */
      title: "No runs match these filters",
    },
  },

  sentences: {
    empty: {
      detail: "Change a filter, or clear them all.",
    },

    filters: {
      searchHint:
        "Matches run IDs, SPIFFE IDs and task refs. The ledger does the matching; nothing is filtered in this browser.",
    },

    page: {
      keyset:
        "Pages run forward from a keyset cursor. Use the browser's back button to return to an earlier page.",
    },

    verification: {
      notChecked:
        "A verification is three live checks against Fulcio and Rekor per commit, and this table runs none. Open the run to see them.",
    },
  },

  /* A word that is never a string of its own: LoadingState puts it after
   * "Loading", so it is lower case and carries no punctuation, and it is kept
   * out of `labels` so that FE-056's sentence-case rule — which is about
   * strings a reader sees whole — is not weakened to accommodate it. */
  fragments: {
    what: "runs",
  },

  /* Copy that takes an argument. Kept apart from the two groups above because
   * FE-056 walks those as data and has to call these instead. */
  formats: {
    /** The table's accessible name, with the exact counts doc 06 §6.2 asks for. */
    caption: (shown: number, total: number): string =>
      `Runs — showing ${shown} of ${total}`,
    showing: (shown: number, total: number): string =>
      `Showing ${shown} of ${total} runs`,
    /** Exact, never rounded (doc 06 §6.2). */
    commits: (count: number): string =>
      count === 1 ? `${count} commit` : `${count} commits`,
    /** doc 06 §7's scale posture, said out loud on the page. */
    bounded: (limit: number): string =>
      `At most ${limit} runs are requested at a time.`,
  },
} as const;

export type RunsStrings = typeof strings;
