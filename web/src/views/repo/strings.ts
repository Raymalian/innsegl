// SPDX-License-Identifier: Apache-2.0

/*
 * Every user-visible string the repo view can render.
 *
 * doc 06 §6.3: "English-first; all strings externalized from components so
 * translation is possible." FE-020 parses every .tsx under web/src and refuses
 * a literal, so this file is not a convention — it is the only place a word
 * can be.
 *
 * doc 06 §6.1 governs the wording and §5.4 the shape:
 *   - factual, unvarnished, specific; no "successfully", no "seamless", no
 *     "trusted by", no exclamation marks;
 *   - sentence case; labels without terminal punctuation, helper text with it.
 * FE-048 holds this file and its twin in views/agent-type to both.
 *
 * THREE GROUPS, not two. `labels` and `sentences` are §5.4's own division.
 * `nouns` is a third because LoadingState renders "Loading {what}…": what goes
 * into that slot is a fragment another sentence swallows, and holding it to
 * either rule would put a capital in the middle of a sentence or a full stop
 * in the middle of a clause.
 *
 * ── THE COVERAGE COPY IS THE POINT OF THIS ISSUE ───────────────────────────
 *
 * doc 06 §3.4 asks for attribution coverage — "% of commits in window with
 * verified agent identity". Neither half of that fraction is available:
 *
 *   the DENOMINATOR is the number of commits in the repository in the window,
 *   which is a fact about the repository host and not one this ledger holds;
 *
 *   the NUMERATOR would have to be VERIFIED rather than recorded, and
 *   internal/api serves verification one commit at a time, live, by design
 *   (IP §6.11, doc 06 P2).
 *
 * The only fraction this data can produce is recorded-over-recorded, which is
 * 100% forever. That is doc 06 §8's tenth anti-pattern exactly. So the view
 * prints the refusal below instead of a number, and says what would make the
 * metric real.
 */

export const strings = {
  labels: {
    repository: "Repository",
    openOnHost: "Open on the repository host",

    /** The accessible name of the block that carries the window and its counts. */
    summary: "This window at a glance",
    windowFrom: "Window opens",
    windowTo: "Window closes",
    runsInWindow: "Runs registered in this window",
    runsShown: "Runs drawn on this page",

    coverage: "Attribution coverage",

    groupedByIdentity: "Attributed runs, grouped by agent identity",
    identity: "Agent identity",
    runsForIdentity: "Runs by this identity in this window",
    runsTable: "Runs, newest first",
    runId: "Run",
    agentType: "Agent type",
    task: "Task",
    status: "Status",
    commits: "Commits recorded by this run",
    registered: "Registered",

    noRuns: "No runs in this window",
    wrongRoute: "This address does not name a repository",
  },

  nouns: {
    runs: "the runs for this repository",
  },

  sentences: {
    defaultWindow:
      "This address carries no usable window, so the last 30 days are shown.",

    setIsComplete:
      "The server counted the same number of runs it served, so every run in this window is grouped below and the counts beside each identity are the whole of it.",
    setIsTruncated:
      "The server counted more runs in this window than it served, so what is grouped below is the most recent page of them and no count is taken over it.",

    coverageDenominator:
      "Coverage is the share of a repository's commits that carry a verified agent identity. This ledger records only the commits it was used to make, so it holds no count of the commits in this window that it did not make, and that count is a fact about the repository host rather than about the ledger.",
    coverageNumerator:
      "The numerator would have to be verified rather than recorded. A verified commit is one where three checks ran live against Fulcio and Rekor; the query API answers one commit at a time and exposes no commit listing for a repository, so a figure assembled here would be a count of stored rows wearing a verification result's clothes.",
    coverageRefusal:
      "No percentage is shown, because the only one this data can produce is the share of recorded commits that were recorded, which is all of them and always will be.",
    coverageNeeded:
      "Two things would make this measurable: a commit total for this repository and window taken from the repository host, and a coverage query that runs the three checks live on the server.",

    commitsSpanRepos:
      "This run touched more than one repository, so this count is not this repository's alone.",

    noHostLink:
      "The recorded value is not in the host/org/name form, so no link to a repository host can be derived from it.",

    empty: "No run registered in this window touched this repository.",
    wrongRoute:
      "A repository view is reached from data that names a repository, and this address names none.",
  },
} as const;

export type RepoStrings = typeof strings;
