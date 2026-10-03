// SPDX-License-Identifier: Apache-2.0

/*
 * Every user-visible string the agent-type view can render.
 *
 * doc 06 §6.3 puts them here; FE-020 parses every .tsx under web/src and
 * refuses a literal, so this file is not a convention. doc 06 §6.1 governs the
 * wording and §5.4 the shape, and FE-048 holds both this file and its twin in
 * views/repo to them. Three groups rather than two, for the reason that file
 * gives: `nouns` are the fragments another sentence swallows.
 *
 * ── THE AGGREGATE VERIFICATION COPY IS THE POINT OF THIS ISSUE ─────────────
 *
 * doc 06 §3.5 asks for "aggregate verification status across time". There is
 * no honest one to render, and the reasons are structural rather than
 * temporary:
 *
 *   IP §6.11 and doc 06 P2 forbid a verdict read out of the database. A tally
 *   assembled from `commit_recorded` rows would be exactly that — it would
 *   report as "verified" every commit the ledger wrote down, which is all of
 *   them, with no check having run.
 *
 *   A live tally would have to run the three checks against Fulcio and Rekor
 *   for every commit in the window. internal/api verifies one named commit per
 *   request and exposes no commit listing at all, so there is nothing to
 *   iterate and nothing to aggregate.
 *
 * internal/api hit the same wall for the overview's pass rate and left the
 * metric out, saying so in Overview's own comment. This view does the same
 * thing one level up: it states that nothing here has been verified live, says
 * why a stored answer would not be a verification, and sends the reader to the
 * page that does check — one commit at a time, against the logs.
 *
 * That is not a smaller answer than a number. A green "98% verified" computed
 * from stored rows is the single most damaging thing this dashboard could
 * render, because every reader who acted on it would be acting on a database
 * query wearing a cryptographic result's clothes.
 */

export const strings = {
  labels: {
    agentType: "Agent type",

    /** The accessible name of the block that carries the window and its counts. */
    summary: "This window at a glance",
    windowFrom: "From",
    windowTo: "To",
    runsInWindow: "Runs",
    runsShown: "Runs shown",

    frequency: "Runs over time",
    bucketFrom: "From",
    bucketTo: "To",
    bucketRuns: "Runs",

    reposTouched: "Repositories touched",

    aggregateVerification: "Verification",
    verifyACommit: "Verify a commit",

    runs: "Runs",
    runId: "Run",
    identity: "Agent identity",
    task: "Task",
    status: "Status",
    commits: "Commits",
    registered: "Registered",
    repos: "Repositories",

    noRuns: "No runs in this window",
    wrongRoute: "This address does not name an agent type",
  },

  nouns: {
    runs: "the runs of this agent type",
  },

  sentences: {
    defaultWindow:
      "No dates in the address, so the last 30 days are shown.",

    bucketBounds:
      "Each row counts runs from the start of the window up to its end time, less the row above. No run is counted twice or missed.",

    reposComplete:
      "This is every repository this agent type touched in this window.",
    reposFromPage:
      "More runs matched than are shown, so this list may be short.",

    verificationNotLive:
      "Nothing on this page was checked live, and nothing here is a verdict about a commit.",
    verificationNoAggregate:
      "Verification is three live checks against Fulcio and Rekor for one commit. The server answers one commit at a time and keeps no tally, so there is none to show for this agent type.",
    verificationDatabaseOnly:
      "A tally built from the ledger alone would be a verdict read from a database, not checked against the logs. So none is shown.",

    runsComplete:
      "Every run registered in this window is below.",
    runsTruncated:
      "More runs matched than fit on this page. The newest are shown.",

    empty: "No run of this agent type was registered in this window.",
    wrongRoute:
      "An agent type page is opened from an agent type name, and this address has none.",
  },
} as const;

export type AgentTypeStrings = typeof strings;
