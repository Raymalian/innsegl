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
    windowFrom: "Window opens",
    windowTo: "Window closes",
    runsInWindow: "Runs registered in this window",
    runsShown: "Runs drawn on this page",

    frequency: "Run frequency across this window",
    bucketFrom: "From",
    bucketTo: "To",
    bucketRuns: "Runs registered",

    reposTouched: "Repositories touched",

    aggregateVerification: "Aggregate verification status",
    verifyACommit: "Verify a commit",

    runs: "Runs of this agent type in this window",
    runId: "Run",
    identity: "Agent identity",
    task: "Task",
    status: "Status",
    commits: "Commits recorded by this run",
    registered: "Registered",
    repos: "Repositories this run touched",

    noRuns: "No runs in this window",
    wrongRoute: "This address does not name an agent type",
  },

  nouns: {
    runs: "the runs of this agent type",
  },

  sentences: {
    defaultWindow:
      "This address carries no usable window, so the last 30 days are shown.",

    bucketBounds:
      "Each row is counted by the server over the window's start and the instant in its second column, and the row above it is subtracted, so a run on a boundary is counted once and none falls between two rows.",

    reposComplete:
      "The server counted the same number of runs it served, so this is every repository this agent type touched in this window.",
    reposFromPage:
      "The server counted more runs in this window than it served, so this is the set named by the runs drawn below and may be short of it.",

    verificationNotLive:
      "Nothing on this page has been verified live, and nothing here is a verdict about any commit.",
    verificationNoAggregate:
      "Verification is three checks run against Fulcio and Rekor for one named commit. The query API answers one commit at a time and holds no aggregate, so there is no verified-and-failed tally for this agent type to report.",
    verificationDatabaseOnly:
      "A status assembled from the ledger's own records would be a verdict read out of a database rather than checked against the logs, and this system does not issue one; the overview's pass rate was left out for the same reason.",

    runsComplete:
      "The server counted the same number of runs it served, so every run registered in this window is below.",
    runsTruncated:
      "The server counted more runs in this window than it served, so this is the most recent page of them.",

    empty: "No run of this agent type was registered in this window.",
    wrongRoute:
      "An agent-type view is reached from data that names an agent type, and this address names none.",
  },
} as const;

export type AgentTypeStrings = typeof strings;
