// SPDX-License-Identifier: Apache-2.0

/*
 * Every user-visible string this view can render.
 *
 * doc 06 §6.3: "English-first; all strings externalized from components so
 * translation is possible." `app/nocopyincomponents.test.ts` (FE-020) parses
 * every .tsx under web/src and refuses JSX text and perceivable attributes, so
 * this is not a convention — a component that holds copy does not pass.
 *
 * doc 06 §6.1 governs the wording:
 *   - Factual, unvarnished, specific. Say what was checked and what happened.
 *   - Errors state what failed and what the reader can do.
 *   - Banned: "successfully", "seamless", "trusted by", exclamation marks.
 * doc 06 §5.4: sentence case; labels without terminal punctuation, helper text
 * with it.
 *
 * The view's NAME is not here. It comes from the shell's catalogue through
 * `useStrings()`, so the nav item and the page heading cannot drift apart.
 */

/** English-first digit grouping. Punctuation rather than copy, but it belongs
 * with the catalogue rather than in a component, for the same reason
 * `app/strings.ts` keeps its title separator here. */
export const GROUP_SEPARATOR = ",";

export const strings = {
  page: {
    summary:
      "What the ledger holds, and how far behind the public record is.",
  },

  loading: {
    /** Reads as "Loading the overview…" through the shared component. */
    what: "the overview",
  },

  metrics: {
    regionLabel: "System metrics",
    howCounted: "How this is counted",
    activeAgents: {
      label: "Active agents",
      description: "Working in the last 15 minutes.",
      meaning:
        "Runs whose newest recorded fact is not a retirement and not a credential withdrawal, and that recorded something in the last 15 minutes. A session closed without its end signal stays registered until the silence backstop retires it; until then it is counted idle.",
      idle: (idle: string, after: string) =>
        `${idle} idle: registered, nothing recorded for ${after} or more.`,
      breakdown: (lapsed: string, abandoned: string) =>
        `${lapsed} lapsed and ${abandoned} abandoned, counted apart from this number.`,
      horizon: (horizon: string) =>
        `A withdrawn run is counted abandoned once a ${horizon} restore horizon has passed.`,
      noHorizon:
        "No restore horizon is set, so a withdrawn run stays restorable until it is retired.",
      horizonUnknown:
        "The query API did not report the horizon these were counted with.",
    },
    runsToday: {
      label: "Runs today",
      description: "Started since midnight UTC.",
      meaning: (since: string) => `Runs registered since ${since}.`,
      unknown: "Not counted",
      unknownDescription: "The runs list did not answer.",
      unknownMeaning:
        "The runs index did not answer, so this shows no number rather than a guess.",
    },
    commits: {
      label: "Commits attributed",
      description: "Commits the ledger holds.",
      meaning:
        "Commits the ledger holds a commit_recorded event for. A record, not a verification.",
    },
    openAlerts: {
      label: "Open alerts",
      description: "Not yet resolved.",
      meaning:
        "Alerts raised by the ledger that nobody has resolved. Each one is a finding to look at, not a verdict on every commit.",
      link: "See the alerts",
    },
  },

  passRate: {
    label: "Verification pass rate",

    notMeasured: "Not measured",
    notMeasuredMeaning:
      "No live check has run over these commits, so no rate is shown.",
    cachedMeaning:
      "The rate in hand was retained from an earlier check rather than measured now, so it is not shown as a current rate.",
    checkedRatio: (checked: string, total: string) =>
      `${checked} of ${total} commits checked live`,
    verifiedRatio: (verified: string, checked: string) =>
      `${verified} of ${checked} commits verified live`,
    breakdown: (failed: string, unavailable: string) =>
      `${failed} failed, ${unavailable} could not be checked.`,
    measuredAt: (ago: string) => `Measured ${ago} ago.`,
    verifyLink: "Verify a commit",
  },

  heartbeat: {
    /* The header chip: a few words, and the whole sentence behind it. */
    chip: {
      reading: "Checking anchoring",
      unreadable: "Anchoring unknown",
      nothingSealed: "Nothing anchored yet",
      anchored: (ago: string) => `Anchored ${ago} ago`,
      behind: (lag: string) => `Anchoring ${lag} behind`,
      pending: (ago: string) => `Sealed ${ago} ago, not anchored`,
    },
    sentenceAnchored: (segment: number, ago: string) =>
      `Ledger segment ${segment} anchored ${ago} ago`,
    sentenceSealed: (segment: number, ago: string) =>
      `Ledger segment ${segment} sealed ${ago} ago, not yet anchored in Rekor`,
    sentenceBeyond: (over: string, bound: string) =>
      ` — ${over} beyond the ${bound} anchoring-lag bound`,
    sealedAt: (when: string) => `. Sealed ${when}.`,
    /** The state doc 02 §3 creates and the shared component has no words for:
     * sealed, with the anchoring members still to arrive on a superseding
     * event. */
    sealedPrefix: (segment: number) => `Ledger segment ${segment} sealed `,
    /* The eye's half of the sealed sentence, split where the component
     * interleaves a <time>. Same reason as components/common's heartbeat
     * split: a template literal with substitutions inside JSX is copy, and it
     * escaped FE-020's scanner until the scanner was widened. */
    agoSuffix: (ago: string) => `${ago} ago`,
    sealedSuffix: ", not yet anchored in Rekor",
    beyondBound: (over: string, bound: string) =>
      ` — ${over} beyond the ${bound} anchoring-lag bound`,
    unreadable:
      "Couldn't read the anchoring heartbeat — the query API didn't answer, so how far behind the public record is is unknown.",
    /** Before the first answer arrives. Neither calm nor an alarm: nothing has
     * been read yet, and saying "couldn't read" while a read is in flight
     * would be as wrong as saying the log is current. */
    reading: "Reading the anchoring heartbeat…",
    detailHeading: "Anchoring",
    segmentRange: (first: number, last: number) =>
      `Chain positions ${first} to ${last}`,
    segmentLabel: "Segment",
    rekorLabel: "Rekor entry index",
    pendingRekor: "No Rekor entry yet",
  },

  error: {
    withReason: (reason: string) =>
      `Showing nothing rather than guessing. The read failed with: ${reason}`,
  },

  recentRuns: {
    heading: "Recent runs",
    /* The qualification on the heading. doc 06 §6.2: a window, always — a list
     * that does not say which ten it is showing is §8 anti-pattern 10's
     * "cumulative counts with no window" in a smaller frame. */
    order: "newest first",
    /* The table's accessible name. Exact, never rounded (doc 06 §6.2). */
    caption: (count: number) =>
      count === 1
        ? "The 1 most recent run, newest first."
        : `The ${count} most recent runs, newest first.`,
    /* doc 06 §5.4: sentence case, and a label carries no terminal punctuation.
     * They are SET uppercase by the column-header style; the catalogue holds
     * the words a translator reads, not their casing. */
    columns: {
      status: "Status",
      run: "Run",
      repo: "Repository",
      agent: "Agent",
      task: "Task",
      activeFor: "Active for",
      commits: "Commits",
    },
    emptyTitle: "No runs yet",
    emptyDetail: "The ledger holds no run_registered event.",
    commits: (count: number) =>
      count === 1 ? "1 commit" : `${count} commits`,
    registered: "Registered",
    noRepos: "Signed nothing",
    all: "All runs",
  },
} as const;

export type OverviewStrings = typeof strings;
