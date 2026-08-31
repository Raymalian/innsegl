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
    activeAgents: {
      label: "Active agents",
      meaning: "Runs registered and neither retired nor expired.",
    },
    runsToday: {
      label: "Runs today",
      meaning: (since: string) => `Runs registered since ${since}.`,
      unknown: "Not counted",
      unknownMeaning:
        "The runs index did not answer, so this shows no number rather than a guess.",
    },
    commits: {
      label: "Commits attributed",
      meaning:
        "Commits the ledger holds a commit_recorded event for. A record, not a verification.",
    },
  },

  passRate: {
    label: "Verification pass rate",

    /* The state this build is always in. The wording is deliberate: it says
     * what is missing, why the obvious substitute is refused, and what the
     * reader can do instead (doc 06 §6.1). */
    notMeasured: "Not measured",
    notMeasuredMeaning:
      "No live check has run over these commits. A rate counted from the ledger would assert a verification result that nothing checked, so none is shown.",
    cachedMeaning:
      "The rate in hand was retained from an earlier check rather than measured now, so it is not shown as a current rate.",
    checkedRatio: (checked: string, total: string) =>
      `${checked} of ${total} commits checked live`,
    verifiedRatio: (verified: string, checked: string) =>
      `${verified} of ${checked} commits verified live`,
    /* doc 06 §8 anti-pattern 2: failed and unavailable never collapse, and a
     * single rate is exactly the collapse — so the two are always spelled
     * out beside it. */
    breakdown: (failed: string, unavailable: string) =>
      `${failed} failed, ${unavailable} could not be checked.`,
    measuredAt: (ago: string) => `Measured ${ago} ago.`,
    verifyLink: "Verify a commit",
  },

  heartbeat: {
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

  alerts: {
    title: (count: number) =>
      count === 1 ? "1 open integrity alert" : `${count} open integrity alerts`,
    detail:
      "The reconciler recorded a signature it could not attribute, or a ledger claim with no external proof. This build has no view that lists them: the query API serves their count and not the events.",
    evidenceLabel: "See the response this count came from",
  },

  error: {
    withReason: (reason: string) =>
      `Showing nothing rather than guessing. The read failed with: ${reason}`,
  },

  recentRuns: {
    heading: "Recent runs",
    emptyTitle: "No runs yet",
    emptyDetail: "The ledger holds no run_registered event.",
    commits: (count: number) =>
      count === 1 ? "1 commit" : `${count} commits`,
    registered: "Registered",
    all: "All runs",
  },
} as const;

export type OverviewStrings = typeof strings;
