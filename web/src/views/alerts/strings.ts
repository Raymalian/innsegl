// SPDX-License-Identifier: Apache-2.0

/*
 * Every string the notification menu and the alert detail view render —
 * ADR-0054, doc 06 §6.1, §6.3, §5.4.
 *
 * Labels carry no terminal punctuation; keys ending in `Detail` or `Status`
 * and the `reasons` are sentences and end in a full stop. FE-138 checks both,
 * and checks that nothing here offers to change an alert: the dashboard is
 * read-only (ADR-0044), and an operator resolves an alert from the command
 * line.
 */

const plural = (count: number, one: string, many: string) =>
  count === 1 ? `1 ${one}` : `${count} ${many}`;

export const strings = {
  menu: {
    /** The bell's accessible name. The count is in it, so a screen reader
     * hears the alarm without opening the menu (P3). */
    buttonLabel: (count: number) =>
      count === 0 ? "Alerts, none open" : `Alerts, ${plural(count, "open", "open")}`,
    /** Neither the list nor the count answered: unknown, never zero (P2). */
    buttonUnknownLabel: "Alerts, count unknown",
    /** Before the first answer arrives. */
    buttonReadingLabel: "Alerts, reading",
    /** The badge's visible text when the count is unknown. */
    unknownBadge: "?",
    /** The menu's accessible name. */
    menuLabel: "Open alerts, newest first",
    heading: "Open alerts",
    order: "newest first",
    emptyDetail: "No open alerts.",
    readingDetail: "Reading the alerts.",
    unreadDetail: "The alerts could not be read, so how many are open is unknown.",
    countOnlyDetail: (count: number) =>
      `${plural(count, "alert is", "alerts are")} open. The list could not be read, so only the count is shown.`,
    moreDetail: (count: number) =>
      `${plural(count, "more open alert is", "more open alerts are")} not listed here.`,
    /** The polite live region (doc 06 §6.4). */
    announceNew: (count: number) =>
      count === 1 ? "1 new open alert." : `${count} new open alerts.`,
    announceOpen: (count: number) =>
      count === 1 ? "1 open alert." : `${count} open alerts.`,
    /** "3 min ago", by the item's time. */
    ago: (elapsed: string) => `${elapsed} ago`,
  },

  alert: {
    driftTitle: "Ledger drift detected",
    unattributedTitle: "Unattributed signature detected",
    /** One line for a list. The reconciler's five known reasons, in words a
     * reader can act on; anything else falls back to the reason itself with
     * its long hex runs shortened. The full reason is on the detail view. */
    reasons: {
      noLogEntry: "A recorded commit names a transparency log entry that does not exist.",
      unusableUuid: "A recorded commit names a transparency log entry that cannot exist.",
      otherArtifact: "A recorded commit's log entry attests a different commit.",
      otherIdentity: "A recorded commit's log entry was signed under a different identity.",
      otherLogIndex: "A recorded commit's log entry sits at a different log index.",
      unknownDetail: "A ledger claim has no external proof.",
    },
    unattributedDetail: (logIndex: number) =>
      `Rekor log index ${logIndex} holds a signature under one of this ledger's identities, with no record of it here.`,
  },

  detail: {
    loadingWhat: "the alert",
    notFoundTitle: "No such alert",
    notFoundDetail: "The alerts feed holds no alert with this event ID.",
    failedWith: (reason: string) =>
      `Showing nothing rather than guessing. The read failed with: ${reason}`,
    factsLabel: "What this alert records",
    statusLabel: "Status",
    openStatus:
      "Open. This dashboard is read-only; an operator resolves an alert from the command line.",
    resolvedStatus: (by: string, at: string) => `Resolved by ${by} at ${at}.`,
    resolvedReason: (reason: string) => `Reason given: ${reason}`,
    recordedLabel: "Recorded",
    runLabel: "Run",
    noRun: "None. This alert concerns the ledger, not one run.",
    claimLabel: "Ledger claim",
    reasonLabel: "Reason",
    identityLabel: "Certificate identity",
    rekorEntryLabel: "Rekor entry",
    rekorIndexLabel: "Rekor log index",
    positionLabel: "Chain position",
    eventLabel: "Alert event",
    /* How an operator resolves an open alert. A command to copy, never a
     * button: the dashboard writes nothing (ADR-0044). The angle-bracket
     * placeholders are left for the operator; only the event ID is filled. */
    resolveHeading: "How to resolve",
    resolveDetail:
      "Resolving records that a person reviewed this alert; the alert itself is never changed.",
    autoClearDetail:
      "A drift alert about a segment clears on its own once that segment is anchored.",
    resolveCommand: (eventId: string) =>
      `innsegl resolve-alert -event-id=${eventId} -resolved-by=<your name> -reason="<why it is resolved>"`,
    evidenceHeading: "Evidence",
    rawRecord: "See this alert's raw record",
    viewRun: "View the run this claim concerns",
  },
} as const;

export type AlertStrings = typeof strings;
