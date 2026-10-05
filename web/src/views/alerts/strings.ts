// SPDX-License-Identifier: Apache-2.0

/*
 * Every string the notification menu, the alerts page and the alert detail
 * view render — ADR-0054, RM-330, doc 06 §6.1, §6.3, §5.4.
 *
 * Labels carry no terminal punctuation; keys ending in `Detail` or `Status`
 * and the `reasons` are sentences and end in a full stop. FE-138 checks both.
 *
 * Resolving: ADR-0044's 2026-10-03 amendment lets a signed-in operator
 * resolve an alert here, confirmed with a fresh passkey. The words say what
 * that records and never offer to hide, dismiss or clear an alert: a
 * resolution is a statement in a person's name, appended beside the alert,
 * and the alert itself is never changed.
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
    /** A grouped item's count: several open alerts of one kind. */
    groupCount: (count: number) => `${count} open`,
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
      noTelemetryWitness: "A recorded tool call has no result in the harness's own telemetry.",
      commitNotSigned: "A commit was made with no signature recorded for it.",
      unknownDetail: "A ledger claim has no external proof.",
      unanchored: (first: string, last: string) =>
        `Positions ${first}–${last} are sealed but could not be anchored in the transparency log.`,
    },
    unattributedDetail: (logIndex: number) =>
      `Rekor log index ${logIndex} holds a signature under one of this ledger's identities, with no record of it here.`,
  },

  /** What each cause means and what to do about it (RM-330). One paragraph
   * each, in words an operator who did not build this can act on. */
  explain: {
    whatHeading: "What this means",
    todoHeading: "What to do",
    noTelemetryWitness: {
      title: "Tool calls with no telemetry result",
      whatDetail:
        "The gateway recorded a tool call, but the harness's own telemetry never reported a result for it. Either the call did not run as recorded, or the harness stopped exporting telemetry.",
      todoDetail:
        "Check whether the harness was exporting telemetry while this run was active. If it was stopped or restarted, that explains the alert and you can resolve every alert like it in this run at once. If telemetry was running, read the run's tool calls before you resolve.",
    },
    commitNotSigned: {
      title: "Commits with no signature",
      whatDetail:
        "A commit was made in a watched repository with no signature recorded for it. Something committed outside an agent's signed path.",
      todoDetail:
        "Find the commit and who made it. If a person committed by hand, resolve it and say so. If an agent made it, find out why its commit was not signed before you resolve.",
    },
    rekorMismatch: {
      title: "Commits that do not match the transparency log",
      whatDetail:
        "The ledger records a commit signature whose transparency log entry is missing or does not match it. The ledger and the public record disagree about this commit.",
      todoDetail:
        "Treat this as possible tampering until you know otherwise. Check the commit on the verify page and compare the log entry by hand. Resolve only once you know why they differ, for example a transparency log that was reset.",
    },
    unanchored: {
      title: "Segments not yet anchored",
      whatDetail:
        "A sealed stretch of the ledger has not been written to the transparency log yet. Until it is, nobody outside can check that part of the chain.",
      todoDetail:
        "Usually nothing: the alert clears on its own once the segment is anchored. If it stays open, check that the transparency log is reachable from the core host.",
    },
    unattributed: {
      title: "Signatures with no record in this ledger",
      whatDetail:
        "The transparency log holds a signature made under one of this ledger's identities, and the ledger has no record of it. An identity may have signed something outside innsegl.",
      todoDetail:
        "Look up the log entry and what it signed. If nobody can account for it, treat that identity as compromised. Resolve only once you know who made the signature.",
    },
    other: {
      title: "Other disagreements",
      whatDetail:
        "The reconciler found that the ledger and an outside record disagree. The reason it gave is shown in full below.",
      todoDetail:
        "Read the reason and the ledger claim it names, and resolve once you know the cause.",
    },
  },

  /** The alerts page (RM-330). */
  page: {
    heading: "Alerts",
    introDetail:
      "Every alert the reconciler and the sealer have raised, grouped by what raised it. A resolved alert stays listed with who resolved it and why.",
    loadingWhat: "the alerts",
    failedWith: (reason: string) =>
      `Showing nothing rather than guessing. The read failed with: ${reason}`,
    filtersLabel: "Which alerts",
    kindLabel: "Show",
    kinds: { open: "Open", resolved: "Resolved", all: "All" },
    runLabel: "Run",
    allRuns: "All runs",
    emptyOpenDetail: "No open alerts.",
    emptyResolvedDetail: "No resolved alerts.",
    emptyAllDetail: "No alerts have been raised.",
    emptyRunDetail: "No alerts of this kind name this run.",
    incompleteDetail: (count: number) =>
      `Only the newest ${count} alerts could be read, so older ones are not listed.`,
    openCount: (count: number) => `${count} open`,
    resolvedCount: (count: number) => `${count} resolved`,
    noRunLabel: "No run",
    rowOpenStatus: "Open.",
    rowResolvedStatus: (by: string) => `Resolved by ${by}.`,
    resolveGroupLabel: (count: number) =>
      count === 1 ? "Resolve this alert" : `Resolve these ${count} alerts`,
    groupListLabel: (title: string) => `${title}: alerts`,
  },

  /** Resolving one alert, or every open alert in a group (RM-330). */
  resolve: {
    heading: "Resolve this alert",
    groupHeading: (count: number) => `Resolve ${count} open alerts`,
    reasonLabel: "Reason",
    reasonDetail:
      "Say why, in words someone can check later. The resolution records your account name, the time and this reason; the alert itself is never changed.",
    confirmLabel: "Confirm with passkey",
    workingLabel: "Waiting for your passkey",
    cancelLabel: "Cancel",
    needReasonDetail: "Give a reason before confirming.",
    unsupportedDetail:
      "This browser has no passkey support, so it cannot confirm a resolution.",
    cancelledDetail: "The passkey prompt was closed, so nothing was resolved.",
    failedWith: (reason: string) => `Nothing was resolved: ${reason}`,
    doneDetail: (count: number) =>
      count === 1
        ? "Resolved. The alert now records your name, the time and your reason."
        : `Resolved ${count} alerts. Each records your name, the time and your reason.`,
  },

  detail: {
    loadingWhat: "the alert",
    notFoundTitle: "No such alert",
    notFoundDetail: "The alerts feed holds no alert with this event ID.",
    failedWith: (reason: string) =>
      `Showing nothing rather than guessing. The read failed with: ${reason}`,
    factsLabel: "What this alert records",
    statusLabel: "Status",
    openStatus: "Open. Nobody has resolved it yet.",
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
    evidenceHeading: "Evidence",
    recordToggle: "Show the full record",
    viewRun: "View the run this claim concerns",
    runAlerts: "Every alert in this run",
  },
} as const;

export type AlertStrings = typeof strings;
