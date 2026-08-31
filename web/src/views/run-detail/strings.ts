// SPDX-License-Identifier: Apache-2.0

/*
 * Every user-visible string the run-detail view can render.
 *
 * doc 06 §6.3: "English-first; all strings externalized from components so
 * translation is possible." Same shape as the two catalogues that came before
 * it — `components/common/strings.ts` and `components/verification/strings.ts`
 * — kept in this directory because this directory is separately owned. Folding
 * the three together is a mechanical edit for whoever wants one file.
 *
 * doc 06 §6.1 governs the wording:
 *   - "Factual, unvarnished, specific. Say what was checked and what happened."
 *   - "Errors state what failed and what the user can do."
 *   - Banned: "successfully", "seamless", "trusted by", exclamation marks.
 * doc 06 §5.4: sentence case everywhere; labels carry no terminal punctuation,
 * helper text does.
 *
 * ── ONE FUNCTION IS DOING SOMETHING LOAD-BEARING ───────────────────────────
 *
 * `event.source` takes the enum value as an argument instead of holding four
 * finished sentences. doc 06 §3.3 asks for the literal label `source:
 * reconciler`, and `reconciler` is a protected string from doc 02 §2 — so the
 * enum value has to arrive from the ledger and pass through untouched, while
 * the word around it stays translatable. A catalogue holding "source:
 * reconciler" as one string would let a translator change a protected value
 * by accident, and a component holding it would fail FE-020.
 */

export const strings = {
  header: {
    /* doc 06 §3.3: "Header: full SPIFFE ID (mono, copyable), agent type, task
     * ref, registered/retired timestamps, credential expiry history." */
    identity: "Agent identity",
    agentType: "Agent type",
    taskRef: "Task",
    repos: "Repositories",
    commits: "Commits recorded",
    registered: "Registered",
    retired: "Retired",
    expired: "Expired",
    stillRunning: "Not ended",
    runId: "Run",
    chainPosition: "Latest chain position",
    credentials: "Credential expiry history",
    credentialIssued: "Issued",
    credentialExpiry: "Expires",
    credentialAudience: "Audience",
    noCredentials: "No credential was issued to this run.",
    /* P2: the reason an end timestamp is absent is a fact, not a blank. */
    noEnd: "This run has no retirement or expiry event in the ledger.",
  },

  timeline: {
    heading: "Timeline",
    /* doc 06 §3.3: "Each timeline node shows its chain position." */
    chainPosition: (position: number) => `Chain position ${position}`,
    eventId: "Event",
    eventHash: "Event hash",
    prevEventHash: "Previous event hash",
    empty: "This run has no events in the ledger.",
    emptyDetail: "A run with no events is a run that was never registered.",
  },

  event: {
    /* The eleven types of doc 02 §3, in that document's order. Labels, so no
     * terminal punctuation (doc 06 §5.4). */
    runRegistered: "Run registered",
    credentialIssued: "Credential issued",
    toolCall: "Tool call",
    commitIntent: "Commit intent",
    commitRecorded: "Commit recorded",
    commitIntentExpired: "Commit intent expired",
    runRetired: "Run retired",
    runExpired: "Run expired",
    unattributedSignatureDetected: "Unattributed signature detected",
    ledgerDriftDetected: "Ledger drift detected",
    segmentSealed: "Segment sealed",
    /* An event type this build does not know. It is shown, not dropped. */
    unrecognised: "Event type this dashboard does not recognise",

    /** doc 06 §3.3's literal label. The enum value passes through untouched. */
    source: (source: string) => `source: ${source}`,
    /* Who each writer is, for a reader who has not read doc 02. */
    writer: {
      mcp: "Appended by the MCP server as the agent worked.",
      reconciler:
        "Appended by the reconciler, which reads Rekor and repairs what the ledger missed.",
      reaper: "Appended by the reaper, which ends runs whose credential ran out.",
      system: "Appended by the system itself, outside any agent's work.",
      unrecognised: "Appended by a writer this dashboard does not recognise.",
    },
    /* The sentence doc 06 §3.3 asks for: repaired history visible AS repaired.
     * Only for an event type whose ordinary writer is the agent (doc 02 §3's
     * "Emitted by" column) — the reconciler's own alerts are not repairs. */
    repaired: "Repaired history",
    repairedDetail:
      "The agent never recorded this event. The reconciler reconstructed it afterwards from the transparency log, so the ledger lost this fact and got it back.",
  },

  chain: {
    /* The link between this event and the one before it in the GLOBAL chain.
     * Three states, and the third is why this exists: a run's events are not
     * adjacent in the ledger, so most links cannot be checked from this
     * response at all, and silence about that would read as "checked, fine". */
    linked: "Chain link holds",
    linkedDetail: "This event names the hash of the event immediately before it.",
    broken: "Chain link broken",
    brokenDetail:
      "This event follows the one above it in the ledger and does not name its hash. Either the ledger was altered or the response was.",
    unchecked: "Chain link not checkable here",
    uncheckedDetail:
      "Events from other runs sit between these two, so this response does not contain the event this one names. Verify it against the full chain.",
    first: "First event in this response",
    firstDetail: "There is no earlier event here to link it to.",
  },

  detail: {
    /* Type-specific members, labelled. doc 02 §3's own field names in words. */
    agentType: "Agent type",
    taskRef: "Task",
    audience: "Audience",
    credentialExpiry: "Credential expiry",
    toolName: "Tool",
    repo: "Repository",
    treeHash: "Tree hash",
    commitSha: "Commit",
    rekorLogIndex: "Rekor log index",
    rekorEntryUuid: "Rekor entry",
    intentEventId: "Intent event",
    certificateIdentity: "Certificate identity",
    subjectEventId: "Subject event",
    reason: "Reason",
    payloadDigest: "Payload digest",
    supersedes: "Supersedes",
  },

  toolCall: {
    /* doc 06 §3.3: "tool-call events (count, expandable to digests)". IP E4 and
     * doc 02 §3 keep the body out of the ledger entirely, so the digest is
     * genuinely all there is — and saying so is better than a reader assuming
     * the dashboard is withholding it. */
    expand: "Digests",
    noDigest: "This tool call recorded no payload digest.",
    bodyNotStored:
      "The ledger stores no tool-call body, only its digest. Compare the digest against the body you hold.",
    count: (n: number) => (n === 1 ? `${n} tool call` : `${n} tool calls`),
  },

  canonical: {
    heading: "Canonical members",
    /* P5, honestly bounded: these are the decoded members, not the bytes. */
    detail:
      "These are the event's canonical members after JSON decoding. Re-deriving the event hash needs the exact response bytes, which this rendering does not preserve.",
    undecodable: "This event's canonical members could not be decoded.",
    undecodableDetail:
      "The ledger returned something this dashboard could not read as JSON. Read it from the API response directly.",
    absent: "This response carried no canonical members for this event.",
  },

  alert: {
    /* doc 06 §4.5 and P3. Page-level, red, persistent while the events stand. */
    drift: "Ledger drift detected in this run",
    driftDetail:
      "The ledger claims something the transparency log does not confirm. The events below carry the reason.",
    unattributed: "A signature in this trust domain has no recorded intent",
    unattributedDetail:
      "Something signed with an identity from this trust domain without a commit intent in the ledger. The events below carry the certificate identity.",
    chainBroken: "A chain link in this run does not hold",
    chainBrokenDetail:
      "An event does not name the hash of the event before it. Either the ledger was altered or the response was.",
    evidence: "Go to the event",
  },

  severity: {
    /* doc 06 §8 anti-pattern 2: a node whose event is a failure must not
     * render as merely informational. These are the words that say so, and
     * they are never the only cue — see styles.ts and Severity in
     * TimelineNode.tsx. */
    alert: "Integrity alert",
    alertMeaning: "The reconciler found something the external record does not support.",
    degraded: "Ended without completing",
    degradedMeaning: "What this event describes was started and never finished.",
  },

  time: {
    /* doc 06 §6.2: "Absolute timestamps with timezone on hover for every
     * relative time." The absolute value reaches a pointer, a keyboard and a
     * screen reader by three separate routes — see RelativeTime.tsx. */
    ago: (duration: string) => `${duration} ago`,
    ahead: (duration: string) => `in ${duration}`,
    show: "Show the absolute time",
    /* Spoken before the value so the announcement is not a bare number. */
    announce: (label: string, absolute: string, relative: string) =>
      `${label}: ${absolute}, ${relative}`,
    unparseable: "Timestamp the dashboard could not read",
  },

  verification: {
    heading: "Verification",
    /* doc 06 §4.1's panel is behind a disclosure, because a run with twenty
     * commits would otherwise open twenty live checks nobody asked for. */
    expand: "Verify this commit",
    loading: "the verification of this commit",
    /* The freshness bound. doc 06 §8 anti-pattern 1 is "a 'verified' state
     * rendered from cache while the live check errored"; a result held on
     * screen long enough stops being a live check whether or not anything
     * errored, and this view says so rather than letting the green age. */
    stale:
      "This check ran more than a minute ago, so it is reported as a retained result rather than a live one.",
    refresh: "Run the checks again",
    unavailable: "the proof for this commit",
    noCommit: "This event records no commit SHA, so there is nothing to verify.",
  },

  view: {
    heading: "Run detail",
    loading: "the run",
    notFound: "No run with this identifier",
    notFoundDetail: "The ledger holds no run with this identifier. Check the link.",
    failed: "Can't reach the ledger",
    failedDetail: "Showing nothing rather than guessing.",
    retry: "Retry",
  },
} as const;

export type RunDetailStrings = typeof strings;
