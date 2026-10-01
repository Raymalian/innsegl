// SPDX-License-Identifier: Apache-2.0

/*
 * Every user-visible string the run page can render — doc 06 §6.3.
 *
 * Copy is drawn from the approved mockup (Main.dc.html, States.dc.html) word
 * for word wherever the mockup states one, so a diff against the artboard's
 * text is a diff against this file and nowhere else.
 */

export const strings = {
  /* FE-020 forbids a bare separator glyph as JSX text — "/" and "·" carry no
   * words for a translator to change, but the scanner (src/app/
   * nocopyincomponents.test.ts) refuses any non-whitespace JSX text node
   * outright, the same way components/verification/identity.ts's own
   * `separator` field exists so IdentityComparison.tsx never writes one
   * literally. */
  punctuation: {
    slash: "/",
    middot: " · ",
    dash: " — ",
  },

  header: {
    heading: (agentType: string) => `${agentType} agent`,
  },

  facts: {
    copySpiffeId: (value: string) => `Copy SPIFFE ID ${value}`,
    identity: "Identity",
    startedBy: "Started by",
    workedIn: "Worked in",
    did: "Did",
    started: "Started",
    committed: "Committed",
    repository: "Repository",
    workedInValue: (repo: string) => `${repo} · own worktree`,
    startedByAt: (step: number, when: string) => `at step ${step} · ${when} UTC`,
  },

  files: {
    statusLabel: {
      A: "Added",
      M: "Modified",
      D: "Deleted",
      R: "Reverted",
      W: "Written",
    },
  },

  commits: {
    heading: "Commits",
    none: "None.",
    /** The session aside's own sentence when at least one commit is signed
     * by a one-commit identity the session started rather than by the
     * session itself (#443). */
    oneCommitIdentities: (n: number) =>
      `${n === 1 ? "1 commit" : `${n} commits`}, each signed under its own one-commit identity. They are commits, not agents, and are listed here rather than in the agents table.`,
    allCommits: (n: number) => `All ${n} commits`,
  },

  timeline: {
    showMore: (next: number, left: number) => `Show ${next} more steps (${left} left)`,
    showFullOutput: "Show full output",
    loadingFullOutput: "Loading the full output…",
    noSteps: "No steps were recorded for this run: it ran before the gateway recorded its tool calls.",
    toggleLabel: "Diff layout",
    unified: "Unified",
    sideBySide: "Side by side",
    done: "done",
    exitCode: (code: number) => `exit ${code}`,
    failedExitCode: (code: number) => `failed · exit ${code}`,
    failedNoExitCode: "failed",
    /* The mockup's exact sentence is shown only when the record itself says
     * the step was refused (`outcome.kind === "refused"`) — this view cannot
     * truthfully claim a sandbox refusal for an ordinary "error" the contract
     * did not categorise that way (doc 06 P1: evidence over assertion). Every
     * other non-ok outcome gets the second, general sentence alone, which is
     * true of any failure. */
    refusedBySandbox: "Refused by the harness sandbox.",
    failedIsRecord: "A step that failed is part of the record, shown as it happened.",
    witnessGateway: "Gateway",
    witnessSnapshot: "Workspace snapshot",
    witnessTelemetry: "Harness telemetry",
    witnessGatewayPresent: "relayed, body stored",
    witnessGatewayMissing: "not relayed",
    witnessSnapshotChanged: "tree changed as the diff shows",
    witnessSnapshotUnchanged: "tree unchanged",
    witnessSnapshotNone: "no snapshot taken",
    witnessSnapshotInactive: "no snapshots for this run",
    witnessTelemetryMatched: "matches the gateway's record",
    witnessTelemetryMissing: "no event for this tool call",
    witnessTelemetryPending: "not yet reported",
    witnessTelemetryInactive: "telemetry inactive for this run",
    returned: "returned",
    newFile: "new file",
    modifiedFile: "modified",
    deletedFile: "deleted",
    revertedFile: "reverted",
    treeChange: (before: string, after: string) => `tree ${before} → ${after}`,
    diffLayoutLabel: "diff",
  },

  witnessDisagreement: {
    bannerTitle: (step: number, reason: string) => `Witnesses disagree on step ${step}: ${reason}`,
    reasonTelemetryMissing:
      "the gateway relayed a tool call the harness's telemetry never reported",
    reasonGatewayMissing:
      "the harness's telemetry recorded a tool call the gateway never relayed",
    reasonSnapshot: "the workspace snapshot disagrees with what the gateway and telemetry recorded",
    reasonGeneric: "the three witnesses do not agree on what happened",
    detailTelemetryMissing: (toolUseId: string) =>
      `Tool call ${toolUseId} is on this run's record; no telemetry event for it arrived within 5 minutes, while telemetry for the steps around it did. Something other than this agent's harness may have used its session.`,
    detailGeneric: (toolUseId: string) =>
      `Tool call ${toolUseId} is on this run's record, and at least one of the three witnesses disagrees with the other two.`,
  },

  commitCard: {
    heading: "Commit",
    copyCommitSha: (sha: string) => `Copy commit SHA ${sha}`,
    check1: "1 · Fulcio certificate chain",
    check2: "2 · Rekor inclusion",
    check3: "3 · Trailer matches certificate identity",
    valid: "Valid",
    provenAtIndexPrefix: "Proven at index ",
    sameIdentity: "Same identity",
    checkFailed: "Failed",
    checkUnavailable: "Unavailable",
    signedBy: "Signed by this run in the core; recorded as intent → signature → record",
    verifyYourself: "Verify it yourself",
    loading: "the verification of this commit",
    unavailable: "the proof for this commit",
  },

  diff: {
    binary: "binary file",
  },

  loading: {
    record: "the run",
    diff: "this step's diff",
  },

  empty: {
    title: "No record for this run",
    detail: "The ledger holds no record with this identifier. Check the link.",
  },

  error: {
    title: "Can't reach the ledger",
    detail: "Showing nothing rather than guessing.",
    retry: "Retry",
  },

  /* #443 (RM-278): the agent page — one agent at a time, by task, with its
   * lineage. Copy drawn word for word from Agent.dc.html and Session.dc.html
   * wherever the mockup states one. */
  agentPage: {
    newFile: "new file",
    writtenFile: "written",
    moreLines: (n: number) => `· ${n} more ${n === 1 ? "line" : "lines"}`,
    addedLine: "added line",
    addedMarker: "+",
    kickerSubagent: (agentType: string) => `SUBAGENT · ${agentType}`,
    kickerSession: "SESSION · the agent you talk to",
    sessionHeading: (repo: string) => `Session on ${repo}`,

    lineageAria: "Where this agent came from",
    thisAgent: "this agent",
    thisSession: "this session",
    /** "Where it sits"'s own highlighted row names the session capitalised,
     * as its own row of a short list rather than as a nav pill's label
     * (Session.dc.html's own distinction between the two). */
    thisSessionAside: "This session",
    startedByYou: "started by you · nothing above it",
    spawnedAtStep: (step: number) => (step > 0 ? `spawned at step ${step}` : "not matched to a step"),
    sessionLabel: "Session",

    askedTo: "Asked to",
    askedCaption: "the instructions its parent's spawn carried",
    showAllLines: (n: number) => `Show all ${n} lines`,
    reportedBack: "Reported back",
    reportedCaption: (step: number) => `its final message to the session · step ${step}`,

    whatItRanSubagent: (n: number) => `What it ran · ${n === 1 ? "1 step" : `${n.toLocaleString("en-US")} steps`}`,
    whatItRanSession: (n: number) =>
      `What it ran · ${n === 1 ? "1 step" : `${n.toLocaleString("en-US")} steps`}, newest first`,
    commandsToggle: "Commands",
    withOutputToggle: "With output",
    filterAll: "All",
    filterSpawned: "Agents started",
    filterCommits: "Commits",
    filterFailed: "Failed",

    colN: "#",
    colTool: "Tool",
    colCommand: "Command or file",
    colResult: "Result",
    colTime: "Time",

    groupRange: (a: number, b: number, n: number, atA: string, atB: string) =>
      `Steps ${a}–${b} · ${n === 1 ? "1 more command" : `${n} more commands`}, ${atA}–${atB}`,
    show: "show",

    reportTool: "Report",
    reportHandedBack: "Handed its report back to the session · shown above",
    started: "Started",

    agentsStartedHeading: "Agents it started",
    agentsStartedSub: "newest first · each opens its own page",
    findAnAgent: "Find an agent by task",
    colTask: "Task",
    colKind: "Kind",
    colSteps: "Steps",
    colCommits: "Commits",
    colEnded: "Ended",
    showingOf: (shown: number, total: number) => `Showing ${shown} of ${total}`,
    showMoreAgents: "Show more agents",

    whereItSits: "Where it sits",
    otherAgents: (n: number) => (n === 1 ? "1 other agent" : `${n} other agents`),
    startedNoSubagents: "Started no subagents of its own.",
    linkedByAgentId: (step: number) => `Matched to step ${step} by the agent id its spawn returned and its own steps carry.`,
    linkedByBrief: (step: number) => `Matched to step ${step} by the exact instructions its spawn carried.`,
    linkedByNone: "Not matched to a step of its parent.",

    filesItWrote: "Files it wrote",
    stepN: (n: number) => `step ${n}`,

    witnessesHeading: "Witnesses",
    hookRecordedWitnesses:
      "Recorded by the hook before the gateway existed: no snapshots or telemetry for this agent. Every step's body is stored and its digest verifies.",
    witnessesAgreeAll: (steps: number) => `Gateway, snapshots and telemetry agree on all ${steps} steps`,
    witnessesDisagreeSummary: (disagree: number, steps: number) =>
      `Gateway, snapshots and telemetry disagree on ${disagree} of ${steps} steps`,
    witnessesNoSteps: "No steps were recorded for this run",
    witnessesPartlyChecked: (agree: number, steps: number, unchecked: number) =>
      `Witnesses agree on ${agree} of ${steps} steps; ${unchecked} could not be checked`,
  },
} as const;

export type RunPageStrings = typeof strings;
