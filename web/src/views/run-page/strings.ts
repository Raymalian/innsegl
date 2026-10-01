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
    runsCrumb: "Runs",
    heading: (agentType: string) => `${agentType} agent`,
    witnessesComplete: "Every step has a stored body; digests verify",
    witnessesIncomplete: (stored: number, verified: number, steps: number) =>
      `${stored} of ${steps} steps have a stored body; ${verified} digests verify`,
  },

  facts: {
    identity: "Identity",
    copySpiffeId: (value: string) => `Copy SPIFFE ID ${value}`,
    repoBranch: "Repository · branch",
    activity: "Activity",
    activitySummary: (steps: number, commits: number, subagents: number, files: number) =>
      [
        steps === 1 ? "1 step" : `${steps} steps`,
        commits === 1 ? "1 commit" : `${commits} commits`,
        subagents === 1 ? "1 subagent" : `${subagents} subagents`,
        files === 1 ? "1 file" : `${files} files`,
      ].join(" · "),
    witnesses: "Witnesses",
    witnessesAgreeAll: (steps: number) =>
      `Gateway, snapshots and telemetry agree on all ${steps} steps`,
    witnessesDisagreeSummary: (disagree: number, steps: number) =>
      `Gateway, snapshots and telemetry disagree on ${disagree} of ${steps} steps`,
    witnessesNoSteps: "No steps were recorded for this run",
    witnessesPartlyChecked: (agree: number, steps: number, unchecked: number) =>
      `Witnesses agree on ${agree} of ${steps} steps; ${unchecked} could not be checked`,
  },

  tree: {
    heading: "Agent tree",
    linkedBy: (step: number) =>
      `Linked by the exact brief its parent's spawn carried (step ${step})`,
  },

  files: {
    heading: "Files changed",
    scopeWholeRun: "whole run",
    writtenBySubagent: (path: string) => `${path} was written by the subagent`,
    legend: {
      added: "A added",
      modified: "M modified",
      deleted: "D deleted",
      reverted: "R reverted",
    },
    statusLabel: {
      A: "Added",
      M: "Modified",
      D: "Deleted",
      R: "Reverted",
    },
    neverCommitted: (writtenStep: number, deletedStep: number) =>
      `written in step ${writtenStep}, deleted in step ${deletedStep} · never committed`,
    neverCommittedNote:
      "Every change the snapshots saw is shown, including ones the agent undid; the file tree marks them so a reviewer sees what was tried, not only what landed.",
    neverCommittedHeading: "A change that never reached a commit",
  },

  commits: {
    heading: "Commits",
    madeByStep: (step: number) => `made by step ${step}`,
    landedOn: (branch: string) => `landed on ${branch}`,
    notLanded: "on no branch",
    notLandedRefLock: "on no branch: lost git's ref lock to a parallel commit",
    landingUnknown: "landing not checked",
    notLandedHeading: "Signed, not landed",
    notLandedCaption:
      "The signature holds, so it stays verified; landing is read from the repository and shown beside it, never mixed into the verdict.",
    rewritten: "rewritten onto another commit",
  },

  brief: {
    heading: "Brief",
    caption: (digest: string) => `the first message this agent received · keyed digest ${digest}`,
  },

  reply: {
    heading: (digest: string) => `Reply · keyed digest ${digest}`,
  },

  timeline: {
    heading: "Timeline",
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
    witnessesAgreeAll: (total: number) => `${total} of ${total} witnesses agree`,
    witnessesPartial: (agree: number, total: number) => `${agree} of ${total} witnesses`,
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
    spawned: "Spawned",
    /* The fallback word when the tree response names no agent type for the
     * spawned run — still said plainly rather than left blank (P2). */
    subagentFallback: "subagent",
    spawnedLink: (agentType: string, runId: string) => `${agentType} · ${runId}`,
    spawnedBrief: (summary: string) => ` — "${summary}"`,
    returned: "returned",
    subagentCommitNote: (sha: string) => `The subagent made commit ${sha} on its own run; open it for its steps and diffs.`,
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
} as const;

export type RunPageStrings = typeof strings;
