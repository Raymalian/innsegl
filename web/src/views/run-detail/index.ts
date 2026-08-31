// SPDX-License-Identifier: Apache-2.0

/*
 * doc 06 §3.3's run detail, for the shell's view registry (`ViewRegistry` in
 * app/App.tsx keys a component by the route table's own view name — this one
 * belongs under `run`).
 *
 * Wiring it into that registry is `app/`'s edit and not this issue's: RM-046
 * owns `web/src/views/run-detail/` and nothing else, and `app/main.tsx` is
 * where the six views are assembled once they all exist. Reported.
 *
 * The pieces are exported alongside the view because doc 06 §3.4 and §3.5's
 * views show runs too, and a repo view that wanted this timeline should
 * compose it rather than write a second one.
 */

export { RunDetailView, RunNotFound, fetchRun } from "./RunDetailView";
export type { FetchRun, RunDetailViewProps } from "./RunDetailView";

export { RunHeader } from "./RunHeader";
export type { RunHeaderProps } from "./RunHeader";

export { Timeline } from "./Timeline";
export type { TimelineProps } from "./Timeline";

export { TimelineNode } from "./TimelineNode";
export type { TimelineNodeProps } from "./TimelineNode";

export { RelativeTime, Instant } from "./RelativeTime";
export type { RelativeTimeProps } from "./RelativeTime";

export {
  CommitVerification,
  DEFAULT_FRESHNESS_MS,
  fetchProof,
} from "./CommitVerification";
export type { CommitVerificationProps, VerifyCommit } from "./CommitVerification";

export {
  canonicalOf,
  chainLinkAt,
  commitSHAOf,
  conditionsOf,
  credentialHistory,
  isRepairedHistory,
  memberString,
  nodeAnchorId,
  parseInstant,
  runEnd,
  severityOf,
  toolCallCount,
} from "./events";
export type {
  Canonical,
  ChainLink,
  Condition,
  ConditionKind,
  CredentialIssue,
  RunEnd,
  Severity,
} from "./events";

export { strings } from "./strings";
export type { RunDetailStrings } from "./strings";

export {
  EMITTED_BY,
  EVENT_TYPES,
  EVENT_TYPE_IDS,
  MEMBERS,
  SOURCES,
  SOURCE_IDS,
  eventTypeIdOf,
  sourceIdOf,
} from "./types";
export type {
  EventTypeId,
  RunDetail,
  RunSummary,
  SourceId,
  TimelineEvent,
} from "./types";
