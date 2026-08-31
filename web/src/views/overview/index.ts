// SPDX-License-Identifier: Apache-2.0

/*
 * The overview view — doc 06 §3.1, issue #52.
 *
 * `OverviewView` goes in `App`'s view registry under "overview";
 * `OverviewHeartbeat` goes in its `heartbeat` prop, which is the slot RM-041
 * left for exactly this. Neither requires an edit to `web/src/app/`.
 */

export { Overview } from "./Overview";
export type { OverviewProps } from "./Overview";

export { OverviewHeartbeat, OverviewView } from "./OverviewView";
export type { OverviewViewProps } from "./OverviewView";

export {
  AnchoringEvidence,
  AnchoringPulse,
  DEFAULT_LAG_BOUND_MS,
} from "./AnchoringPulse";
export type { AnchoringPulseProps } from "./AnchoringPulse";

export { MetricCard } from "./MetricCard";
export type { MetricCardProps, MetricTone } from "./MetricCard";

export { PassRateCard } from "./PassRateCard";
export type { PassRateCardProps } from "./PassRateCard";

export { RecentRuns } from "./RecentRuns";
export type { RecentRunsProps } from "./RecentRuns";

export {
  DEFAULT_API_BASE,
  RECENT_RUNS_LIMIT,
  fetchOverview,
  fetchRecentRuns,
  fetchRunsToday,
  useOverview,
} from "./data";
export type { OverviewResource, UseOverviewOptions } from "./data";

export { formatCount, formatRate, startOfUtcDay } from "./format";

export { strings } from "./strings";
export type { OverviewStrings } from "./strings";

export type {
  AnchorHeartbeat,
  MeasuredLiveness,
  OverviewData,
  PassRate,
  RunPage,
  RunSummary,
  WindowedCount,
} from "./types";
