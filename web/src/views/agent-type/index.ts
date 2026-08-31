// SPDX-License-Identifier: Apache-2.0

/*
 * The agent-type view — doc 06 §3.5, issue #55.
 *
 * `AgentTypeView` matches the shell's `ComponentType<ViewProps>`, so wiring it
 * is one entry in the registry web/src/app/main.tsx passes to App. That file
 * is the app shell's (RM-041) and is not this issue's to edit; the
 * registration is reported as work for whoever owns the wave that lights the
 * views up.
 */

export { AgentTypeView } from "./AgentTypeView";
export type { AgentTypeViewProps } from "./AgentTypeView";

export { FREQUENCY_BUCKETS, bucketCounts, bucketsOf } from "./frequency";
export type { Bucket } from "./frequency";

export { PAGE_LIMIT, fetchRuns, runsPath } from "./query";
export type { LoadRuns, RunPage, RunSummary, RunsQuery } from "./query";

export {
  DEFAULT_WINDOW_DAYS,
  isComplete,
  reposNamedBy,
  resolveWindow,
} from "./window";
export type { StatedWindow } from "./window";

export { strings } from "./strings";
export type { AgentTypeStrings } from "./strings";
