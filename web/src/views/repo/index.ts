// SPDX-License-Identifier: Apache-2.0

/*
 * The repository view — doc 06 §3.4, issue #55.
 *
 * `RepoView` matches the shell's `ComponentType<ViewProps>`, so wiring it is
 * one entry in the registry web/src/app/main.tsx passes to App. That file is
 * the app shell's (RM-041) and is not this issue's to edit; the registration
 * is reported as work for whoever owns the wave that lights the views up.
 */

export { RepoView } from "./RepoView";
export type { RepoViewProps } from "./RepoView";

export { PAGE_LIMIT, fetchRuns, runsPath } from "./query";
export type { LoadRuns, RunPage, RunSummary, RunsQuery } from "./query";

export {
  DEFAULT_WINDOW_DAYS,
  groupByIdentity,
  hostUrlOf,
  isComplete,
  resolveWindow,
} from "./repo";
export type { IdentityGroup, StatedWindow } from "./repo";

export { strings } from "./strings";
export type { RepoStrings } from "./strings";
