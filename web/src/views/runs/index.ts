// SPDX-License-Identifier: Apache-2.0

/*
 * doc 06 §3.2's runs view — issue #53 (RM-045).
 *
 * The shell's view registry takes a `ComponentType<ViewProps>`; `RunsView` is
 * one, and it reads the route from the address bar when it is rendered without
 * one. Wiring it into src/app/main.tsx belongs to whoever owns that file.
 */

export { RunsView } from "./RunsView";
export type { RunsViewProps } from "./RunsView";

export { RunsTable } from "./RunsTable";
export type { RunsTableProps } from "./RunsTable";

export { RunsFilterForm, dateInputOf, endOfDay, startOfDay } from "./RunsFilterForm";
export type { RunsFilterFormProps } from "./RunsFilterForm";

export { RunsPager } from "./RunsPager";
export type { RunsPagerProps } from "./RunsPager";

export {
  DEFAULT_PAGE_SIZE,
  MAX_PAGE_SIZE,
  RUNS_ENDPOINT,
  RUNS_PATH,
  boundedFilters,
  fetchRuns,
  runsLinkPath,
  runsRequestPath,
} from "./api";
export type { RunPage, RunSummary, RunsSource } from "./api";

export type { CommitProof, RunProofSource, StatedLiveness } from "./proofs";

export { strings } from "./strings";
export type { RunsStrings } from "./strings";
