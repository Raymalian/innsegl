// SPDX-License-Identifier: Apache-2.0

import type { ViewRegistry } from "./App";
import { AgentTypeView } from "../views/agent-type";
import { OverviewView } from "../views/overview";
import { PublicVerifyView } from "../views/public-verify";
import { RepoView } from "../views/repo";
import { RunDetailView } from "../views/run-detail";
import { RunsView } from "../views/runs";

// Re-exported so main.tsx has one import for everything the shell needs, and
// so this module is the single place that knows which view supplies the
// header's anchoring pulse (doc 06 §3.1 puts it on every view).
export { OverviewHeartbeat } from "../views/overview";

// The registry the shell renders from. RM-041 built App to take it rather than
// import the views itself, so that wave 4's five agents could each own a
// directory without touching src/app/ — which is why this line is the
// supervisor's and not any one issue's.
//
// It is also the moment the views become reachable at all. Every one of them
// was built, tested and committed against a shell that rendered a placeholder
// for its route; until this registry existed the bundle did not contain them
// and no browser could reach one. `satisfies` rather than a bare annotation so
// a key that is not a ViewName is a compile error, and a view added to
// routes.ts without a component here stays visibly absent instead of silently
// rendering nothing.
export const views = {
  // The overview is the one view that takes no route: it renders the same page
  // at /, and its props are all injection seams for tests. Wrapped rather than
  // widening ViewRegistry, because the registry's contract — every view is a
  // function of the route — is what keeps the shell's navigation honest.
  overview: () => <OverviewView />,
  runs: RunsView,
  run: RunDetailView,
  repo: RepoView,
  agentType: AgentTypeView,
  verify: PublicVerifyView,
} satisfies ViewRegistry;
