// SPDX-License-Identifier: Apache-2.0

/*
 * doc 06 §3.3's run page (E19, #395-397), for the shell's view registry.
 *
 * `RunRoute` is what `app/views.tsx` actually wires in: it reads the route's
 * `chain` bit and renders either this page or the run-detail view the run
 * page superseded at `/runs/:runId`, which stays reachable at
 * `/runs/:runId/chain` (issue's own instruction; no new link needed).
 */

import { RunDetailView } from "../run-detail";
import type { Route } from "../../app/routes";
import { RunPage } from "./RunPage";

export function RunRoute({ route }: { readonly route: Route }) {
  if (route.view === "run" && route.chain === true) {
    return <RunDetailView route={route} />;
  }
  return <RunPage route={route} />;
}

export { RunPage } from "./RunPage";
export type { RunPageProps } from "./RunPage";

export { fetchRunRecord, fetchStepDiff, fetchProof, RunRecordNotFound } from "./api";
export type { FetchRunRecord, FetchStepDiff, FetchProof } from "./api";

export { strings } from "./strings";
export type { RunPageStrings } from "./strings";

export { isRunRecord, isStepDiff } from "./validate";
