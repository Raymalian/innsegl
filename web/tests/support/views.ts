// SPDX-License-Identifier: Apache-2.0

// doc 06 §3's six views, addressed the way a reader actually reaches them —
// through src/app/routes.ts's own path grammar — and the document title each
// one produces (src/app/strings.ts's `documentTitle`), which is the cheapest
// real signal that the view which rendered is the one the address named and
// not doc 06 §4.6's placeholder or an unmocked-request error state.

import { AGENT_TYPE, COMMIT_SHA, REPO, RUN_ID } from "./api-fixtures";

export interface ViewCase {
  readonly name: string;
  readonly path: string;
  readonly title: string;
}

const TITLE_SUFFIX = " · Innsegl";

export const VIEWS: readonly ViewCase[] = [
  { name: "overview", path: "/", title: `Overview${TITLE_SUFFIX}` },
  { name: "runs", path: "/runs", title: `Runs${TITLE_SUFFIX}` },
  { name: "run", path: `/runs/${RUN_ID}`, title: `Run detail${TITLE_SUFFIX}` },
  { name: "repo", path: `/repos/${REPO}`, title: `Repositories${TITLE_SUFFIX}` },
  {
    name: "agentType",
    path: `/agent-types/${AGENT_TYPE}`,
    title: `Agent types${TITLE_SUFFIX}`,
  },
  {
    name: "verify",
    path: `/verify?commit=${COMMIT_SHA}&repo=${REPO}`,
    title: `Verify a commit${TITLE_SUFFIX}`,
  },
];
