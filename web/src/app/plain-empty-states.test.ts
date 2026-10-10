// SPDX-License-Identifier: Apache-2.0

/*
 * FE-148 (E28): an empty or not-found state says what the reader can see in
 * plain words. No event type (run_registered, commit_recorded), and no claim
 * that the ledger holds nothing: with reads scoped to organisations, the
 * ledger may hold runs this reader cannot see.
 */

import { describe, expect, it } from "vitest";

import { strings as overview } from "../views/overview/strings";
import { strings as alerts } from "../views/alerts/strings";
import { strings as repos } from "../views/repos/strings";
import { strings as repo } from "../views/repo/strings";
import { strings as agentType } from "../views/agent-type/strings";
import { strings as runDetail } from "../views/run-detail/strings";
import { strings as runPage } from "../views/run-page/strings";
import { strings as auth } from "../views/auth/strings";

/** Every string under a key that names an empty, missing or not-found state. */
function emptyStates(tree: unknown, path = ""): Array<[string, string]> {
  if (typeof tree === "string") {
    return /empty|notFound|noRuns|noRepos|missing|nothing/i.test(path) ? [[path, tree]] : [];
  }
  if (typeof tree !== "object" || tree === null) return [];
  return Object.entries(tree).flatMap(([k, v]) => emptyStates(v, path === "" ? k : `${path}.${k}`));
}

const catalogues = { overview, alerts, repos, repo, agentType, runDetail, runPage, auth };

describe("FE-148 empty states in plain words", () => {
  for (const [name, catalogue] of Object.entries(catalogues)) {
    it(`${name}: no event type and no "the ledger holds no"`, () => {
      for (const [path, text] of emptyStates(catalogue)) {
        expect(text, `${name}.${path}`).not.toMatch(/\b[a-z]+_[a-z]+(_[a-z]+)*\b/);
        expect(text, `${name}.${path}`).not.toMatch(/ledger holds no/i);
      }
    });
  }

  it("the overview's commit count is explained without an event type", () => {
    expect(overview.metrics.commits.meaning).not.toMatch(/commit_recorded/);
  });
});
