// SPDX-License-Identifier: Apache-2.0

// FE-090 — every view the route table names has a component behind it.
//
// ViewRegistry is Partial by design: RM-041 shipped the shell before any view
// existed, and a route with no component renders an honest placeholder rather
// than a blank page. That was right during wave 4 and is wrong after it. All
// six views exist now, and a Partial type will not notice when a seventh route
// is added and nobody registers it — the route would simply render the
// placeholder, in production, looking like a view that had not loaded.
//
// This is the check that noticed the whole of wave 4 was unreachable: five
// views were built, tested and committed against a shell that rendered a
// placeholder for every one of their routes, and the built bundle did not
// contain them. `vite build` went from 201.74 kB to 310.75 kB when the
// registry was wired, which is the difference this test exists to keep.

import { describe, expect, it } from "vitest";

import { VIEWS } from "./routes";
import { views } from "./views";

describe("FE-090 the view registry is complete", () => {
  it("has a component for every view in the route table", () => {
    const missing = VIEWS.filter((name) => views[name] === undefined);
    expect(missing).toEqual([]);
  });

  it("registers nothing the route table does not name", () => {
    const unknown = Object.keys(views).filter(
      (name) => !(VIEWS as readonly string[]).includes(name),
    );
    expect(unknown).toEqual([]);
  });

  it("is scanning a real registry, so a passing run is not a vacuous one", () => {
    expect(VIEWS.length).toBeGreaterThanOrEqual(6);
    expect(Object.keys(views)).toHaveLength(VIEWS.length);
  });
});
