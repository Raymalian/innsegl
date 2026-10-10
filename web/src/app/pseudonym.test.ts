// SPDX-License-Identifier: Apache-2.0

/*
 * FE-145 (ADR-0080 decision 4): a repository or branch name the query API
 * could not resolve is a pseudonym whose name was erased. It is shown as
 * such, with a short form a person can match across pages, and never blank.
 */

import { describe, expect, it } from "vitest";

import { displayName, isPseudonym } from "./pseudonym";
import { shortRepo } from "../views/run-page/derive";

const erased = "pn:rk-0a1b2c3d:3f9a1c2b7e6d5c4b3a291807f6e5d4c3";

describe("FE-145 repository names", () => {
  it("shows a resolved or literal name as it is", () => {
    expect(displayName("github.com/acme/api")).toBe("github.com/acme/api");
    expect(displayName("feature/quiet")).toBe("feature/quiet");
    expect(isPseudonym("github.com/acme/api")).toBe(false);
  });

  it("shows an erased name as erased, with a short form, never blank", () => {
    expect(isPseudonym(erased)).toBe(true);
    expect(displayName(erased)).toBe("Name erased · 3f9a1c2b");
  });

  it("the run page's short repository says the same", () => {
    expect(shortRepo(erased)).toBe("Name erased · 3f9a1c2b");
    expect(shortRepo("github.com/acme/api")).toBe("acme/api");
  });
});
