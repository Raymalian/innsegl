// SPDX-License-Identifier: Apache-2.0

/*
 * RPG-CONTRACT — the provided fixtures satisfy the contract's own types.
 *
 * `record.json` and `diff-step1.json` are #395-397's contract, read by both
 * this view and `internal/api`'s own fixture test; this is the dashboard
 * side's half of "the two sides cannot drift" — a runtime shape check
 * against `types.ts`, since a `JSON.parse()` import cannot be statically
 * checked (see validate.ts and load.ts for why).
 */

import { describe, expect, it } from "vitest";

import { loadFixture } from "./fixtures/load";
import { isRunRecord, isStepDiff } from "./validate";

describe("RPG-CONTRACT the provided fixtures satisfy types.ts", () => {
  it("record.json is a RunRecord", () => {
    const record = loadFixture("record.json");
    expect(isRunRecord(record)).toBe(true);
  });

  it("diff-step1.json is a StepDiff", () => {
    const diff = loadFixture("diff-step1.json");
    expect(isStepDiff(diff)).toBe(true);
  });

  it("states-record.json (this issue's own fixture) is a RunRecord", () => {
    const record = loadFixture("states-record.json");
    expect(isRunRecord(record)).toBe(true);
  });

  it("states-diff.json (this issue's own fixture) is a StepDiff", () => {
    const diff = loadFixture("states-diff.json");
    expect(isStepDiff(diff)).toBe(true);
  });

  it("refuses a value that is not a RunRecord at all", () => {
    expect(isRunRecord({ nope: true })).toBe(false);
    expect(isRunRecord(null)).toBe(false);
    expect(isRunRecord([])).toBe(false);
  });

  it("refuses a RunRecord with one field of the wrong shape", () => {
    const record = loadFixture("record.json") as Record<string, unknown>;
    const run = record["run"] as Record<string, unknown>;
    expect(isRunRecord({ ...record, run: { ...run, status: "on-fire" } })).toBe(false);
  });
});
