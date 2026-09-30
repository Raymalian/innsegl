// SPDX-License-Identifier: Apache-2.0

/*
 * Test fixtures for the run page's own tests (RPG-010..015). The two
 * contract fixtures (record.json, diff-step1.json — not this issue's to
 * edit) plus this issue's own states-record.json/states-diff.json, all
 * loaded and shape-checked through the same path `contract.test.ts` uses, so
 * a component test can never be exercising a shape the contract does not
 * actually produce.
 */

import { loadFixture } from "./fixtures/load";
import { isRunRecord, isStepDiff } from "./validate";
import type { RunRecord, StepDiff } from "./types";

function typed<T>(value: unknown, check: (v: unknown) => v is T, name: string): T {
  if (!check(value)) throw new Error(`fixtures: ${name} does not satisfy its contract type`);
  return value;
}

export const RUN_ID = "run-df219cf8c90bf55f74ca6870c034b5f9";
export const STATES_RUN_ID = "run-9c1f2e3a4b5c6d7e8f9a0b1c2d3e4f5a";

/** The instant `data_as_of` in record.json names, so a rendered "3 min ago"
 * in a test is deterministic. */
export const NOW = new Date("2026-09-30T14:34:07Z");
export const STATES_NOW = new Date("2026-09-30T15:15:41Z");

export function record(): RunRecord {
  return typed(loadFixture("record.json"), isRunRecord, "record.json");
}

export function stepOneDiff(): StepDiff {
  return typed(loadFixture("diff-step1.json"), isStepDiff, "diff-step1.json");
}

export function statesRecord(): RunRecord {
  return typed(loadFixture("states-record.json"), isRunRecord, "states-record.json");
}

export function statesDiff(): StepDiff {
  return typed(loadFixture("states-diff.json"), isStepDiff, "states-diff.json");
}
