// SPDX-License-Identifier: Apache-2.0

/*
 * RM-330 (#506) — what each alert means, and how the alerts page groups them.
 *
 * Every alert has a cause the page can name in plain words: the reconciler's
 * fixed reasons, the sealer's anchoring reason, or the unattributed
 * signature. Alerts with the same cause are one group, because one review
 * usually explains all of them — a run whose telemetry stopped raises one
 * witness alert per tool call.
 */

import { describe, expect, it } from "vitest";

import type { AlertRecord } from "../overview/types";
import { alertCause, explain } from "./explain";
import { DRIFT, SEGMENT_DRIFT, UNATTRIBUTED } from "./fixtures";
import { groupAlerts } from "./groups";
import { strings } from "./strings";

const WITNESS: AlertRecord = {
  ...DRIFT,
  event_id: "01a07900-0000-7000-8000-000000000001",
  chain_position: 50,
  reason: "the harness's own OTLP telemetry recorded no tool_result for this tool call",
};

const UNSIGNED: AlertRecord = {
  ...DRIFT,
  event_id: "01a07900-0000-7000-8000-000000000002",
  chain_position: 51,
  reason: "a git commit was made with no signature recorded for it",
};

const UNANCHORED: AlertRecord = {
  ...SEGMENT_DRIFT,
  event_id: "01a07900-0000-7000-8000-000000000003",
  chain_position: 52,
  reason:
    "segment sha256:9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f (positions 1..40) is sealed but has no transparency log entry: dial tcp: connection refused",
};

describe("RM-330 every alert has a cause, and every cause an explanation", () => {
  it.each([
    [WITNESS, "noTelemetryWitness"],
    [UNSIGNED, "commitNotSigned"],
    [DRIFT, "rekorMismatch"],
    [{ ...DRIFT, reason: "the transparency log entry this commit_recorded names is at a different rekor_log_index" }, "rekorMismatch"],
    [UNANCHORED, "unanchored"],
    [UNATTRIBUTED, "unattributed"],
    [SEGMENT_DRIFT, "other"],
  ] as const)("%#: names the cause %s", (alert, cause) => {
    expect(alertCause(alert)).toBe(cause);
  });

  it("explains each cause with what it means and what to do, never the same words twice", () => {
    const causes = ["noTelemetryWitness", "commitNotSigned", "rekorMismatch", "unanchored", "unattributed", "other"] as const;
    const seen = new Set<string>();
    for (const cause of causes) {
      const copy = explain(cause);
      expect(copy.whatDetail, cause).toMatch(/\.$/);
      expect(copy.todoDetail, cause).toMatch(/\.$/);
      expect(seen.has(copy.whatDetail), cause).toBe(false);
      seen.add(copy.whatDetail);
    }
  });

  it("says plainly that an unanchored segment clears on its own", () => {
    expect(explain("unanchored").todoDetail).toMatch(/on its own/);
  });

  it("names the two reasons the menu used to show raw in plain words", () => {
    expect(strings.alert.reasons.noTelemetryWitness).toMatch(/\.$/);
    expect(strings.alert.reasons.commitNotSigned).toMatch(/\.$/);
  });
});

describe("RM-330 grouping and filtering the alerts page", () => {
  const resolvedWitness: AlertRecord = {
    ...WITNESS,
    event_id: "01a07900-0000-7000-8000-000000000009",
    chain_position: 49,
    resolved: true,
    resolved_by: "operator",
    resolved_at: "2026-09-06T18:00:00Z",
    resolved_reason: "telemetry was restarted",
  };
  const otherRunWitness: AlertRecord = {
    ...WITNESS,
    event_id: "01a07900-0000-7000-8000-000000000010",
    chain_position: 53,
    run_id: "run-other",
  };
  const all = [DRIFT, UNATTRIBUTED, WITNESS, resolvedWitness, otherRunWitness, UNSIGNED];

  it("puts alerts with one cause in one group, newest first, with open and resolved counts", () => {
    const { groups } = groupAlerts(all, { kind: "all", run: "" });
    const witness = groups.find((g) => g.cause === "noTelemetryWitness");
    expect(witness?.alerts.map((a) => a.event_id)).toEqual([
      otherRunWitness.event_id,
      WITNESS.event_id,
      resolvedWitness.event_id,
    ]);
    expect(witness?.open).toHaveLength(2);
    expect(witness?.resolvedCount).toBe(1);
  });

  it("lists only open alerts by default, and drops a group with none", () => {
    const { groups } = groupAlerts([DRIFT, resolvedWitness], { kind: "", run: "" });
    expect(groups.map((g) => g.cause)).toEqual(["rekorMismatch"]);
  });

  it("lists only resolved alerts when asked", () => {
    const { groups } = groupAlerts(all, { kind: "resolved", run: "" });
    expect(groups).toHaveLength(1);
    expect(groups[0]?.alerts.map((a) => a.event_id)).toEqual([resolvedWitness.event_id]);
  });

  it("narrows to one run, and offers every run the alerts name", () => {
    const { groups, runs } = groupAlerts(all, { kind: "", run: "run-other" });
    expect(groups).toHaveLength(1);
    expect(groups[0]?.open.map((a) => a.event_id)).toEqual([otherRunWitness.event_id]);
    expect(runs).toEqual(["run-dd41951f222496a135241a77d1430237", "run-other"]);
  });

  it("orders groups with open alerts first, then by their newest alert", () => {
    const { groups } = groupAlerts(all, { kind: "all", run: "" });
    expect(groups.map((g) => g.cause)).toEqual([
      "noTelemetryWitness",
      "commitNotSigned",
      "unattributed",
      "rekorMismatch",
    ]);
  });

  it("keeps two unknown reasons apart, so one review never closes an unrelated alert", () => {
    const a: AlertRecord = { ...SEGMENT_DRIFT, event_id: "01a07900-0000-7000-8000-00000000000a", reason: "first thing" };
    const b: AlertRecord = { ...SEGMENT_DRIFT, event_id: "01a07900-0000-7000-8000-00000000000b", reason: "second thing" };
    expect(groupAlerts([a, b], { kind: "", run: "" }).groups).toHaveLength(2);
  });
});
