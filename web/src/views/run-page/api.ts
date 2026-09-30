// SPDX-License-Identifier: Apache-2.0

/*
 * The run page's reads. Three endpoints, each injectable so a test never
 * touches the network (the same shape as run-detail's `fetchRun`):
 *
 *   GET /api/v1/runs/{run_id}/record          RunRecord  (the contract)
 *   GET /api/v1/runs/{run_id}/steps/{n}/diff  StepDiff   (one step's diff)
 *   GET /api/v1/proof/{sha}                   Proof      (components/verification)
 *
 * The proof endpoint is the same one run-detail's CommitVerification already
 * reads; this file has its own copy rather than importing that view's local
 * module, so this view's fetch behaviour does not depend on another view's
 * internals staying unchanged. It is the same one-line fetch either way —
 * nothing about verification is reimplemented, only the HTTP call that
 * hands the response to `components/verification`'s own rollup.
 */

import type { Proof } from "../../components/verification";
import type { RunRecord, StepDiff } from "./types";

/** A run this ledger does not hold. Distinct from a read that failed — the
 * two are different facts (doc 06 P2). */
export class RunRecordNotFound extends Error {}

export type FetchRunRecord = (
  runId: string,
  signal: AbortSignal,
) => Promise<RunRecord>;

export type FetchStepDiff = (
  runId: string,
  step: number,
  signal: AbortSignal,
) => Promise<StepDiff>;

export type FetchProof = (commitSHA: string, signal: AbortSignal) => Promise<Proof>;

export const fetchRunRecord: FetchRunRecord = async (runId, signal) => {
  const response = await fetch(`/api/v1/runs/${encodeURIComponent(runId)}/record`, {
    signal,
  });
  if (response.status === 404) throw new RunRecordNotFound(runId);
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return (await response.json()) as RunRecord;
};

export const fetchStepDiff: FetchStepDiff = async (runId, step, signal) => {
  const response = await fetch(
    `/api/v1/runs/${encodeURIComponent(runId)}/steps/${step}/diff`,
    { signal },
  );
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return (await response.json()) as StepDiff;
};

export const fetchProof: FetchProof = async (commitSHA, signal) => {
  const response = await fetch(`/api/v1/proof/${encodeURIComponent(commitSHA)}`, {
    signal,
  });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return (await response.json()) as Proof;
};
