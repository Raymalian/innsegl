// SPDX-License-Identifier: Apache-2.0

/*
 * The shape of the overview, as `internal/api` actually returns it.
 *
 * Every name below is the JSON name the Go type carries — snake_case and all —
 * for the same reason `components/verification/types.ts` keeps them: a second
 * vocabulary is a second thing to keep in agreement by hand.
 * `internal/api/query.go`'s `Overview` and `AnchorHeartbeat` are the source,
 * and `internal/api/server.go` serves them at `GET /api/v1/overview`.
 *
 * Three things about that response are load-bearing here and none of them is
 * obvious from the type:
 *
 * 1. THERE IS NO PASS RATE, deliberately. query.go says so in as many words:
 *    "a rate computed from these tables would be a database-only verdict,
 *    which IP §6.11 and FD P2 forbid in terms". doc 06 §3.1 asks for one
 *    anyway. `PassRate` below is therefore NOT part of this response — it is
 *    the shape a LIVE measurement would have to have, and nothing in this
 *    build produces one. See PassRateCard.
 *
 * 2. `anchored` is false for an ordinary, healthy state. doc 02 §3 puts the
 *    anchoring members on a SUPERSEDING `segment_sealed` event "once Rekor
 *    confirms", so between the seal and the confirmation the newest event
 *    carries none of them. That segment is sealed and waiting, which is
 *    neither "anchored M min ago" nor "nothing anchored yet".
 *
 * 3. `sealed_at` is always present in the JSON even when nothing was sealed:
 *    Go's `omitempty` does not omit a struct, so the zero time marshals as
 *    "0001-01-01T00:00:00Z". `present` is the field to branch on, never the
 *    timestamp.
 */

/** The newest sealed segment, and whether Rekor has it yet. */
export interface AnchorHeartbeat {
  /** False when no segment has ever been sealed. */
  readonly present: boolean;
  /** Content address of the segment (doc 02 §3). Not the "N" of the header:
   * ADR-0006 and `internal/segment`'s LagSnapshot both say segments are named
   * to people by their position range. */
  readonly segment_id?: string;
  readonly first_position?: number;
  readonly last_position?: number;
  /** RFC 3339. The `ts` of the newest `segment_sealed` event — which is the
   * seal time while `anchored` is false, and the moment the superseding
   * anchoring event was appended once it is true. */
  readonly sealed_at?: string;
  readonly anchored: boolean;
  readonly rekor_log_index?: number;
}

/** `GET /api/v1/overview`. */
export interface OverviewData {
  readonly active_runs: number;
  readonly retired_runs: number;
  readonly expired_runs: number;
  readonly commits_recorded: number;
  /** How many `unattributed_signature_detected` and `ledger_drift_detected`
   * events the ledger holds. A COUNT: the query API exposes no endpoint that
   * lists them, so this view can report that they exist and cannot link to
   * each one. Reported as a gap. */
  readonly open_alerts: number;
  readonly anchor: AnchorHeartbeat;
  readonly data_as_of: string;
}

/** One page of `GET /api/v1/runs`, read for `total` alone (see RunsToday). */
export interface RunPage {
  readonly runs: readonly RunSummary[];
  readonly total: number;
  readonly limit: number;
  readonly next_cursor?: string;
  readonly data_as_of: string;
}

/** One row of the runs table (`internal/api/query.go`'s RunSummary). */
export interface RunSummary {
  readonly run_id: string;
  readonly spiffe_id: string;
  readonly agent_type: string;
  readonly task_ref: string;
  readonly status: "active" | "retired" | "expired";
  readonly repos: readonly string[];
  readonly commits: number;
  readonly chain_position: number;
  readonly registered_at: string;
  readonly last_event_at: string;
}

/**
 * A count over a stated window.
 *
 * doc 06 §8 anti-pattern 10 names "cumulative counts with no window" as a
 * defect, so a windowed metric carries the window it was counted over and the
 * card renders it. `since` is what the query API was actually asked for, not a
 * description of it.
 */
export interface WindowedCount {
  readonly count: number;
  readonly since: Date;
}

/**
 * A verification pass rate that a LIVE check produced.
 *
 * Nothing in this build produces one, and that is the whole difficulty — see
 * PassRateCard for the argument and the report for the ruling this needs.
 * The shape is here because it is what would make doc 06 §3.1's rate
 * renderable without asserting a verdict nothing checked:
 *
 *   - the three outcomes stay separate. A single scalar "pass rate" collapses
 *     *failed* into *unavailable*, which doc 06 §8 anti-pattern 2 forbids.
 *   - `liveness` is required and has no default, exactly as it is on
 *     `VerificationPanel` (FE-039). A retained rate that says nothing by
 *     saying nothing is the same silent failure one level up.
 *   - `measuredAt` is when the checks ran, because a rate is a measurement
 *     with an age and not a current state.
 */
export interface PassRate {
  readonly verified: number;
  readonly failed: number;
  readonly unavailable: number;
  /** Commits the measurement covered. verified + failed + unavailable. */
  readonly checked: number;
  readonly measuredAt: Date;
  readonly liveness: MeasuredLiveness;
}

/** `Liveness` with the source stated. The panel's contract, narrowed: there is
 * no arm here in which a caller can stay quiet. */
export interface MeasuredLiveness {
  readonly source: "live" | "cache";
  readonly liveError?: string;
}
