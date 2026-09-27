// SPDX-License-Identifier: Apache-2.0

/*
 * Alert records as `GET /api/v1/alerts` serves them, for this directory's
 * tests. Shapes copied from a real deployment's feed, identifiers anonymised.
 */

import type { AlertRecord } from "../overview/types";

export const DRIFT: AlertRecord = {
  chain_position: 25,
  event_id: "01a077c2-eff1-7762-8a61-91a3a5c390e8",
  event_type: "ledger_drift_detected",
  ts: "2026-09-06T17:27:39.249Z",
  run_id: "run-dd41951f222496a135241a77d1430237",
  subject_event_id: "01a072b2-cdda-774e-a0e2-889ec5ac33fa",
  reason: "commit_recorded claims a Rekor entry that the log does not contain",
  resolved: false,
};

export const UNATTRIBUTED: AlertRecord = {
  chain_position: 32,
  event_id: "01a077dd-7004-7ef5-befc-b91fe55d3f59",
  event_type: "unattributed_signature_detected",
  ts: "2026-09-06T17:56:35.972Z",
  certificate_identity:
    "spiffe://innsegl.dev/agent/38830790/831c43f5/run-4d060209a64e0aa508f13e9f1fe193f5",
  rekor_entry_uuid:
    "628d17d6783490c97e42fb59ab4d3f6d7a1550d945e2bed280f455bca226de78f76205cc0c68c131",
  rekor_log_index: 2,
  resolved: false,
};

/** A segment-read drift: no run, and a free-text reason carrying a digest. */
export const SEGMENT_DRIFT: AlertRecord = {
  chain_position: 40,
  event_id: "01a07801-1111-7222-8333-944455556666",
  event_type: "ledger_drift_detected",
  ts: "2026-09-06T18:10:00.000Z",
  subject_event_id: "01a07800-aaaa-7bbb-8ccc-9dddeeeeffff",
  reason:
    "segment object sha256:9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f is missing from storage",
  resolved: false,
};

export const NOW = new Date("2026-09-06T18:13:00.000Z");
