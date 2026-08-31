// SPDX-License-Identifier: Apache-2.0

/*
 * The shape of a proof, as `internal/api` actually returns one.
 *
 * Every name below is the JSON name the Go type carries — snake_case and all —
 * because the alternative is a second vocabulary that has to be kept in
 * agreement with the first by hand. `internal/api/proof.go`'s Proof is the
 * source; `internal/verify`'s Check, Claim, CertificateInfo and EntryInfo are
 * embedded in it verbatim, and `internal/api/rederive.go`'s Finding is the
 * companion the same BFF produces.
 *
 * Two of the three vocabularies here are TRI-STATES, and both of them are
 * three states because collapsing any two would be a defect rather than a
 * simplification:
 *
 *   Result   verified | failed | unavailable        (doc 06 §4.1, P2)
 *   Verdict  the same three, plus `unattributed`    (VER-006)
 *   Agreement agrees | contradicts | underivable    (#48's re-derivation)
 *
 * `unattributed` is not a fourth verdict about a verification; it is a
 * statement about the COMMIT — one that carries neither a signature nor an
 * Agent-* trailer, and so makes no claim for anything to check. E7 says
 * commits from before adoption are simply unattributed, and rendering one as
 * failed would make every pre-adoption commit look like an attack.
 */

/** One check's outcome. doc 06 §4.1 requires exactly these three. */
export type CheckResult = "verified" | "failed" | "unavailable";

/** The rollup, plus the commit-level state VER-006 requires. */
export type Verdict = CheckResult | "unattributed";

/** One piece of evidence behind a check (doc 06 P1). */
export interface Fact {
  readonly name: string;
  readonly value: string;
}

export interface Check {
  readonly name: string;
  readonly result: CheckResult;
  readonly detail?: string;
  readonly facts?: readonly Fact[];
}

/**
 * The three check names, spelled as `internal/verify` spells them, which is
 * how doc 06 §4.1 spells them.
 *
 * PROTECTED STRINGS. They are duplicated here rather than derived, for the
 * same reason internal/verify duplicates the trailer keys rather than
 * importing them from internal/signing: this file must depend on nothing, and
 * a spelling that drifts is caught by FE-038 asserting these three against the
 * specification's own words.
 *
 * They are used to RECOGNISE a check, never to render one — the label a reader
 * sees comes from the string catalogue, so a translator can move it.
 */
export const CHECK_NAMES = {
  certificateChain: "Fulcio certificate chain valid",
  rekorInclusion: "Rekor inclusion proven",
  trailerIdentity: "Trailer matches certificate identity",
} as const;

export type CheckId = keyof typeof CHECK_NAMES;

export const CHECK_IDS: readonly CheckId[] = [
  "certificateChain",
  "rekorInclusion",
  "trailerIdentity",
];

/** Which of the three a check is, or undefined for one this build does not
 * know. An unknown check is rendered under its own name rather than dropped:
 * a panel that silently omitted a check would be hiding a result. */
export function checkIdOf(name: string): CheckId | undefined {
  return CHECK_IDS.find((id) => CHECK_NAMES[id] === name);
}

/** What the commit's trailers assert. Claimed, never established. */
export interface Claim {
  readonly identity?: string;
  readonly run?: string;
  readonly task?: string;
}

/** What the signing certificate says about itself. */
export interface CertificateInfo {
  readonly spiffe_id?: string;
  readonly issuer?: string;
  readonly serial_number?: string;
  readonly not_before?: string;
  readonly not_after?: string;
  readonly fingerprint?: string;
}

/** The transparency-log entry check 2 found. */
export interface EntryInfo {
  readonly uuid?: string;
  readonly log_index: number;
  readonly log_id?: string;
  readonly integrated_at?: string;
  /** Whether the log SIGNED the integration time. Without it the timestamp is
   * a number in a response rather than a statement by the log. */
  readonly time_attested: boolean;
}

/** An attribution rescued from a rewritten commit's tree hash. */
export interface Recovered {
  readonly commit_sha: string;
  readonly identity: string;
  readonly log_index: number;
  readonly integrated_at: string;
}

/** One dependency the BFF spoke to, and what it said. */
export interface Upstream {
  readonly name: string;
  readonly url: string;
  readonly reachable: boolean;
  readonly error?: string;
  readonly checked_at: string;
}

/** One piece of material the BFF could not collect, and why. A gap is stated
 * rather than left as an absence: silence about missing evidence reads as
 * "collected and fine". */
export interface Gap {
  readonly name: string;
  readonly reason: string;
}

/** The raw input and output doc 06 §7 requires in the response. */
export interface Material {
  readonly commit_object?: string;
  readonly commit_object_id?: string;
  readonly certificate_pem?: string;
  readonly fulcio_root_pem?: string;
  readonly rekor_entry?: unknown;
  readonly rekor_log_public_key_pem?: string;
  readonly collected_at?: string;
  readonly gaps?: readonly Gap[];
}

/** One live verification plus everything needed to re-derive it. */
export interface Proof {
  readonly repo: string;
  readonly commit_sha: string;
  readonly tree_hash?: string;
  readonly verdict: Verdict;
  readonly checks: readonly Check[];
  readonly claim: Claim;
  readonly certificate: CertificateInfo;
  readonly entry: EntryInfo;
  readonly recovered?: readonly Recovered[];
  readonly notes?: readonly string[];
  readonly upstreams: readonly Upstream[];
  readonly material: Material;
  readonly data_as_of: string;
}

/** One re-derivation's outcome (internal/api/rederive.go). */
export type Agreement = "agrees" | "contradicts" | "underivable";

/** One re-derived claim. `underivable` is NEVER read as either of the other
 * two: a response degraded by an unreachable log carries no entry, and a
 * checker that read absent material as agreement would be doc 06's
 * anti-pattern 1 with the badge moved one level down. */
export interface Finding {
  readonly name: string;
  readonly result: Agreement;
  readonly detail?: string;
}
