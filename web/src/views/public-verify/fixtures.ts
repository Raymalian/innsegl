// SPDX-License-Identifier: Apache-2.0

/*
 * Wire fixtures for the public verification page.
 *
 * These are RESPONSE BODIES, not typed Proofs, and that is the point. The
 * dashboard's other views can start from a `Proof` because something upstream
 * of them has already decided the response was one. This page cannot: it is
 * the view that a stranger points at a deployment nobody vouches for, so the
 * first thing it does with a response is refuse to believe it is well formed.
 * A fixture typed as `Proof` would have skipped that step in every test.
 *
 * So every builder below returns `unknown`, the tests hand it to the real
 * parser, and a malformed body is one of the cases rather than a case nobody
 * could express.
 *
 * The three check names come from `components/verification`'s CHECK_NAMES —
 * the protected spellings `internal/verify` uses and doc 06 §4.1 states. A
 * fixture that invented its own would be testing a page nobody has tested.
 */

import { CHECK_NAMES } from "../../components/verification";
import type { CheckResult } from "../../components/verification";

export const COMMIT_SHA = "4f2c1d9b8a7e6f5d4c3b2a1908f7e6d5c4b3a291";
export const REPO = "innsegl";
export const LOG_INDEX = 82914;
export const ENTRY_UUID =
  "24296fb24b8ad77a1c9f6d3e5b4a2f1908e7d6c5b4a39281706f5e4d3c2b1a09";
export const PROVEN_IDENTITY =
  "spiffe://innsegl.dev/agent/fix-ci/task-1481/run-7f3a2c";
export const FORGED_IDENTITY =
  "spiffe://innsegl.dev/agent/fix-ci/task-1481/run-0e91bd";
export const FULCIO_ENDPOINT = "https://fulcio.innsegl.dev/api/v1/rootCert";
export const REKOR_ENDPOINT = "https://rekor.innsegl.dev/api/v1/log/entries";
export const CHECKED_AT = "2026-08-31T09:14:02Z";
export const REFUSED = "dial tcp 10.0.0.4:443: connect: connection refused";

export const CERTIFICATE_PEM =
  "-----BEGIN CERTIFICATE-----\nMIIB0jCCAXigAwIBAgIUX\n-----END CERTIFICATE-----\n";
export const FULCIO_ROOT_PEM =
  "-----BEGIN CERTIFICATE-----\nMIICxDCCAmugAwIBAgIU\n-----END CERTIFICATE-----\n";
export const REKOR_KEY_PEM =
  "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYI\n-----END PUBLIC KEY-----\n";
export const COMMIT_OBJECT =
  "tree 9a8b7c6d5e4f302918273645afbecd0192837465\n" +
  "author fix-ci <fix-ci@innsegl.dev> 1756631042 +0000\n\n" +
  "chore: retry the flaky integration test\n\n" +
  `Agent-Identity: ${PROVEN_IDENTITY}\nAgent-Run: run-7f3a2c\nAgent-Task: task-1481\n`;

const DETAIL: Record<CheckResult, string> = {
  verified: "the check ran and the claim holds",
  failed: "the check ran and the claim does not hold",
  unavailable: "the check could not run",
};

function check(name: string, result: CheckResult): Record<string, unknown> {
  return { name, result, detail: DETAIL[result] };
}

export interface WireOptions {
  /** The three results, in doc 06 §4.1's order. */
  readonly results?: readonly [CheckResult, CheckResult, CheckResult];
  /** What the server ASSERTS. Deliberately settable to a lie. */
  readonly verdict?: string;
  readonly fulcioReachable?: boolean;
  readonly rekorReachable?: boolean;
  /** Drop one or both upstreams from the response entirely. */
  readonly omitUpstreams?: readonly string[];
  readonly claimIdentity?: string;
  readonly certificateIdentity?: string;
  /** Withhold the material a live upstream would have supplied. */
  readonly gaps?: readonly { readonly name: string; readonly reason: string }[];
  readonly withMaterial?: boolean;
  readonly withEntry?: boolean;
  readonly findings?: readonly Record<string, unknown>[];
}

/** A response body shaped exactly as `internal/api`'s Proof marshals. */
export function wireProof(options: WireOptions = {}): unknown {
  const results = options.results ?? (["verified", "verified", "verified"] as const);
  const fulcioReachable = options.fulcioReachable ?? true;
  const rekorReachable = options.rekorReachable ?? true;
  const omitted = new Set(options.omitUpstreams ?? []);
  const withEntry = options.withEntry ?? true;
  const withMaterial = options.withMaterial ?? true;

  const upstreams = [
    {
      name: "fulcio",
      url: FULCIO_ENDPOINT,
      reachable: fulcioReachable,
      checked_at: CHECKED_AT,
      ...(fulcioReachable ? {} : { error: REFUSED }),
    },
    {
      name: "rekor",
      url: REKOR_ENDPOINT,
      reachable: rekorReachable,
      checked_at: CHECKED_AT,
      ...(rekorReachable ? {} : { error: REFUSED }),
    },
  ].filter((upstream) => !omitted.has(upstream.name));

  const body: Record<string, unknown> = {
    repo: REPO,
    commit_sha: COMMIT_SHA,
    tree_hash: "9a8b7c6d5e4f302918273645afbecd0192837465",
    verdict: options.verdict ?? "verified",
    checks: [
      check(CHECK_NAMES.certificateChain, results[0]),
      check(CHECK_NAMES.rekorInclusion, results[1]),
      check(CHECK_NAMES.trailerIdentity, results[2]),
    ],
    claim: {
      identity: options.claimIdentity ?? PROVEN_IDENTITY,
      run: "run-7f3a2c",
      task: "task-1481",
    },
    certificate: {
      spiffe_id: options.certificateIdentity ?? PROVEN_IDENTITY,
      issuer: "https://oidc.innsegl.dev",
      serial_number: "5f1c0a3d",
      not_before: "2026-08-30T11:02:41Z",
      not_after: "2026-08-30T11:12:41Z",
      fingerprint: "b1c2d3e4f5061728394a5b6c7d8e9f0011223344",
    },
    entry: withEntry
      ? {
          uuid: ENTRY_UUID,
          log_index: LOG_INDEX,
          log_id: "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
          integrated_at: "2026-08-30T11:04:07Z",
          time_attested: true,
        }
      : { log_index: 0, time_attested: false },
    upstreams,
    material: {
      commit_object: COMMIT_OBJECT,
      commit_object_id: COMMIT_SHA,
      collected_at: CHECKED_AT,
      ...(withMaterial
        ? {
            certificate_pem: CERTIFICATE_PEM,
            fulcio_root_pem: FULCIO_ROOT_PEM,
            rekor_log_public_key_pem: REKOR_KEY_PEM,
            rekor_entry: { [ENTRY_UUID]: { logIndex: LOG_INDEX, body: "eyJraW5kIjoiaGFzaGVkcmVrb3JkIn0=" } },
          }
        : {}),
      ...(options.gaps === undefined ? {} : { gaps: options.gaps }),
    },
    data_as_of: CHECKED_AT,
  };
  if (options.findings !== undefined) body["findings"] = options.findings;
  return body;
}

/**
 * The failure this page exists for: both upstreams gone, so neither check that
 * needs one could run. The trailer/certificate comparison still holds, because
 * it is arithmetic over bytes already in hand — which is exactly why the page
 * must not let two passing checks and one blocked one read as a verdict.
 */
export function bothUpstreamsBlocked(): unknown {
  return wireProof({
    results: ["unavailable", "unavailable", "verified"],
    verdict: "unavailable",
    fulcioReachable: false,
    rekorReachable: false,
    withMaterial: false,
    withEntry: false,
    gaps: [
      {
        name: "fulcio_root_pem",
        reason:
          "the certificate authority could not be reached, so the root a third party would chain to is not in this response: " +
          REFUSED,
      },
      {
        name: "rekor_log_public_key_pem",
        reason:
          "the transparency log's public key could not be fetched, so its proof cannot be checked against anything: " +
          REFUSED,
      },
    ],
  });
}

/**
 * A server asserting a verdict its upstreams did not supply: three green
 * checks and a "verified" badge, over two upstreams that never answered.
 * There is no honest response of this shape — it is what a tampered or
 * database-backed deployment would return, and the page must refuse it.
 */
export function lyingProof(): unknown {
  return wireProof({
    results: ["verified", "verified", "verified"],
    verdict: "verified",
    fulcioReachable: false,
    rekorReachable: false,
  });
}

/** The same lie told by omission: no upstream is reported at all. */
export function silentUpstreamsProof(): unknown {
  return wireProof({ omitUpstreams: ["fulcio", "rekor"] });
}

/** A commit from before adoption: no claim, so nothing to check (E7, VER-006). */
export function unattributedProof(): unknown {
  const body = wireProof({ verdict: "unattributed" }) as Record<string, unknown>;
  return {
    ...body,
    checks: [],
    claim: {},
    certificate: {},
    entry: { log_index: 0, time_attested: false },
  };
}

/** A forged trailer: check 3 ran and failed. */
export function forgedTrailerProof(): unknown {
  return wireProof({
    results: ["verified", "verified", "failed"],
    verdict: "failed",
    claimIdentity: FORGED_IDENTITY,
  });
}
