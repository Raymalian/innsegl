// SPDX-License-Identifier: Apache-2.0

/*
 * Proof fixtures — the material FE-001 to FE-004 render.
 *
 * These are hand-built copies of what `internal/api`'s Prover returns: field
 * for field, spelling for spelling, including the three check names
 * `internal/verify` spells in doc 06 §4.1's words. Nothing here invents a
 * vocabulary the backend does not use, because a panel tested against an
 * invented shape is a panel nobody has tested.
 *
 * The builders below vary ONE thing each. That matters for FE-001: three
 * renders that differ in their check details would differ in their markup for
 * reasons that have nothing to do with the tri-state treatment, and the test
 * would pass without the treatment existing. `proofWithResults` holds every
 * detail, fact and identity constant and moves only the three results, so what
 * is left over between two renders is the presentation and nothing else.
 */

import type { Check, CheckResult, Proof } from "./types";
import { CHECK_NAMES } from "./types";

/** The identity the certificate proves in every fixture below. */
export const PROVEN_IDENTITY =
  "spiffe://innsegl.dev/agent/fix-ci/task-1481/run-7f3a2c";

/**
 * A forged trailer: the same trust domain, agent type and task, a run id that
 * is not the one the certificate proves. This is the shape doc 06 §4.1 and
 * VER-002 are written against — one segment out of six, in the middle of a
 * 52-character URI, which is exactly the difference a reader will not find by
 * eye and the panel therefore has to name.
 */
export const FORGED_IDENTITY =
  "spiffe://innsegl.dev/agent/fix-ci/task-1481/run-0e91bd";

export const COMMIT_SHA = "4f2c1d9b8a7e6f5d4c3b2a1908f7e6d5c4b3a291";
export const LOG_INDEX = 82914;

const DETAIL: Record<CheckResult, string> = {
  verified: "the check ran and the claim holds",
  failed: "the check ran and the claim does not hold",
  unavailable: "the check could not run",
};

function check(name: string, result: CheckResult): Check {
  return {
    name,
    result,
    detail: DETAIL[result],
    facts: [{ name: "checked against", value: "https://rekor.innsegl.dev" }],
  };
}

export interface ProofOverrides {
  readonly claimIdentity?: string;
  readonly certificateIdentity?: string;
  readonly upstreamsReachable?: boolean;
  readonly verdict?: Proof["verdict"];
}

/**
 * One proof carrying exactly the three results given, in doc 06 §4.1's order:
 * Fulcio chain, Rekor inclusion, trailer identity.
 */
export function proofWithResults(
  results: readonly [CheckResult, CheckResult, CheckResult],
  overrides: ProofOverrides = {},
): Proof {
  const reachable = overrides.upstreamsReachable ?? true;
  const checkedAt = "2026-08-31T09:14:02Z";
  return {
    repo: "innsegl",
    commit_sha: COMMIT_SHA,
    tree_hash: "9a8b7c6d5e4f302918273645afbecd0192837465",
    // The panel does not read this for its badge, and FE-001 proves it: a
    // server claiming "verified" over a failed check must still render failed.
    verdict: overrides.verdict ?? "verified",
    checks: [
      check(CHECK_NAMES.certificateChain, results[0]),
      check(CHECK_NAMES.rekorInclusion, results[1]),
      check(CHECK_NAMES.trailerIdentity, results[2]),
    ],
    claim: {
      identity: overrides.claimIdentity ?? PROVEN_IDENTITY,
      run: "run-7f3a2c",
      task: "task-1481",
    },
    certificate: {
      spiffe_id: overrides.certificateIdentity ?? PROVEN_IDENTITY,
      issuer: "https://oidc.innsegl.dev",
      serial_number: "5f1c0a3d",
      not_before: "2026-08-30T11:02:41Z",
      not_after: "2026-08-30T11:12:41Z",
      fingerprint: "b1c2d3e4f5061728394a5b6c7d8e9f0011223344",
    },
    entry: {
      uuid: "24296fb24b8ad77a1c9f6d3e5b4a2f1908e7d6c5b4a39281706f5e4d3c2b1a09",
      log_index: LOG_INDEX,
      log_id: "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
      integrated_at: "2026-08-30T11:04:07Z",
      time_attested: true,
    },
    upstreams: [
      {
        name: "fulcio",
        url: "https://fulcio.innsegl.dev/api/v1/rootCert",
        reachable,
        checked_at: checkedAt,
        ...(reachable ? {} : { error: "dial tcp: connection refused" }),
      },
      {
        name: "rekor",
        url: "https://rekor.innsegl.dev/api/v1/log/entries",
        reachable,
        checked_at: checkedAt,
        ...(reachable ? {} : { error: "dial tcp: connection refused" }),
      },
    ],
    material: {
      commit_object: "tree 9a8b7c6d5e4f302918273645afbecd0192837465\n",
      commit_object_id: COMMIT_SHA,
      certificate_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
      fulcio_root_pem: "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n",
      rekor_log_public_key_pem: "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n",
      collected_at: checkedAt,
    },
    data_as_of: checkedAt,
  };
}

/** All three checks ran live and passed. The only proof entitled to a green. */
export function verifiedProof(): Proof {
  return proofWithResults(["verified", "verified", "verified"]);
}

/** doc 06 §4.1: any single check failing makes the rollup failed. */
export function failedProof(): Proof {
  return proofWithResults(["failed", "verified", "verified"]);
}

/** doc 06 §4.1: any check erroring makes the rollup unavailable. */
export function unavailableProof(): Proof {
  return proofWithResults(["unavailable", "unavailable", "verified"], {
    upstreamsReachable: false,
  });
}

/**
 * The forged-trailer fixture doc 06 §7 requires by name: "The three-check
 * panel's mismatch case has a dedicated test with a forged trailer fixture."
 *
 * Check 3 fails, the other two hold — the certificate is genuine and the log
 * entry is real; what is false is the claim the commit message makes about
 * them. That is the case worth rendering carefully, because everything else on
 * the page looks fine.
 */
export function forgedTrailerProof(): Proof {
  const base = proofWithResults(["verified", "verified", "failed"], {
    claimIdentity: FORGED_IDENTITY,
    verdict: "failed",
  });
  const [chain, inclusion, identity] = base.checks;
  if (chain === undefined || inclusion === undefined || identity === undefined) {
    throw new Error("fixtures: the three checks are built above");
  }
  return {
    ...base,
    checks: [
      chain,
      inclusion,
      {
        ...identity,
        detail: "the trailer claims one identity and the certificate proves another",
        facts: [
          { name: "Agent-Identity trailer", value: FORGED_IDENTITY },
          { name: "certificate URI SAN", value: PROVEN_IDENTITY },
          {
            name: "differing segment",
            value: `run-id: the trailer says "run-0e91bd", the certificate says "run-7f3a2c"`,
          },
        ],
      },
    ],
  };
}
