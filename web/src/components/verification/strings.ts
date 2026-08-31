// SPDX-License-Identifier: Apache-2.0

/*
 * Every user-visible string the verification panel can render.
 *
 * doc 06 §6.3: "English-first; all strings externalized from components so
 * translation is possible." Same rule and same shape as the shared
 * components' catalogue, kept in this directory because this directory is
 * separately owned; folding the two together is a mechanical edit whenever
 * somebody wants one file.
 *
 * doc 06 §6.1 governs the wording and this is the component it was written
 * for. "Factual, unvarnished, specific. Say what was checked and what
 * happened: 'Rekor inclusion proven at index 82914,' not 'Everything looks
 * good!'" — and §8's anti-pattern 9 is "celebratory or reassuring copy
 * substituting for evidence". A panel that says "verified" in a friendly voice
 * is making a cryptographic claim in a register that invites the reader not to
 * check it. FE-038 holds this file to §6.1's banned vocabulary and §5.4's
 * casing and punctuation.
 *
 * The three check names are doc 06 §4.1's own words, which are also the words
 * `internal/verify` uses. They are a label a translator may move; the
 * spellings in types.ts are the protocol and are not.
 */

export const strings = {
  panel: {
    heading: "Verification",
    commit: "Commit",
    checkedAt: "Checked",
  },

  /* The rollup (doc 06 §4.2). Four states, because a commit that claims
   * nothing is not a commit that failed (VER-006, E7). */
  verdict: {
    verified: {
      label: "Verified",
      meaning: "All three checks ran live against Fulcio and Rekor, and all three hold.",
    },
    failed: {
      label: "Failed",
      meaning: "A check ran and what it checked does not hold.",
    },
    unavailable: {
      label: "Verification unavailable",
      meaning: "A check could not run, so nothing here is proven either way.",
    },
    unattributed: {
      label: "Unattributed",
      meaning:
        "This commit carries no signature and no Agent-Identity trailer, so it claims nothing for a check to settle.",
    },
  },

  /* One check's own result. Never collapsed into the rollup's (doc 06 §4.1). */
  result: {
    verified: {
      label: "Verified",
      meaning: "This check ran and what it checked holds.",
    },
    failed: {
      label: "Failed",
      meaning: "This check ran and what it checked does not hold.",
    },
    unavailable: {
      label: "Unavailable",
      meaning: "This check could not run.",
    },
  },

  checks: {
    heading: "Checks",
    certificateChain: "Fulcio certificate chain valid",
    rekorInclusion: "Rekor inclusion proven",
    trailerIdentity: "Trailer matches certificate identity",
    logIndex: "Log index",
    /* §6.1: say what happened. An absent entry is not entry number zero. */
    noLogIndex: "No transparency-log entry was resolved for this commit.",
    evidence: "Evidence",
  },

  identity: {
    heading: "Trailer and certificate identity",
    trailer: "Agent-Identity trailer",
    certificate: "Certificate URI SAN",
    absent: "Not present.",
    agree: "The trailer is the identity the certificate proves.",
    differs: (segment: string) => `The ${segment} segment differs.`,
    uncomparable:
      "The two identities cannot be compared segment by segment, so the whole value is marked.",
    /* Spoken beside the mark, because a mark is a visual event and doc 06 §6.4
     * wants the differing text reachable by assistive technology too. */
    marked: "differs",
  },

  mismatch: {
    title: "Trailer does not match the certificate",
    detail:
      "The commit claims one identity and the certificate proves another, so this attribution is not the one the signer holds.",
    evidence: "See the two identities",
  },

  /* Why a set of passing checks is not being reported as verified. Each of
   * these is a sentence a reader can act on, per doc 06 §6.1. */
  downgrade: {
    heading: "Reported as unavailable",
    "not-a-live-check":
      "This result was not produced by a live check, so it is reported as unavailable rather than repeated as a verdict.",
    "live-check-errored":
      "The live check could not run, so an earlier verdict is not repeated here.",
    "upstream-unreachable":
      "An upstream this check needs was unreachable, so it could not settle anything.",
    "material-contradicted":
      "The response contradicts its own material, so nothing it asserts is taken on trust.",
    "checks-missing":
      "One of the three checks is missing from this response, so the set is incomplete.",
  },

  upstream: {
    heading: "Upstreams",
    unreachable: (name: string) => `${name} was unreachable.`,
  },

  material: {
    heading: "Raw material",
    detail: "Everything below is what a third party needs to re-derive this verdict without the dashboard.",
    commitObject: "Commit object",
    certificate: "Signing certificate",
    fulcioRoot: "Fulcio root",
    rekorKey: "Rekor public key",
    gaps: "Missing material",
  },

  notes: {
    heading: "Notes",
  },
} as const;

export type VerificationStrings = typeof strings;
