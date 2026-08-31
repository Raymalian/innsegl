// SPDX-License-Identifier: Apache-2.0

/*
 * doc 06 §3.6's public verification page — issue #56 (RM-048).
 *
 * The shell registers `PublicVerifyView` under the route table's `verify`
 * view. Everything else is exported because this page's honesty is made of
 * testable parts rather than of a careful component: the response parser, the
 * client's five outcomes and the liveness gate each stand alone, and each has
 * its own test that can fail on its own.
 */

export { PublicVerifyView } from "./PublicVerifyView";
export type { PublicVerifyViewProps } from "./PublicVerifyView";

export { ProofChain } from "./ProofChain";
export type { ProofChainProps } from "./ProofChain";

export { DEFAULT_REQUEST_TIMEOUT_MS, fetchProof, proofPath } from "./client";
export type { ProofClientOptions, ProofOutcome, ProofRequest } from "./client";

export { readProofResponse } from "./response";
export type { ProofReading } from "./response";

export { REQUIRED_UPSTREAMS, livenessOf } from "./liveness";

export { strings, upstreamName } from "./strings";
export type { PublicVerifyStrings } from "./strings";
