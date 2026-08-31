// SPDX-License-Identifier: Apache-2.0

/*
 * The one request this page makes, and the five answers it can get.
 *
 * `GET /api/v1/proof/{commit_sha}?repo=` — internal/api/server.go's
 * handleProof. There is no other endpoint here: doc 06 §3.6's page is
 * anonymous, so it has nothing to authenticate with and nothing to ask that
 * would need it.
 *
 * ── FIVE OUTCOMES, NOT TWO ─────────────────────────────────────────────────
 *
 * A `Proof | null` return would have collapsed four different failures into
 * one, and doc 06 P2 is the rule against exactly that: "It never collapses 'we
 * couldn't check' into either of the other two." A commit this deployment does
 * not hold, a deployment that refused the request, a deployment that could not
 * be reached, and a deployment whose answer could not be read are four
 * different things to tell a reader, and only one of them is worth retrying
 * the same way.
 *
 * NONE of the five is a proof unless it is the first, and the view renders the
 * three-check panel in that branch alone. That is what keeps doc 06 §4.6's
 * "no blank panels" and I5's "no database-only verdict" from depending on
 * anybody remembering them: there is no code path from a failed request to a
 * rendered verdict, because the failure branches carry no Proof to render.
 *
 * ── NO CREDENTIALS, NO CACHE ───────────────────────────────────────────────
 *
 * `credentials: "omit"` because the page is anonymous and a cookie that
 * travelled with the request would make the answer depend on who was asking,
 * which is the opposite of what a shareable proof link means.
 *
 * `cache: "no-store"` because doc 06 §8's first anti-pattern is "a verified
 * state rendered from cache while the live check errored", and an intermediary
 * that had cached a 200 would produce precisely that with the page none the
 * wiser. internal/api/server.go sets `Cache-Control: no-store` on every
 * response for the same reason; this is the other half of that agreement.
 *
 * ── THE BOUND IS HERE, AND ALSO IN THE COMPONENT ───────────────────────────
 *
 * doc 06 §8's anti-pattern 8 is "spinners without timeout-to-error". This
 * client aborts its own request, and `LoadingState` independently times out
 * the indicator. Two bounds rather than one, because they fail differently: a
 * fetch that never settles is caught here, and a client that never resolves
 * its promise at all is caught there.
 */

import type { Finding, Proof } from "../../components/verification";
import { readProofResponse } from "./response";

export interface ProofRequest {
  readonly commit: string;
  readonly repo: string;
}

/** What came back. Exactly one of these carries a Proof. */
export type ProofOutcome =
  | { readonly kind: "proof"; readonly proof: Proof; readonly findings: readonly Finding[] }
  | { readonly kind: "not-found"; readonly detail: string }
  | { readonly kind: "rejected"; readonly detail: string }
  | { readonly kind: "unreachable"; readonly detail: string }
  | { readonly kind: "malformed"; readonly detail: string };

export interface ProofClientOptions {
  /** Where the API lives. Empty means same-origin, which is the deployment. */
  readonly baseUrl?: string;
  readonly fetchImpl?: typeof fetch;
  readonly timeoutMs?: number;
  /** The caller's abort, for a request that has been superseded. */
  readonly signal?: AbortSignal;
}

/** Long enough for a cold verification against two upstreams, short enough
 * that a reader is not left watching a page that will never answer. */
export const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;

/** The address of one proof. Exported because it is also the shareable link a
 * reader can hand to `curl`, which is the whole of doc 06 P5 in one URL. */
export function proofPath(request: ProofRequest, baseUrl = ""): string {
  const path = `${baseUrl}/api/v1/proof/${encodeURIComponent(request.commit)}`;
  if (request.repo === "") return path;
  return `${path}?repo=${encodeURIComponent(request.repo)}`;
}

export async function fetchProof(
  request: ProofRequest,
  options: ProofClientOptions = {},
): Promise<ProofOutcome> {
  if (request.commit === "") {
    return { kind: "rejected", detail: "no commit was named" };
  }

  const doFetch = options.fetchImpl ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  const abortFromCaller = () => controller.abort();
  options.signal?.addEventListener("abort", abortFromCaller);

  try {
    const response = await doFetch(proofPath(request, options.baseUrl ?? ""), {
      method: "GET",
      headers: { Accept: "application/json" },
      credentials: "omit",
      cache: "no-store",
      signal: controller.signal,
    });

    let body: unknown;
    try {
      body = await response.json();
    } catch (error) {
      return {
        kind: "malformed",
        detail: `HTTP ${response.status}: the body is not JSON: ${messageOf(error)}`,
      };
    }

    if (!response.ok) {
      const detail = `HTTP ${response.status}: ${serverMessage(body)}`;
      return response.status === 404
        ? { kind: "not-found", detail }
        : { kind: "rejected", detail };
    }

    const reading = readProofResponse(body);
    if (!reading.ok) {
      return {
        kind: "malformed",
        detail: `the response is not a proof: ${reading.reason}`,
      };
    }
    return { kind: "proof", proof: reading.proof, findings: reading.findings };
  } catch (error) {
    return {
      kind: "unreachable",
      detail: timedOut
        ? `no answer within ${timeoutMs} ms`
        : messageOf(error),
    };
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", abortFromCaller);
  }
}

/** internal/api's error envelope: `{"error":{"code":…,"message":…}}`. Rendered
 * verbatim — doc 06 §6.1 wants the reader told what failed, and the
 * deployment's own sentence says it better than a substitute would. */
function serverMessage(body: unknown): string {
  if (typeof body === "object" && body !== null && "error" in body) {
    const envelope = (body as { error: unknown }).error;
    if (typeof envelope === "object" && envelope !== null && "message" in envelope) {
      const message = (envelope as { message: unknown }).message;
      if (typeof message === "string" && message !== "") return message;
    }
  }
  return "the deployment gave no reason";
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
