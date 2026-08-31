// SPDX-License-Identifier: Apache-2.0

/*
 * FE-062 (NEW — proposed for doc 07 TC-FE; see the report for #56).
 *
 *   U | The public page's proof request: address, transport options and the
 *     five outcomes | The request is anonymous and uncacheable; each of a
 *     proof, a missing commit, a refusal, an unreachable deployment and an
 *     unreadable answer is its own outcome, and only the first carries a
 *     Proof | FD §3.6, §7, §8.1, P2; IP I5
 *
 * ── WHY THE TRANSPORT OPTIONS ARE ASSERTED AND NOT JUST WRITTEN ────────────
 *
 * `cache: "no-store"` is what stops doc 06 §8's anti-pattern 1 from arriving
 * through an intermediary rather than through the UI: a proxy or a service
 * worker that had cached a 200 would hand this page a verified verdict for a
 * live check that never ran, and nothing on the page could tell. It is one
 * word in a fetch call, it is invisible in review once written, and removing
 * it breaks nothing that any other test would notice. So it is asserted.
 *
 * `credentials: "omit"` is doc 06 §3.6's "anonymous, no auth" made true of the
 * request rather than of the page's intent. A cookie travelling with a proof
 * request would make the answer depend on who asked, which is not what a
 * shareable proof link means.
 *
 * ── WHY FIVE OUTCOMES AND NOT A NULL ───────────────────────────────────────
 *
 * doc 06 P2 forbids collapsing "we couldn't check" into anything else. Four of
 * these five are ways of not checking, and they call for different actions: a
 * commit this deployment does not serve is not a deployment that is down, and
 * neither is an answer that could not be read. Exactly one member of the union
 * carries a Proof, which is what makes "no verdict without a live check" a
 * property of the type rather than of a branch somebody remembered.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { DEFAULT_REQUEST_TIMEOUT_MS, fetchProof, proofPath } from "./client";
import { COMMIT_SHA, REPO, wireProof } from "./fixtures";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

function responding(body: unknown, status = 200, contentType = "application/json") {
  return vi.fn(
    async () =>
      new Response(typeof body === "string" ? body : JSON.stringify(body), {
        status,
        headers: { "content-type": contentType },
      }),
  );
}

describe("FE-062 the address of one proof", () => {
  it("is internal/api's own route", () => {
    expect(proofPath({ commit: COMMIT_SHA, repo: "" })).toBe(
      `/api/v1/proof/${COMMIT_SHA}`,
    );
  });

  it("carries the repository only when one was named", () => {
    expect(proofPath({ commit: COMMIT_SHA, repo: REPO })).toBe(
      `/api/v1/proof/${COMMIT_SHA}?repo=${REPO}`,
    );
  });

  it("encodes both, so a revision with a slash cannot become a second path segment", () => {
    expect(proofPath({ commit: "topic/a", repo: "org/repo" })).toBe(
      "/api/v1/proof/topic%2Fa?repo=org%2Frepo",
    );
  });

  it("can be pointed at another deployment", () => {
    expect(proofPath({ commit: "abc", repo: "" }, "https://verify.innsegl.dev")).toBe(
      "https://verify.innsegl.dev/api/v1/proof/abc",
    );
  });
});

describe("FE-062 the request is anonymous and uncacheable", () => {
  it("sends no credentials, stores nothing, and only reads", async () => {
    const fetchImpl = responding(wireProof());
    await fetchProof({ commit: COMMIT_SHA, repo: REPO }, { fetchImpl });

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`/api/v1/proof/${COMMIT_SHA}?repo=${REPO}`);
    expect(init.method).toBe("GET");
    expect(init.credentials).toBe("omit");
    expect(init.cache).toBe("no-store");
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });
});

describe("FE-062 the five outcomes", () => {
  it("a proof, when the deployment returns one", async () => {
    const outcome = await fetchProof(
      { commit: COMMIT_SHA, repo: REPO },
      { fetchImpl: responding(wireProof()) },
    );
    expect(outcome.kind).toBe("proof");
    if (outcome.kind !== "proof") return;
    expect(outcome.proof.commit_sha).toBe(COMMIT_SHA);
  });

  it("not-found, with the deployment's own sentence", async () => {
    const outcome = await fetchProof(
      { commit: COMMIT_SHA, repo: REPO },
      {
        fetchImpl: responding(
          { error: { code: "not_found", message: "innsegl holds no commit 4f2c1d9" } },
          404,
        ),
      },
    );
    expect(outcome.kind).toBe("not-found");
    expect(outcome.kind !== "proof" && outcome.detail).toContain(
      "innsegl holds no commit 4f2c1d9",
    );
  });

  it("rejected, on any other status the deployment returns", async () => {
    for (const status of [400, 405, 429, 500, 503]) {
      const outcome = await fetchProof(
        { commit: COMMIT_SHA, repo: "" },
        { fetchImpl: responding({ error: { code: "internal", message: "the prover failed" } }, status) },
      );
      expect(outcome.kind, `HTTP ${status}`).toBe("rejected");
      expect(outcome.kind !== "proof" && outcome.detail).toContain(String(status));
    }
  });

  it("rejected with a stated absence when the deployment gives no reason", async () => {
    const outcome = await fetchProof(
      { commit: COMMIT_SHA, repo: "" },
      { fetchImpl: responding({}, 500) },
    );
    expect(outcome.kind !== "proof" && outcome.detail).toContain("no reason");
  });

  it("unreachable, when there is no answer at all", async () => {
    const outcome = await fetchProof(
      { commit: COMMIT_SHA, repo: "" },
      {
        fetchImpl: vi.fn(async () => {
          throw new TypeError("Failed to fetch");
        }),
      },
    );
    expect(outcome.kind).toBe("unreachable");
    expect(outcome.kind !== "proof" && outcome.detail).toBe("Failed to fetch");
  });

  it("malformed, when the body is not JSON", async () => {
    const outcome = await fetchProof(
      { commit: COMMIT_SHA, repo: "" },
      { fetchImpl: responding("<html>a proxy error page</html>", 200, "text/html") },
    );
    expect(outcome.kind).toBe("malformed");
  });

  it("malformed, when the body is JSON but not a proof, and names the field", async () => {
    const outcome = await fetchProof(
      { commit: COMMIT_SHA, repo: "" },
      { fetchImpl: responding({ verdict: "verified" }) },
    );
    expect(outcome.kind).toBe("malformed");
    expect(outcome.kind !== "proof" && outcome.detail).toContain("commit_sha");
  });

  it("refuses to ask about no commit at all", async () => {
    const fetchImpl = responding(wireProof());
    const outcome = await fetchProof({ commit: "", repo: REPO }, { fetchImpl });
    expect(outcome.kind).toBe("rejected");
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("carries a Proof in exactly one of the five", async () => {
    const outcomes = await Promise.all([
      fetchProof({ commit: COMMIT_SHA, repo: "" }, { fetchImpl: responding(wireProof()) }),
      fetchProof({ commit: COMMIT_SHA, repo: "" }, { fetchImpl: responding({}, 404) }),
      fetchProof({ commit: COMMIT_SHA, repo: "" }, { fetchImpl: responding({}, 500) }),
      fetchProof({ commit: COMMIT_SHA, repo: "" }, { fetchImpl: responding({ a: 1 }) }),
      fetchProof(
        { commit: COMMIT_SHA, repo: "" },
        { fetchImpl: vi.fn(async () => { throw new Error("down"); }) },
      ),
    ]);
    expect(outcomes.filter((o) => "proof" in o)).toHaveLength(1);
    expect(new Set(outcomes.map((o) => o.kind)).size).toBe(5);
  });
});

describe("FE-062 the request is bounded (doc 06 §8 anti-pattern 8)", () => {
  it("has a default bound", () => {
    expect(DEFAULT_REQUEST_TIMEOUT_MS).toBeGreaterThan(0);
  });

  it("gives up rather than hanging, and says how long it waited", async () => {
    const outcome = await fetchProof(
      { commit: COMMIT_SHA, repo: "" },
      {
        timeoutMs: 5,
        fetchImpl: vi.fn(
          (_url: RequestInfo | URL, init?: RequestInit) =>
            new Promise<Response>((_resolve, reject) => {
              init?.signal?.addEventListener("abort", () =>
                reject(new DOMException("aborted", "AbortError")),
              );
            }),
        ) as unknown as typeof fetch,
      },
    );
    expect(outcome.kind).toBe("unreachable");
    expect(outcome.kind !== "proof" && outcome.detail).toBe("no answer within 5 ms");
  });

  it("aborts when the caller supersedes the request", async () => {
    const controller = new AbortController();
    const pending = fetchProof(
      { commit: COMMIT_SHA, repo: "" },
      {
        signal: controller.signal,
        fetchImpl: vi.fn(
          (_url: RequestInfo | URL, init?: RequestInit) =>
            new Promise<Response>((_resolve, reject) => {
              init?.signal?.addEventListener("abort", () =>
                reject(new DOMException("aborted", "AbortError")),
              );
            }),
        ) as unknown as typeof fetch,
      },
    );
    controller.abort();
    const outcome = await pending;
    expect(outcome.kind).toBe("unreachable");
    expect(outcome.kind !== "proof" && outcome.detail).not.toContain("no answer within");
  });
});
