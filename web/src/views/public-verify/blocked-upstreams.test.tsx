// SPDX-License-Identifier: Apache-2.0

/*
 * FE-007 — doc 07: "Public page with Fulcio/Rekor blocked | Explicit
 * 'verification can't run' + offline material; zero database-only verdicts |
 * FD §3.6, P2". doc 07 §I5 lists it as one of the three tests that carry
 * "verification trusts nothing".
 *
 * doc 07 types it (E). This is its frontend half and it is as end-to-end as a
 * browser-side suite can be: `globalThis.fetch` is stubbed, so the real
 * client, the real response parser, the real liveness gate, the real
 * three-check panel and the real rollup all run. Nothing between the wire and
 * the pixels is a double. What is NOT covered here is a real BFF with real
 * Fulcio and Rekor containers taken away — that is E8's, and it is reported as
 * a gap rather than implied by this file's name.
 *
 * ── WHAT "ZERO DATABASE-ONLY VERDICTS" MEANS AS AN ASSERTION ───────────────
 *
 * I5: "Verification never trusts this system. Every attribution claim must be
 * checkable against Fulcio/Rekor by a third party with no access to our
 * database." IP §6.11's frontend consequence: "Public paste-a-SHA page
 * performs live Fulcio/Rekor checks; if it cannot, it says so — it never
 * downgrades to database-only 'trust us' answers."
 *
 * So the property under test is not "the page renders unavailable when the
 * server says unavailable". A server that says unavailable is an honest
 * server. The property is that NO RESPONSE, honest or not, can put a verdict
 * on this page unless both upstreams answered — including a response that
 * asserts `verdict: "verified"` over three passing checks while reporting both
 * upstreams unreachable, and including one that reports no upstream at all.
 *
 * ── HOW A VERDICT IS MEASURED ──────────────────────────────────────────────
 *
 * Three channels, all three of them things a person perceives, because doc 06
 * §6.4 says a verification result is carried by "color + icon + label" and a
 * test that checked one of the three could pass while the other two lied:
 *
 *   the WORD   the badge's own text content
 *   the COLOUR the `proof-verified` token, which ADR-0038 decision 4 makes the
 *              only route to a green anywhere in the build
 *   the SHAPE  the tick-in-a-ring `ProofIcon` draws for a verification, which
 *              is the only place that silhouette appears
 *
 * A `data-*` attribute is used to FIND the badge and never to establish what
 * it says. That distinction is deliberate: this repository has already had one
 * assertion pass because it compared two states by a marker nobody could see.
 *
 * The word and the shape are asserted OF THE ROLLUP BADGE, and the colour of
 * the whole page. The first draft of this file asserted all three of the whole
 * page and failed on an honest render: doc 06 §4.1 forbids collapsing the
 * three checks, so a check that genuinely passed keeps its own word "Verified"
 * and its own tick inside a panel whose rollup is unavailable. Only the colour
 * is withheld from a passing row in a panel that did not verify — which is
 * what components/verification's FE-036 established, and this is the same rule
 * read from the outside.
 */

import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { strings as verification } from "../../components/verification";
import { PublicVerifyView } from "./PublicVerifyView";
import { strings } from "./strings";
import {
  COMMIT_SHA,
  FULCIO_ENDPOINT,
  REFUSED,
  REKOR_ENDPOINT,
  REPO,
  bothUpstreamsBlocked,
  lyingProof,
  silentUpstreamsProof,
  wireProof,
} from "./fixtures";

afterEach(cleanup);

/** Answer every request with this body and status. */
function serve(body: unknown, status = 200): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      new Response(typeof body === "string" ? body : JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      }),
    ),
  );
}

/** The transport itself is gone: no response at all. */
function refuse(message: string): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      throw new TypeError(message);
    }),
  );
}

beforeEach(() => {
  vi.unstubAllGlobals();
});

/**
 * Render the page for one address and wait for the live check to settle.
 *
 * The wait is on `aria-busy`, which `LoadingState` sets and clears, and on the
 * page then carrying either a verdict badge or an alert. Both are real
 * accessibility state rather than a hook added for the test: a marker that
 * existed only for this file would be a marker nothing else could break.
 */
async function show(commit = COMMIT_SHA, repo = REPO) {
  const view = render(
    <PublicVerifyView route={{ view: "verify", commit, repo }} />,
  );
  await waitFor(() => {
    expect(view.container.querySelector('[aria-busy="true"]')).toBeNull();
    expect(
      view.container.querySelector("[data-verdict]") ??
        view.container.querySelector('[role="alert"]'),
    ).not.toBeNull();
  });
  return view;
}

/** The one rollup badge on the page, located structurally and read visibly. */
function verdictBadges(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll<HTMLElement>("[data-verdict]"));
}

/**
 * No verdict of "verified" reaches the reader through any of the three
 * channels doc 06 §6.4 names.
 */
function refusesToClaimVerification(container: HTMLElement): void {
  for (const badge of verdictBadges(container)) {
    // The word, and the shape, on the badge that carries the rollup.
    expect(badge.textContent).not.toContain(verification.verdict.verified.label);
    expect(badge.querySelector('[data-icon="verification-mark"]')).toBeNull();
  }
  // The colour, over the whole page: ADR-0038 decision 4 makes
  // `proof-verified` the only route to a green anywhere in the build, so this
  // one is not scoped to the badge and does not need to be.
  expect(container.innerHTML).not.toContain("proof-verified");
}

describe("FE-007 both upstreams blocked", () => {
  it("says verification can't run, in doc 06 §6.1's own words", async () => {
    serve(bothUpstreamsBlocked());
    const { container } = await show();

    expect(
      screen.getByText(strings.blocked.title("Fulcio, Rekor")),
    ).toBeInTheDocument();
    expect(screen.getByText(strings.blocked.detail)).toBeInTheDocument();
    refusesToClaimVerification(container);
  });

  it("renders verification unavailable, and never failed", async () => {
    serve(bothUpstreamsBlocked());
    const { container } = await show();

    const badges = verdictBadges(container);
    expect(badges).toHaveLength(1);
    expect(badges[0]?.textContent).toContain(
      verification.verdict.unavailable.label,
    );
    // doc 06 §8 anti-pattern 2: failed and unavailable never collapse.
    expect(badges[0]?.textContent).not.toContain(verification.verdict.failed.label);
  });

  it("names each upstream, the endpoint it asked, and what it said", async () => {
    serve(bothUpstreamsBlocked());
    await show();

    for (const endpoint of [FULCIO_ENDPOINT, REKOR_ENDPOINT]) {
      expect(screen.getByText(endpoint)).toBeInTheDocument();
    }
    expect(screen.getAllByText(REFUSED).length).toBeGreaterThanOrEqual(2);
  });

  it("hands over the material that survived, and states what did not", async () => {
    serve(bothUpstreamsBlocked());
    const { container } = await show();

    // The commit object needs no upstream, so it is still here: doc 06 §6.1's
    // "verify offline with the material below" has to be true, not a phrase.
    expect(container.textContent).toContain("Agent-Identity:");
    // And the holes are named rather than left as absences.
    expect(screen.getByText(/fulcio_root_pem/)).toBeInTheDocument();
    expect(screen.getByText(/rekor_log_public_key_pem/)).toBeInTheDocument();
  });
});

describe("FE-007 one upstream blocked", () => {
  it.each([
    ["Fulcio", { fulcioReachable: false }],
    ["Rekor", { rekorReachable: false }],
  ] as const)("%s alone is enough to withhold a verdict", async (_name, opts) => {
    serve(
      wireProof({
        ...opts,
        results: ["verified", "verified", "verified"],
        verdict: "verified",
      }),
    );
    const { container } = await show();
    refusesToClaimVerification(container);
  });
});

describe("FE-007 zero database-only verdicts", () => {
  it("refuses a server that asserts verified over upstreams that never answered", async () => {
    serve(lyingProof());
    const { container } = await show();
    refusesToClaimVerification(container);
    expect(verdictBadges(container)[0]?.textContent).toContain(
      verification.verdict.unavailable.label,
    );
  });

  it("refuses a server that reports no upstream at all", async () => {
    serve(silentUpstreamsProof());
    const { container } = await show();
    refusesToClaimVerification(container);
    expect(screen.getByText(strings.blocked.detail)).toBeInTheDocument();
  });

  it("shows no verdict at all when the deployment itself did not answer", async () => {
    refuse("Failed to fetch");
    const { container } = await show();
    expect(verdictBadges(container)).toHaveLength(0);
    refusesToClaimVerification(container);
    expect(screen.getByRole("alert")).toBeInTheDocument();
  });

  it("shows no verdict at all when the response is not a proof", async () => {
    serve({ verdict: "verified" });
    const { container } = await show();
    expect(verdictBadges(container)).toHaveLength(0);
    refusesToClaimVerification(container);
  });

  it("shows no verdict at all on an HTTP error", async () => {
    serve({ error: { code: "internal", message: "the prover failed" } }, 500);
    const { container } = await show();
    expect(verdictBadges(container)).toHaveLength(0);
    refusesToClaimVerification(container);
  });

  it("drops the previous answer before asking again, so no green survives a blocked check", async () => {
    serve(wireProof());
    const first = await show();
    expect(first.container.innerHTML).toContain("proof-verified");

    serve(bothUpstreamsBlocked());
    await userEvent.click(screen.getByRole("button", { name: strings.form.submit }));
    await waitFor(() => {
      expect(first.container.innerHTML).not.toContain("proof-verified");
    });
    refusesToClaimVerification(first.container);
  });

  /*
   * The same rule at the moment it is hardest to keep, and the reason the
   * reset lives in the render rather than in an effect.
   *
   * doc 06 §8's anti-pattern 1 is "a verified state rendered from cache while
   * the live check errored". A verdict left on screen while its replacement is
   * still in flight is that anti-pattern with a short life rather than an
   * absent one: the reader sees a green above a check that has not run.
   *
   * The mutation this catches, and the one the previous test did NOT: delete
   * the reset entirely and the earlier assertion still passes, because
   * `waitFor` lets the second request resolve before it looks. So the second
   * request is made never to answer, and the page is read while it is
   * outstanding.
   *
   * What this still cannot see, and it is reported rather than implied: React
   * flushes effects inside `act`, so a reset written as an effect is
   * indistinguishable here from one written during render. The render-time
   * reset is kept because it is correct in a browser, not because this proves
   * it.
   */
  it("shows no verdict at all while the next live check is outstanding", async () => {
    serve(wireProof());
    const view = await show();
    expect(view.container.innerHTML).toContain("proof-verified");

    let release: (() => void) | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(
        () =>
          new Promise<Response>((resolve) => {
            release = () => resolve(new Response("{}", { status: 500 }));
          }),
      ),
    );

    await userEvent.click(screen.getByRole("button", { name: strings.form.submit }));

    // Read with the request still outstanding: nothing resolves it above.
    refusesToClaimVerification(view.container);
    expect(verdictBadges(view.container)).toHaveLength(0);
    expect(view.container.querySelector('[aria-busy="true"]')).not.toBeNull();
    release?.();
  });
});

describe("FE-007 the page still verifies when both upstreams answer", () => {
  it("spends a green only then, so the assertions above are not vacuous", async () => {
    serve(wireProof());
    const { container } = await show();
    expect(container.innerHTML).toContain("proof-verified");
    expect(verdictBadges(container)[0]?.textContent).toContain(
      verification.verdict.verified.label,
    );
    expect(
      container.querySelector('[data-icon="verification-mark"]'),
    ).not.toBeNull();
  });
});
