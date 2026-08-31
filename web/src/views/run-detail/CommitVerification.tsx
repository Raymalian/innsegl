// SPDX-License-Identifier: Apache-2.0

/*
 * doc 06 §3.3's per-commit three-check panel, and the honest account of where
 * the proof in it came from.
 *
 * The panel itself is `components/verification`'s and is composed, not
 * rebuilt. What this file owns is the one thing that component cannot know
 * about itself: whether the proof it is rendering is the result of a check
 * that just ran.
 *
 * ── THE TEMPTATION THIS FILE IS WRITTEN AGAINST ────────────────────────────
 *
 * A run detail shows every commit a run made. The obvious implementation
 * fetches every proof when the page loads, keeps them, and renders green
 * badges down the side of the timeline. Two things are wrong with it and the
 * second is the serious one:
 *
 *   - it fires a live Fulcio and Rekor round trip per commit for a reader who
 *     may only want to know when the run ended;
 *   - every one of those greens goes on ageing after it is fetched, and a
 *     green that no live check currently confirms is doc 06 §8's first
 *     anti-pattern — "a 'verified' state rendered from cache while the live
 *     check errored" — arriving by the back door of time rather than of error.
 *
 * So:
 *
 *   1. Nothing is fetched until a reader opens a commit's verification. The
 *      disclosure is a real button with `aria-expanded`, and the fetching
 *      component is UNMOUNTED while it is closed, so closing a panel discards
 *      the proof rather than parking it.
 *
 *   2. While a proof is held, `liveness` is `{ source: "live" }` only inside
 *      `freshnessMs` of the check that produced it. `verdictOf` reads `live`
 *      as "this proof is the result of a check that just ran", and after the
 *      bound that sentence is no longer true — so the liveness becomes
 *      `{ source: "cache" }`, the panel downgrades a verified rollup to
 *      unavailable, and it prints the reason in words: "This result was not
 *      produced by a live check". The reader is offered a re-check.
 *
 *   3. If a re-check fails while a proof is still on screen, the proof stays
 *      (it is evidence, and hiding it helps nobody) and the liveness carries
 *      BOTH `{ source: "cache" }` and the live error. That is doc 07's FE-003
 *      exactly, arising in a real view rather than in a fixture.
 *
 * The downgrade runs one way, and that is `verdictOf`'s guarantee rather than
 * this file's: a failed check does not become "unavailable" because the
 * network went down. doc 06 §8's second anti-pattern forbids the collapse, and
 * a mismatch that stopped being loud is a mismatch nobody acts on (P3).
 */

import { useCallback, useEffect, useId, useRef, useState } from "react";

import { ErrorState } from "../../components/common/ErrorState";
import { LoadingState } from "../../components/common/LoadingState";
import { VerificationPanel } from "../../components/verification";
import type { Liveness, Proof } from "../../components/verification";
import { strings } from "./strings";
import { disclosure, focusRing, hairline } from "./styles";

/**
 * How long a proof stays live.
 *
 * One minute, and the number is a judgement rather than a measurement: it is
 * long enough that opening a panel and reading it is one live check, short
 * enough that a tab left open over lunch cannot show a green nothing has
 * confirmed since. There is no correct value; there is only the difference
 * between having a bound and not having one.
 */
export const DEFAULT_FRESHNESS_MS = 60_000;

/** How a proof is obtained. Injected, so a test never touches the network and
 * a deployment can route through its own BFF. */
export type VerifyCommit = (
  commitSHA: string,
  signal: AbortSignal,
) => Promise<Proof>;

/** The default: `internal/api`'s live proof endpoint, which runs the three
 * checks against Fulcio and Rekor on every request and holds no cache. */
export const fetchProof: VerifyCommit = async (commitSHA, signal) => {
  const response = await fetch(
    `/api/v1/proof/${encodeURIComponent(commitSHA)}`,
    { signal },
  );
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return (await response.json()) as Proof;
};

export interface CommitVerificationProps {
  readonly commitSHA: string;
  readonly verifyCommit: VerifyCommit;
  readonly freshnessMs?: number;
}

/** The disclosure. Closed, this component holds no proof at all. */
export function CommitVerification({
  commitSHA,
  verifyCommit,
  freshnessMs = DEFAULT_FRESHNESS_MS,
}: CommitVerificationProps) {
  const panelId = useId();
  const [open, setOpen] = useState(false);

  return (
    <div className="flex flex-col gap-2">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((was) => !was)}
        className={`${disclosure} ${focusRing} ${hairline} self-start rounded-sm px-2 py-1`}
      >
        {strings.verification.expand}
      </button>
      <div id={panelId}>
        {open ? (
          <LiveVerification
            commitSHA={commitSHA}
            verifyCommit={verifyCommit}
            freshnessMs={freshnessMs}
          />
        ) : null}
      </div>
    </div>
  );
}

type Held =
  | { readonly state: "loading" }
  | { readonly state: "held"; readonly proof: Proof; readonly liveError?: string }
  | { readonly state: "failed"; readonly error: string };

function LiveVerification({
  commitSHA,
  verifyCommit,
  freshnessMs,
}: {
  readonly commitSHA: string;
  readonly verifyCommit: VerifyCommit;
  readonly freshnessMs: number;
}) {
  const [held, setHeld] = useState<Held>({ state: "loading" });
  /* True once the proof on screen is older than the bound. It is state rather
   * than a comparison against a clock at render time so that the transition
   * out of "live" happens on its own, without a reader interacting. */
  const [stale, setStale] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const held0 = useRef(held);
  held0.current = held;

  useEffect(() => {
    const controller = new AbortController();
    let live = true;
    setStale(false);
    void (async () => {
      try {
        const proof = await verifyCommit(commitSHA, controller.signal);
        if (live) setHeld({ state: "held", proof });
      } catch (cause) {
        if (!live) return;
        const message = cause instanceof Error ? cause.message : String(cause);
        const previous = held0.current;
        /* A failed re-check does not remove evidence already on screen; it
         * removes the claim that the evidence is current. */
        setHeld(
          previous.state === "held"
            ? { state: "held", proof: previous.proof, liveError: message }
            : { state: "failed", error: message },
        );
      }
    })();
    return () => {
      live = false;
      controller.abort();
    };
  }, [commitSHA, verifyCommit, attempt]);

  useEffect(() => {
    if (held.state !== "held" || stale) return undefined;
    const timer = setTimeout(() => setStale(true), freshnessMs);
    return () => clearTimeout(timer);
  }, [held.state, stale, freshnessMs]);

  const recheck = useCallback(() => setAttempt((n) => n + 1), []);

  if (held.state === "loading") {
    return <LoadingState what={strings.verification.loading} onRetry={recheck} />;
  }
  if (held.state === "failed") {
    return (
      <ErrorState
        title={strings.verification.unavailable}
        detail={held.error}
        onRetry={recheck}
      />
    );
  }

  /*
   * The one place in this view where a liveness is decided, and the whole of
   * the decision.
   *
   * `live` is claimed only for a proof this component fetched and has held for
   * less than the bound. Every other case — the bound passed, a re-check
   * errored — is `cache`, which is `verdictOf`'s cue to withhold the green and
   * say why.
   */
  const retained = stale || held.liveError !== undefined;
  const liveness: Liveness = retained
    ? {
        source: "cache",
        ...(held.liveError === undefined ? {} : { liveError: held.liveError }),
      }
    : { source: "live" };

  return (
    <div className="flex flex-col gap-2">
      <VerificationPanel proof={held.proof} liveness={liveness} />
      <p className="flex flex-wrap items-center gap-2">
        {/* Why a result is retained is the panel's own downgrade notice, which
          * names every reason including a live error. The one reason the panel
          * cannot know is the bound, so this states that.
          *
          * The re-check is offered unconditionally, and that is doc 06 P5:
          * "any verification the dashboard performs, a user must be able to
          * reproduce". A control that appears only once a result has gone
          * stale is a control the reader cannot use to confirm a result they
          * are looking at now. It is a read, so it does not offend P6. */}
        {stale ? <span>{strings.verification.stale}</span> : null}
        <button
          type="button"
          onClick={recheck}
          className={`${focusRing} rounded-sm underline underline-offset-2`}
        >
          {strings.verification.refresh}
        </button>
      </p>
    </div>
  );
}
