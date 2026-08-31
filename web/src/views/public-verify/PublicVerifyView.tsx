// SPDX-License-Identifier: Apache-2.0

/*
 * doc 06 §3.6 — the public verification page.
 *
 *   "Anonymous, no auth, shareable URL. Input: a commit SHA (optionally repo).
 *    Output: the full proof chain ... Performs LIVE checks against
 *    Fulcio/Rekor. If they are unreachable, it says exactly that (P2) and
 *    offers nothing database-only in their place. This page is the
 *    adoptability showcase: it must work as a standalone artifact someone
 *    screenshots into an audit report."
 *
 * ── THE ONE PROPERTY THIS FILE EXISTS TO GUARANTEE ─────────────────────────
 *
 * I5: "Verification never trusts this system. Every attribution claim must be
 * checkable against Fulcio/Rekor by a third party with no access to our
 * database." IP §6.11's frontend clause: this page "never downgrades to
 * database-only 'trust us' answers".
 *
 * That is a claim about every code path, not about the happy one, so it is
 * built as three structural facts rather than as three careful branches:
 *
 *   1. A VERDICT HAS ONE SOURCE. `ProofChain` renders exactly one
 *      `VerificationPanel` and this view renders exactly one `ProofChain`.
 *      Nothing else in the directory renders a verification word, a
 *      verification colour or a verification icon, so there is no second path
 *      to a badge that could disagree with the checks.
 *
 *   2. A FAILED REQUEST CARRIES NO PROOF. `ProofOutcome` is a discriminated
 *      union in which exactly one member has a `proof` field. The four failure
 *      members have nothing to render a panel from — not "we choose not to
 *      render one", but "there is no value with which to".
 *
 *   3. A SUPERSEDED ANSWER IS GONE BEFORE THE NEXT ONE ARRIVES. The rendered
 *      phase is keyed on the request, and the key is compared DURING RENDER,
 *      not in an effect. So the frame in which a reader submits a new commit
 *      is already the frame in which the previous verdict has left the page.
 *      An effect-based reset would leave one paint in which a green from the
 *      last commit sits above a live check that has not run yet, which is doc
 *      06 §8's anti-pattern 1 with a shorter lifetime rather than an absent
 *      one.
 *
 *      Honest limit on that last sentence: FE-007 proves the OBSERVABLE half
 *      — that no verdict is on the page while the next request is outstanding
 *      — by making the second request never answer. It does not prove the
 *      render-versus-effect distinction, and cannot: React flushes effects
 *      inside `act`, so in jsdom the two are the same. The render-time reset
 *      is kept because it is right in a browser, not because a test caught
 *      the alternative. Deleting the reset outright DOES fail FE-007, which
 *      was measured by deleting it.
 *
 * And `liveness` is passed by `livenessOf`, which is where the fourth fact
 * lives: a response that never mentions an upstream is not a response that
 * reached one.
 *
 * ── WHAT A "STANDALONE ARTIFACT" COSTS THIS FILE ───────────────────────────
 *
 * ADR-0038 decision 1 says this page ships "no React, no Lit, no framework
 * runtime — it is HTML plus tokens.css", and doc 06 §4.1 puts the React
 * three-check panel on it. The two cannot both be true and the conflict is
 * awaiting a human ruling (raised by RM-043, reported again by RM-048).
 *
 * This is the React build, so that the wave is not blocked. What it does NOT
 * do is take anything from the dashboard it would not need standalone: no
 * string context, no theme context, no staleness provider, no shell. Its
 * imports are React, four presentational components, the three-check panel,
 * the route table and the history-based router — and the last two are the only
 * ones a framework-free build would have to replace, because the browser
 * already has both.
 */

import { useEffect, useId, useState, type FormEvent } from "react";

import { EmptyState } from "../../components/common/EmptyState";
import { ErrorState } from "../../components/common/ErrorState";
import { LoadingState } from "../../components/common/LoadingState";
import { navigate, useRoute } from "../../app/router";
import type { Route } from "../../app/routes";
import { ProofChain } from "./ProofChain";
import { fetchProof } from "./client";
import type { ProofOutcome } from "./client";
import { strings } from "./strings";
import {
  fieldInput,
  fieldLabel,
  fieldStack,
  focusRing,
  identifierText,
  pageHeading,
  pageShell,
  proseText,
  secondaryText,
  submitButton,
} from "./styles";

/** What is on screen, for exactly one request. */
type Phase =
  | { readonly status: "idle" }
  | { readonly status: "loading" }
  | { readonly status: "settled"; readonly outcome: ProofOutcome };

export interface PublicVerifyViewProps {
  /** The shell passes the current route; standalone, the router supplies it.
   * doc 06 §7: "every view's state ... lives in the URL", so the submitted
   * commit is an address and not a field somebody typed into a form. */
  readonly route?: Route;
  /** Bound on one request. The default lives in the client. */
  readonly timeoutMs?: number;
}

/** The commit and repository an address names, or two empty strings. */
function inputFrom(route: Route): { commit: string; repo: string } {
  if (route.view !== "verify") return { commit: "", repo: "" };
  return { commit: route.commit.trim(), repo: route.repo.trim() };
}

export function PublicVerifyView({ route, timeoutMs }: PublicVerifyViewProps) {
  const routed = useRoute();
  const active = inputFrom(route ?? routed);
  const headingId = useId();
  const commitId = useId();
  const commitHintId = useId();
  const repoId = useId();
  const repoHintId = useId();

  // Re-submitting the same address is a new live check, not a no-op: the
  // question this page answers is "what do Fulcio and Rekor say NOW".
  const [attempt, setAttempt] = useState(0);
  const address = `${active.commit} ${active.repo}`;
  const key = `${address} ${attempt}`;

  const [draft, setDraft] = useState(() => ({
    commit: active.commit,
    repo: active.repo,
  }));
  const [seed, setSeed] = useState(address);
  if (seed !== address) {
    setSeed(address);
    setDraft({ commit: active.commit, repo: active.repo });
  }

  const [shown, setShown] = useState<{ key: string; phase: Phase }>(() => ({
    key,
    phase: { status: active.commit === "" ? "idle" : "loading" },
  }));
  // Fact 3 in the file comment: the reset happens here, during render, so no
  // paint ever carries the previous commit's verdict over a request that has
  // not answered.
  if (shown.key !== key) {
    setShown({ key, phase: { status: active.commit === "" ? "idle" : "loading" } });
  }

  useEffect(() => {
    if (active.commit === "") return undefined;
    const controller = new AbortController();
    let current = true;
    void fetchProof(
      { commit: active.commit, repo: active.repo },
      {
        signal: controller.signal,
        ...(timeoutMs === undefined ? {} : { timeoutMs }),
      },
    ).then((outcome) => {
      if (current) setShown({ key, phase: { status: "settled", outcome } });
    });
    return () => {
      current = false;
      controller.abort();
    };
  }, [active.commit, active.repo, key, timeoutMs]);

  const retry = () => setAttempt((n) => n + 1);

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    navigate({
      view: "verify",
      commit: draft.commit.trim(),
      repo: draft.repo.trim(),
    });
    setAttempt((n) => n + 1);
  };

  return (
    <section aria-labelledby={headingId} className={pageShell}>
      <h1 id={headingId} className={pageHeading}>
        {strings.page.heading}
      </h1>
      <p className={proseText}>{strings.page.intro}</p>

      <form onSubmit={submit} className="flex flex-col gap-3">
        <div className={fieldStack}>
          <label htmlFor={commitId} className={fieldLabel}>
            {strings.form.commitLabel}
          </label>
          <input
            id={commitId}
            name="commit"
            type="text"
            spellCheck={false}
            autoComplete="off"
            aria-describedby={commitHintId}
            value={draft.commit}
            onChange={(event) =>
              setDraft((d) => ({ ...d, commit: event.target.value }))
            }
            className={`${fieldInput} ${focusRing}`}
          />
          <span id={commitHintId} className={secondaryText}>
            {strings.form.commitHint}
          </span>
        </div>

        <div className={fieldStack}>
          <label htmlFor={repoId} className={fieldLabel}>
            {strings.form.repoLabel}
          </label>
          <input
            id={repoId}
            name="repo"
            type="text"
            spellCheck={false}
            autoComplete="off"
            aria-describedby={repoHintId}
            value={draft.repo}
            onChange={(event) => setDraft((d) => ({ ...d, repo: event.target.value }))}
            className={`${fieldInput} ${focusRing}`}
          />
          <span id={repoHintId} className={secondaryText}>
            {strings.form.repoHint}
          </span>
        </div>

        <button type="submit" className={`${submitButton} ${focusRing}`}>
          {strings.form.submit}
        </button>
      </form>

      <Result phase={shown.phase} onRetry={retry} />
    </section>
  );
}

function Result({
  phase,
  onRetry,
}: {
  readonly phase: Phase;
  readonly onRetry: () => void;
}) {
  if (phase.status === "idle") {
    return (
      <EmptyState title={strings.form.idleTitle} detail={strings.form.idleDetail} />
    );
  }
  if (phase.status === "loading") {
    return <LoadingState what={strings.page.what} onRetry={onRetry} />;
  }
  const outcome = phase.outcome;
  if (outcome.kind === "proof") {
    return (
      <ProofChain proof={outcome.proof} findings={outcome.findings} onRetry={onRetry} />
    );
  }
  return <Failure outcome={outcome} onRetry={onRetry} />;
}

/**
 * The four ways this page gets no proof, told apart.
 *
 * doc 06 P2 is the reason they are four and not one: "Can't reach this
 * deployment" and "this deployment's answer is not a proof" call for different
 * actions by the reader, and a single "something went wrong" would have told
 * neither. The deployment's own sentence is rendered verbatim underneath,
 * because doc 06 §6.1 asks copy to say what failed and it is the deployment
 * that knows.
 */
const FAILURE_COPY: Record<
  Exclude<ProofOutcome["kind"], "proof">,
  { readonly title: string; readonly detail: string }
> = {
  "not-found": {
    title: strings.failure.notFoundTitle,
    detail: strings.failure.unreachableDetail,
  },
  rejected: {
    title: strings.failure.rejectedTitle,
    detail: strings.failure.unreachableDetail,
  },
  unreachable: {
    title: strings.failure.unreachableTitle,
    detail: strings.failure.unreachableDetail,
  },
  malformed: {
    title: strings.failure.malformedTitle,
    detail: strings.failure.malformedDetail,
  },
};

function Failure({
  outcome,
  onRetry,
}: {
  readonly outcome: Exclude<ProofOutcome, { kind: "proof" }>;
  readonly onRetry: () => void;
}) {
  const copy = FAILURE_COPY[outcome.kind];
  return (
    <div className="flex flex-col gap-2">
      <ErrorState title={copy.title} detail={copy.detail} onRetry={onRetry} />
      <p className={identifierText}>{outcome.detail}</p>
    </div>
  );
}
