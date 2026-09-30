// SPDX-License-Identifier: Apache-2.0

/*
 * The commit card under the step that made it — Main.dc.html. Reuses the
 * real verification material (`components/verification`'s rollup and tri-
 * state types) and the real proof endpoint; nothing about the rollup is
 * reimplemented here, only the layout the mockup shows: an icon, "Commit",
 * the SHA, the subject, the verdict badge, the three named checks in a row,
 * and a footer naming who signed it with a link to verify independently
 * (doc 06 P5).
 *
 * Unlike run-detail's `CommitVerification`, this card is not behind a
 * disclosure — the mockup renders it open, and a run page shows at most a
 * handful of commits (one per step that made one), not the dozens a repo
 * view might. The proof is fetched once, on mount, and held for as long as
 * the card is on screen.
 */

import { useEffect, useState } from "react";

import { IdentifierChip } from "../../components/common/IdentifierChip";
import { VerificationBadge, rollupChecks } from "../../components/verification";
import type { Check, CheckId, Proof } from "../../components/verification";
import { CHECK_IDS, checkIdOf } from "../../components/verification";
import { routeToPath } from "../../app/routes";
import type { FetchProof } from "./api";
import { CommitIcon } from "./icons";
import { strings } from "./strings";
import {
  checkGrid,
  checkLabel,
  checkResult,
  checkResultFailed,
  checkResultOk,
  checkResultUnavailable,
  commitCard,
  commitCardFooter,
  commitCardHeadRow,
  commitCardSha,
  commitCardSubject,
  commitCardTitle,
  link,
  mutedText,
} from "./styles";
import type { RecordCommit } from "./types";

export interface CommitCardProps {
  readonly commit: RecordCommit;
  readonly branch: string;
  readonly repo?: string;
  readonly fetchProof: FetchProof;
}

type Read =
  | { readonly status: "loading" }
  | { readonly status: "loaded"; readonly proof: Proof }
  | { readonly status: "failed"; readonly error: string };

export function CommitCard({ commit, repo, fetchProof }: CommitCardProps) {
  const [state, setState] = useState<Read>({ status: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    let live = true;
    setState({ status: "loading" });
    fetchProof(commit.sha, controller.signal).then(
      (proof) => {
        if (live) setState({ status: "loaded", proof });
      },
      (cause: unknown) => {
        if (live) setState({ status: "failed", error: cause instanceof Error ? cause.message : String(cause) });
      },
    );
    return () => {
      live = false;
      controller.abort();
    };
  }, [commit.sha, fetchProof]);

  return (
    <div id={`commit-${commit.sha}`} className={commitCard} data-commit-sha={commit.sha}>
      <div className={commitCardHeadRow}>
        <CommitIcon />
        <span className={commitCardTitle}>{strings.commitCard.heading}</span>
        <button
          type="button"
          aria-label={strings.commitCard.copyCommitSha(commit.sha)}
          onClick={() => void navigator.clipboard?.writeText(commit.sha)}
          className={commitCardSha}
        >
          {commit.sha.slice(0, 7)}
        </button>
        <span className={commitCardSubject}>{commit.subject}</span>
        <span className="flex-grow" />
        {state.status === "loaded" ? (
          <VerificationBadge verdict={rollupChecks(state.proof.checks)} />
        ) : null}
      </div>

      {state.status === "loading" ? (
        <p role="status" aria-busy="true" className={`p-3 text-micro ${mutedText}`}>
          {strings.commitCard.loading}
        </p>
      ) : null}
      {state.status === "failed" ? (
        <p role="alert" className="p-3 text-micro text-ink-secondary">
          {strings.commitCard.unavailable}
          {strings.punctuation.dash}
          {state.error}
        </p>
      ) : null}
      {state.status === "loaded" ? <CheckRow proof={state.proof} /> : null}

      <div className={commitCardFooter}>
        <span>{strings.commitCard.signedBy}</span>
        <span className="flex-grow" />
        <a href={routeToPath({ view: "verify", commit: commit.sha, repo: repo ?? "" })} className={link}>
          {strings.commitCard.verifyYourself}
        </a>
      </div>
    </div>
  );
}

const CHECK_LABEL: Record<CheckId, string> = {
  certificateChain: strings.commitCard.check1,
  rekorInclusion: strings.commitCard.check2,
  trailerIdentity: strings.commitCard.check3,
};

function toneFor(result: Check["result"]): string {
  return result === "verified" ? checkResultOk : result === "failed" ? checkResultFailed : checkResultUnavailable;
}

function CheckRow({ proof }: { readonly proof: Proof }) {
  return (
    <dl className={checkGrid}>
      {CHECK_IDS.map((id) => {
        const found = proof.checks.find((c) => checkIdOf(c.name) === id);
        const result = found?.result ?? "unavailable";
        return (
          <div key={id}>
            <dt className={checkLabel}>{CHECK_LABEL[id]}</dt>
            <dd className={`${checkResult} ${toneFor(result)}`}>
              <CheckGlyph result={result} />
              <CheckValue id={id} result={result} proof={proof} />
            </dd>
          </div>
        );
      })}
    </dl>
  );
}

function CheckGlyph({ result }: { readonly result: Check["result"] }) {
  return (
    <svg aria-hidden="true" focusable="false" viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth={2.6}>
      {result === "verified" ? (
        <path d="M4 12l5 5L20 6" strokeLinecap="round" strokeLinejoin="round" />
      ) : result === "failed" ? (
        <path d="M6 6l12 12M18 6L6 18" strokeLinecap="round" />
      ) : (
        <path d="M12 8v5M12 16.5v.5" strokeLinecap="round" />
      )}
    </svg>
  );
}

function CheckValue({
  id,
  result,
  proof,
}: {
  readonly id: CheckId;
  readonly result: Check["result"];
  readonly proof: Proof;
}) {
  if (result !== "verified") {
    const label = result === "failed" ? strings.commitCard.checkFailed : strings.commitCard.checkUnavailable;
    return <span>{label}</span>;
  }
  if (id === "certificateChain") return <span>{strings.commitCard.valid}</span>;
  if (id === "rekorInclusion") {
    return (
      <span>
        {strings.commitCard.provenAtIndexPrefix}
        <IdentifierChip value={String(proof.entry.log_index)} kind="rekor" />
      </span>
    );
  }
  return <span>{strings.commitCard.sameIdentity}</span>;
}
