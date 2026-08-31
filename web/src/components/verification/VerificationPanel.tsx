// SPDX-License-Identifier: Apache-2.0

/*
 * The three-check verification panel — doc 06 §4.1. The load-bearing component
 * of the dashboard, and the only one in the product entitled to render green.
 *
 *   "Three named checks, each with its own tri-state result:
 *      1. Fulcio certificate chain valid
 *      2. Rekor inclusion proven (with log index shown)
 *      3. Trailer matches certificate identity (both values shown side by
 *         side; on mismatch, the differing segment is highlighted)
 *    Rules: the three checks never collapse into a single icon at detail
 *    level; a summary badge may roll them up in tables but always expands to
 *    the panel. Any single check failing makes the rollup failed. Any check
 *    erroring (not failing) makes the rollup unavailable, never 'verified.'"
 *
 * ── WHAT THIS COMPONENT REFUSES TO DO ──────────────────────────────────────
 *
 * It does not read `proof.verdict` for its badge. The verdict is rolled up
 * here, from the checks in front of the reader, by `verdictOf` — doc 06 P1,
 * evidence over assertion. A response that asserts "verified" over a failed
 * check is answered with the failed check.
 *
 * It does not spend a green on anything but a live verification. `verdictOf`
 * holds five separate conditions between passing checks and a green, and a
 * passing check inside a panel that did not verify keeps its word and its icon
 * and loses its colour: doc 06 P3 says failure is loud, and two green ticks
 * beside a forged trailer are the picture a forger wants a reviewer to skim.
 *
 * It does not collapse anything. Every check renders its own name, its own
 * tri-state word and its own icon, including when all three say the same
 * thing, and including a check name this build does not recognise — which is
 * rendered under the server's spelling rather than dropped.
 *
 * ── WHAT IT IS NOT ─────────────────────────────────────────────────────────
 *
 * There is no fetch here, no cache, and no state. A caller hands it a proof
 * and says where the proof came from; everything else is a function of those
 * two. That is what makes doc 06's anti-pattern 1 testable rather than
 * hopeful — FE-003 hands it a cached verified proof and a live error and
 * requires the amber.
 */

import { useId } from "react";

import { AlertBanner } from "../common/AlertBanner";
import { IdentifierChip } from "../common/IdentifierChip";
import { Icon } from "../common/Icon";
import { IdentityComparison } from "./IdentityComparison";
import { ProofIcon } from "./ProofIcon";
import { verdictOf } from "./rollup";
import type { Liveness, Rollup } from "./rollup";
import { strings } from "./strings";
import {
  badgeBase,
  checkRow,
  degradedNotice,
  hairline,
  identifierText,
  link,
  mutedText,
  noticeBase,
  noticeBody,
  noticeTitle,
  panelShell,
  proofFailed,
  proofNeutral,
  proofUnavailable,
  proofVerified,
  secondaryText,
  srOnly,
} from "./styles";
import type { Check, CheckId, CheckResult, Finding, Proof, Verdict } from "./types";
import { checkIdOf } from "./types";

export interface VerificationPanelProps {
  readonly proof: Proof;
  /** Where the proof came from, and what the live attempt did. Omitted means
   * live: the BFF holds no cache, so a caller with nothing to say has one. */
  readonly liveness?: Liveness;
  /** The re-derivation `internal/api` performs against the response's own
   * material. A contradiction convicts the responder, so it withholds the
   * green. */
  readonly findings?: readonly Finding[];
  /** Stable prefix for the panel's ids, so a page holding several panels can
   * link to the right one. */
  readonly id?: string;
}

export function VerificationPanel({ proof, liveness, findings, id }: VerificationPanelProps) {
  const generated = useId();
  const anchor = id ?? generated;
  const rollup = verdictOf(proof, liveness, findings);

  const trailer = proof.claim.identity ?? "";
  const certificate = proof.certificate.spiffe_id ?? "";
  const identityCheck = proof.checks.find(
    (check) => checkIdOf(check.name) === "trailerIdentity",
  );
  const comparison =
    trailer === "" && certificate === "" ? null : (
      <IdentityComparison
        id={`${anchor}-identity`}
        trailer={trailer}
        certificate={certificate}
      />
    );
  // The alarm is raised by the CHECK, not by this component's own reading of
  // two strings: the verdict belongs to internal/verify and nothing here
  // upgrades or downgrades one.
  const mismatch = identityCheck?.result === "failed" && trailer !== certificate;

  return (
    <section aria-labelledby={`${anchor}-heading`} className={panelShell}>
      <div className="flex flex-wrap items-center gap-3">
        <h2 id={`${anchor}-heading`} className="text-heading font-semibold leading-tight">
          {strings.panel.heading}
        </h2>
        <VerdictBadge verdict={rollup.verdict} />
        <span className={mutedText}>{strings.panel.commit}</span>
        <IdentifierChip value={proof.commit_sha} kind="sha" />
      </div>

      {/* doc 06 P3: design the alarm first. */}
      {mismatch ? (
        <AlertBanner
          alerts={[
            {
              id: `${anchor}-mismatch`,
              kind: "integrity",
              title: strings.mismatch.title,
              detail: strings.mismatch.detail,
              evidenceHref: `#${anchor}-identity`,
              evidenceLabel: strings.mismatch.evidence,
            },
          ]}
        />
      ) : null}

      {rollup.downgraded ? <Downgrade rollup={rollup} /> : null}

      <ul className="flex list-none flex-col gap-2 p-0">
        {proof.checks.map((check, index) => (
          <CheckItem
            key={`${index}-${check.name}`}
            check={check}
            verdict={rollup.verdict}
            logIndex={proof.entry.log_index}
            hasEntry={(proof.entry.uuid ?? "") !== "" || proof.entry.log_index > 0}
          >
            {checkIdOf(check.name) === "trailerIdentity" ? comparison : null}
          </CheckItem>
        ))}
      </ul>

      {/* A comparison with no check to sit under still belongs on the page. */}
      {identityCheck === undefined ? comparison : null}

      <Unreachable proof={proof} />
      <Notes proof={proof} />
      <RawMaterial proof={proof} />
    </section>
  );
}

/* ── the rollup badge ─────────────────────────────────────────────────────── */

const VERDICT_TONE: Record<Verdict, string> = {
  verified: proofVerified,
  failed: proofFailed,
  unavailable: proofUnavailable,
  unattributed: proofNeutral,
};

function VerdictBadge({ verdict }: { readonly verdict: Verdict }) {
  const { label, meaning } = strings.verdict[verdict];
  return (
    <span
      data-verdict={verdict}
      title={meaning}
      className={`${badgeBase} ${hairline} ${VERDICT_TONE[verdict]}`}
    >
      <ProofIcon verdict={verdict} className="shrink-0" />
      <span>{label}</span>
      <span className={srOnly}>{meaning}</span>
    </span>
  );
}

/* ── one check ────────────────────────────────────────────────────────────── */

const RESULT_TONE: Record<CheckResult, string> = {
  verified: proofVerified,
  failed: proofFailed,
  unavailable: proofUnavailable,
};

const CHECK_LABELS: Record<CheckId, string> = {
  certificateChain: strings.checks.certificateChain,
  rekorInclusion: strings.checks.rekorInclusion,
  trailerIdentity: strings.checks.trailerIdentity,
};

function CheckItem({
  check,
  verdict,
  logIndex,
  hasEntry,
  children,
}: {
  readonly check: Check;
  readonly verdict: Verdict;
  readonly logIndex: number;
  readonly hasEntry: boolean;
  readonly children?: React.ReactNode;
}) {
  const id = checkIdOf(check.name);
  // A check name this build does not know is rendered under the server's own
  // spelling. Dropping it would be hiding a result.
  const label = id === undefined ? check.name : CHECK_LABELS[id];
  const { label: word, meaning } = strings.result[check.result];
  // The green belongs to the panel, not to the row (see the file comment).
  const tone =
    check.result === "verified" && verdict !== "verified"
      ? proofNeutral
      : RESULT_TONE[check.result];

  return (
    <li data-check={id ?? "unrecognised"} data-check-result={check.result} className={`${checkRow} ${hairline}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{label}</span>
        <span className={`${badgeBase} ${hairline} ${tone}`}>
          <ProofIcon verdict={check.result} className="shrink-0" />
          <span>{word}</span>
          <span className={srOnly}>{meaning}</span>
        </span>
      </div>

      {check.detail === undefined || check.detail === "" ? null : (
        <p className={secondaryText}>{check.detail}</p>
      )}

      {/* doc 06 §4.1: "Rekor inclusion proven (with log index shown)". */}
      {id === "rekorInclusion" ? (
        hasEntry ? (
          <div className="flex flex-wrap items-center gap-2">
            <span className={mutedText}>{strings.checks.logIndex}</span>
            <IdentifierChip value={String(logIndex)} kind="rekor" />
          </div>
        ) : (
          <p className={secondaryText}>{strings.checks.noLogIndex}</p>
        )
      ) : null}

      <Facts check={check} />
      {children}
    </li>
  );
}

/** doc 06 P1: a badge with no expandable proof is an assertion, not evidence. */
function Facts({ check }: { readonly check: Check }) {
  const facts = check.facts ?? [];
  if (facts.length === 0) return null;
  return (
    <dl className="flex flex-col gap-1">
      {facts.map((fact, index) => (
        <div key={`${index}-${fact.name}`} className="flex flex-wrap gap-2">
          <dt className={mutedText}>{fact.name}</dt>
          <dd className={identifierText}>{fact.value}</dd>
        </div>
      ))}
    </dl>
  );
}

/* ── why a set of passing checks is not a verdict ─────────────────────────── */

function Downgrade({ rollup }: { readonly rollup: Rollup }) {
  return (
    <div role="status" className={`${noticeBase} ${hairline} ${degradedNotice}`}>
      <ProofIcon verdict="unavailable" className="mt-[0.3em] shrink-0" />
      <span className={noticeBody}>
        <span className={noticeTitle}>{strings.downgrade.heading}</span>
        {rollup.reasons.map((reason) => (
          <span key={reason}>{strings.downgrade[reason]}</span>
        ))}
        {rollup.errors.map((error, index) => (
          <span key={`${index}-${error}`} className={identifierText}>
            {error}
          </span>
        ))}
      </span>
    </div>
  );
}

/* ── the material, and the holes in it ────────────────────────────────────── */

function Unreachable({ proof }: { readonly proof: Proof }) {
  const down = proof.upstreams.filter((upstream) => !upstream.reachable);
  if (down.length === 0) return null;
  return (
    <div className="flex flex-col gap-1">
      <h3 className="font-medium">{strings.upstream.heading}</h3>
      <dl className="flex flex-col gap-1">
        {down.map((upstream) => (
          <div key={upstream.name} className="flex flex-wrap items-center gap-2">
            <dt className="flex items-center gap-1">
              <Icon name="unreachable" className="shrink-0" />
              <span>{strings.upstream.unreachable(upstream.name)}</span>
            </dt>
            <dd className={identifierText}>{upstream.error ?? upstream.url}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function Notes({ proof }: { readonly proof: Proof }) {
  const notes = proof.notes ?? [];
  if (notes.length === 0) return null;
  return (
    <div className="flex flex-col gap-1">
      <h3 className="font-medium">{strings.notes.heading}</h3>
      {notes.map((note, index) => (
        <p key={`${index}-${note.slice(0, 16)}`} className={secondaryText}>
          {note}
        </p>
      ))}
    </div>
  );
}

/**
 * doc 06 §3.6 and §7: the response carries the raw inputs and outputs so the
 * reader can re-derive the verdict without the dashboard, and doc 06 P5 makes
 * that a requirement rather than a courtesy. A gap is stated rather than left
 * as an absence — silence about missing evidence reads as "collected and fine".
 */
function RawMaterial({ proof }: { readonly proof: Proof }) {
  const material = proof.material;
  const documents = [
    { label: strings.material.commitObject, value: material.commit_object },
    { label: strings.material.certificate, value: material.certificate_pem },
    { label: strings.material.fulcioRoot, value: material.fulcio_root_pem },
    { label: strings.material.rekorKey, value: material.rekor_log_public_key_pem },
  ].filter((document) => document.value !== undefined && document.value !== "");
  const gaps = material.gaps ?? [];
  if (documents.length === 0 && gaps.length === 0) return null;

  return (
    <details className="flex flex-col gap-2">
      <summary className={link}>{strings.material.heading}</summary>
      <p className={secondaryText}>{strings.material.detail}</p>
      <dl className="flex flex-col gap-2">
        {documents.map((document) => (
          <div key={document.label} className="flex flex-col gap-1">
            <dt className={mutedText}>{document.label}</dt>
            <dd>
              <pre className={`${identifierText} overflow-x-auto`}>{document.value}</pre>
            </dd>
          </div>
        ))}
        {gaps.map((gap) => (
          <div key={gap.name} className="flex flex-col gap-1">
            <dt className={mutedText}>{`${strings.material.gaps}: ${gap.name}`}</dt>
            <dd className={secondaryText}>{gap.reason}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}
