// SPDX-License-Identifier: Apache-2.0

/*
 * The proof chain, as doc 06 §3.6 orders it:
 *
 *   "Output: the full proof chain — trailer contents, certificate identity,
 *    Fulcio chain check, Rekor inclusion proof, match verdict — each step
 *    rendered with its raw material available (cert PEM, log index) for
 *    offline re-verification."
 *
 * ── WHAT THIS COMPONENT DOES NOT DO ────────────────────────────────────────
 *
 * It does not decide anything. The verdict, the three checks, the rollup rule,
 * the identity comparison and the mismatch alarm all belong to
 * components/verification, which is rendered here whole. There is no second
 * rollup on this page, no second reading of `proof.verdict`, and no branch in
 * this file that could put a different word beside a commit than the panel
 * puts. doc 06 §8's anti-pattern 4 is a summary that cannot be expanded; a
 * second summary that could disagree with the panel would be worse.
 *
 * It does not re-derive. `internal/api/rederive.go` re-computes each claim
 * from the response's own bytes and reports agrees/contradicts/underivable;
 * this renders those findings and writes none of its own. A second
 * re-derivation in a second language is a second thing to keep in agreement
 * with `internal/verify`, and the first time the two disagreed this page would
 * be accusing an honest deployment.
 *
 * ── WHAT IT ADDS, AND WHY EACH PIECE IS HERE ───────────────────────────────
 *
 * The panel is built for the dashboard, where a reader already has the run
 * around it. A stranger with a SHA and no context needs four things the panel
 * does not carry, and each of them is named in §3.6 or in the issue:
 *
 *   LIVE CHECKS      which endpoint was asked, when, and what came back. The
 *                    page's whole promise is that the answer is live (P2), and
 *                    a promise with no record of the request is an assertion.
 *   TRAILER CONTENTS all three Agent-* trailers. The panel compares
 *                    Agent-Identity against the certificate; Agent-Run and
 *                    Agent-Task are part of the claim and appear nowhere else.
 *   CERTIFICATE      issuer, serial, validity window, fingerprint — the fields
 *                    a third party needs to find the same certificate.
 *   LOG ENTRY        uuid, index, log id, integration time and whether the log
 *                    SIGNED that time, plus the entry as served.
 *
 * ── THE ALARM IS FIRST ─────────────────────────────────────────────────────
 *
 * doc 06 P3: "Design the alarm first; the calm state is what's left." When an
 * upstream did not answer, the first thing on the page is doc 06 §6.1's own
 * sentence for this exact situation, above the panel rather than inside it.
 */

import { ErrorState } from "../../components/common/ErrorState";
import { IdentifierChip } from "../../components/common/IdentifierChip";
import { Icon } from "../../components/common/Icon";
import { VerificationPanel } from "../../components/verification";
import type {
  Agreement,
  Finding,
  Proof,
  Upstream,
} from "../../components/verification";
import { REQUIRED_UPSTREAMS, livenessOf } from "./liveness";
import { strings, upstreamName } from "./strings";
import {
  factLabel,
  factList,
  factRow,
  identifierText,
  materialBlock,
  proseText,
  secondaryText,
  sectionHeading,
  sectionShell,
  table,
  tableCell,
  tableHeaderCell,
} from "./styles";

export interface ProofChainProps {
  readonly proof: Proof;
  readonly findings: readonly Finding[];
  /** Offered on the blocked notice. A re-read, never a write (doc 06 P6). */
  readonly onRetry?: () => void;
}

export function ProofChain({ proof, findings, onRetry }: ProofChainProps) {
  const reported = new Map(proof.upstreams.map((upstream) => [upstream.name, upstream]));
  const missing = REQUIRED_UPSTREAMS.filter((name) => !reported.has(name));
  const silent = proof.upstreams.filter((upstream) => !upstream.reachable);
  const withheld = [...missing, ...silent.map((upstream) => upstream.name)];

  return (
    <div className={factList}>
      {withheld.length === 0 ? null : (
        <>
          <ErrorState
            title={strings.blocked.title(withheld.map(upstreamName).join(", "))}
            detail={strings.blocked.detail}
            {...(onRetry === undefined ? {} : { onRetry })}
          />
          {missing.length === 0 ? null : (
            <p className={proseText}>
              {strings.blocked.silent(missing.map(upstreamName).join(", "))}
            </p>
          )}
        </>
      )}

      <VerificationPanel
        proof={proof}
        liveness={livenessOf(proof)}
        findings={findings}
        id="proof"
      />

      <LiveChecks proof={proof} missing={missing} />
      <Trailer proof={proof} />
      <Certificate proof={proof} />
      <LogEntry proof={proof} />
      <Rederivation findings={findings} />
      <Offline proof={proof} />
    </div>
  );
}

/* ── a section, and a label/value pair ────────────────────────────────────── */

function Section({
  heading,
  detail,
  children,
}: {
  readonly heading: string;
  readonly detail?: string;
  readonly children: React.ReactNode;
}) {
  return (
    <section className={sectionShell}>
      <h2 className={sectionHeading}>{heading}</h2>
      {detail === undefined ? null : <p className={proseText}>{detail}</p>}
      {children}
    </section>
  );
}

/** One piece of verbatim material, under the name of what it is (doc 06 P4). */
function Fact({
  label,
  value,
  chip,
}: {
  readonly label: string;
  readonly value: string;
  readonly chip?: "spiffe" | "sha" | "rekor" | "generic";
}) {
  return (
    <div className={factRow}>
      <dt className={factLabel}>{label}</dt>
      <dd className={chip === undefined ? identifierText : ""}>
        {chip === undefined ? value : <IdentifierChip value={value} kind={chip} />}
      </dd>
    </div>
  );
}

/* ── live checks ──────────────────────────────────────────────────────────── */

function LiveChecks({
  proof,
  missing,
}: {
  readonly proof: Proof;
  readonly missing: readonly string[];
}) {
  const reported = new Map(proof.upstreams.map((upstream) => [upstream.name, upstream]));
  const rows: Array<{ name: string; upstream: Upstream | undefined }> = [
    ...REQUIRED_UPSTREAMS.map((name) => ({ name, upstream: reported.get(name) })),
    // An upstream this build does not know about is still reported: dropping
    // one would hide a dependency the deployment actually consulted.
    ...proof.upstreams
      .filter((upstream) => !REQUIRED_UPSTREAMS.includes(upstream.name as "fulcio"))
      .map((upstream) => ({ name: upstream.name, upstream })),
  ];

  return (
    <Section heading={strings.liveCheck.heading} detail={strings.liveCheck.detail}>
      <table className={table}>
        <caption className={`${factLabel} text-left`}>
          {strings.liveCheck.tableLabel}
        </caption>
        <thead>
          <tr>
            <th scope="col" className={tableHeaderCell}>
              {strings.liveCheck.upstream}
            </th>
            <th scope="col" className={tableHeaderCell}>
              {strings.liveCheck.endpoint}
            </th>
            <th scope="col" className={tableHeaderCell}>
              {strings.liveCheck.checkedAt}
            </th>
            <th scope="col" className={tableHeaderCell}>
              {strings.liveCheck.outcome}
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map(({ name, upstream }) => (
            <tr key={name}>
              <th scope="row" className={tableCell}>
                {upstreamName(name)}
              </th>
              <td className={`${tableCell} ${identifierText}`}>
                {upstream === undefined ? strings.liveCheck.absent : upstream.url}
              </td>
              <td className={`${tableCell} ${identifierText}`}>
                {upstream === undefined || upstream.checked_at === ""
                  ? strings.liveCheck.absent
                  : upstream.checked_at}
              </td>
              <td className={tableCell}>
                <Outcome upstream={upstream} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {missing.length === 0 ? null : (
        <p className={secondaryText}>
          {strings.blocked.silent(missing.map(upstreamName).join(", "))}
        </p>
      )}
    </Section>
  );
}

/**
 * What one upstream said. Three states and never two: an upstream that
 * answered, one that did not, and one the response never mentioned. doc 06 P2
 * forbids collapsing the third into either of the first two, and it is the
 * collapse a reader would never notice.
 */
function Outcome({ upstream }: { readonly upstream: Upstream | undefined }) {
  if (upstream === undefined) {
    return (
      <span className="flex items-center gap-1">
        <Icon name="unknown" className="shrink-0" />
        <span>{strings.liveCheck.absent}</span>
      </span>
    );
  }
  if (upstream.reachable) {
    return (
      <span className="flex items-center gap-1">
        <Icon name="anchor-pulse" className="shrink-0" />
        <span>{strings.liveCheck.answered}</span>
      </span>
    );
  }
  return (
    <span className="flex flex-col gap-1">
      <span className="flex items-center gap-1">
        <Icon name="unreachable" className="shrink-0" />
        <span>{strings.liveCheck.unanswered}</span>
      </span>
      {upstream.error === undefined || upstream.error === "" ? null : (
        <span className={identifierText}>{upstream.error}</span>
      )}
    </span>
  );
}

/* ── the claim ────────────────────────────────────────────────────────────── */

function Trailer({ proof }: { readonly proof: Proof }) {
  const { identity, run, task } = proof.claim;
  const empty =
    (identity ?? "") === "" && (run ?? "") === "" && (task ?? "") === "";
  return (
    <Section heading={strings.trailer.heading} detail={strings.trailer.detail}>
      {empty ? (
        <p className={proseText}>{strings.trailer.none}</p>
      ) : (
        <dl className={factList}>
          <Fact
            label={strings.trailer.identity}
            value={identity ?? strings.trailer.absent}
            {...((identity ?? "") === "" ? {} : { chip: "spiffe" as const })}
          />
          <Fact label={strings.trailer.run} value={run ?? strings.trailer.absent} />
          <Fact label={strings.trailer.task} value={task ?? strings.trailer.absent} />
        </dl>
      )}
    </Section>
  );
}

/* ── what the certificate proves ──────────────────────────────────────────── */

function Certificate({ proof }: { readonly proof: Proof }) {
  const cert = proof.certificate;
  const fields: Array<[string, string | undefined]> = [
    [strings.certificate.spiffeId, cert.spiffe_id],
    [strings.certificate.issuer, cert.issuer],
    [strings.certificate.serial, cert.serial_number],
    [strings.certificate.notBefore, cert.not_before],
    [strings.certificate.notAfter, cert.not_after],
    [strings.certificate.fingerprint, cert.fingerprint],
  ];
  const present = fields.filter(([, value]) => (value ?? "") !== "");
  return (
    <Section
      heading={strings.certificate.heading}
      detail={strings.certificate.detail}
    >
      {present.length === 0 ? (
        <p className={proseText}>{strings.certificate.none}</p>
      ) : (
        <dl className={factList}>
          {present.map(([label, value]) => (
            <Fact key={label} label={label} value={value ?? ""} />
          ))}
        </dl>
      )}
    </Section>
  );
}

/* ── what the log holds ───────────────────────────────────────────────────── */

function LogEntry({ proof }: { readonly proof: Proof }) {
  const entry = proof.entry;
  const present = (entry.uuid ?? "") !== "" || entry.log_index > 0;
  const raw = proof.material.rekor_entry;
  return (
    <Section heading={strings.entry.heading} detail={strings.entry.detail}>
      {present ? (
        <>
          <dl className={factList}>
            {entry.uuid === undefined ? null : (
              <Fact label={strings.entry.uuid} value={entry.uuid} />
            )}
            <Fact
              label={strings.entry.logIndex}
              value={String(entry.log_index)}
              chip="rekor"
            />
            {entry.log_id === undefined ? null : (
              <Fact label={strings.entry.logId} value={entry.log_id} />
            )}
            {entry.integrated_at === undefined ? null : (
              <Fact label={strings.entry.integratedAt} value={entry.integrated_at} />
            )}
          </dl>
          {/* doc 06 P2: an unsigned integration time is a number in a
            * response, not a statement by the log, and the two must not read
            * the same. */}
          <p className={proseText}>
            {entry.time_attested ? strings.entry.attested : strings.entry.unattested}
          </p>
        </>
      ) : (
        <p className={proseText}>{strings.entry.none}</p>
      )}
      {raw === undefined || raw === null ? null : (
        <div className={factRow}>
          <span className={factLabel}>{strings.entry.raw}</span>
          <pre className={materialBlock}>{JSON.stringify(raw, null, 2)}</pre>
        </div>
      )}
    </Section>
  );
}

/* ── the deployment's own re-derivation ───────────────────────────────────── */

const AGREEMENT_LABELS: Record<Agreement, string> = {
  agrees: strings.rederivation.agrees,
  contradicts: strings.rederivation.contradicts,
  underivable: strings.rederivation.underivable,
};

const AGREEMENT_ICONS: Record<Agreement, "status-active" | "integrity-alert" | "unknown"> = {
  agrees: "status-active",
  contradicts: "integrity-alert",
  underivable: "unknown",
};

function Rederivation({ findings }: { readonly findings: readonly Finding[] }) {
  const contradicted = findings.some((finding) => finding.result === "contradicts");
  return (
    <Section
      heading={strings.rederivation.heading}
      detail={strings.rederivation.detail}
    >
      {findings.length === 0 ? (
        <p className={proseText}>{strings.rederivation.absent}</p>
      ) : (
        <>
          {contradicted ? (
            <p className={proseText}>{strings.rederivation.contradicted}</p>
          ) : null}
          <dl className={factList}>
            {findings.map((finding, index) => (
              <div key={`${index}-${finding.name}`} className={factRow}>
                <dt className="flex items-center gap-1 font-medium">
                  <Icon name={AGREEMENT_ICONS[finding.result]} className="shrink-0" />
                  <span>{AGREEMENT_LABELS[finding.result]}</span>
                </dt>
                <dd className={secondaryText}>{finding.name}</dd>
                {finding.detail === undefined || finding.detail === "" ? null : (
                  <dd className={identifierText}>{finding.detail}</dd>
                )}
              </div>
            ))}
          </dl>
        </>
      )}
    </Section>
  );
}

/* ── doing it again without this page ─────────────────────────────────────── */

function Offline({ proof }: { readonly proof: Proof }) {
  return (
    <Section heading={strings.offline.heading} detail={strings.offline.detail}>
      <dl className={factList}>
        <Fact label={strings.offline.repo} value={proof.repo} />
        {proof.material.commit_object_id === undefined ? null : (
          <Fact
            label={strings.offline.commitObjectId}
            value={proof.material.commit_object_id}
            chip="sha"
          />
        )}
        <Fact label={strings.offline.dataAsOf} value={proof.data_as_of} />
      </dl>
      <div className={factRow}>
        <span className={factLabel}>{strings.offline.command}</span>
        <pre className={materialBlock}>{strings.offline.commandValue}</pre>
      </div>
    </Section>
  );
}
