// SPDX-License-Identifier: Apache-2.0

/*
 * The trailer and the certificate, side by side — doc 06 §4.1's third check.
 *
 *   "Trailer matches certificate identity (both values shown side by side; on
 *    mismatch, the differing segment is highlighted)."
 *
 * Two decisions are worth stating, because both could reasonably have gone the
 * other way.
 *
 * WHEN THEY AGREE, the identities render as IdentifierChips: middle-truncated
 * with the trust domain and the final segment preserved, copyable in one
 * click, full value to assistive technology (doc 06 §4.3). That is the right
 * rendering for a value a reader wants to take away.
 *
 * WHEN THEY DIFFER, they render in full, segment by segment, and the chip is
 * deliberately not used — because middle truncation elides the middle, and a
 * forged trailer usually differs in the middle. A comparison whose rendering
 * can hide the very difference it exists to show is worse than no comparison.
 *
 * The cue on the differing segment is three things at once, which is doc 06
 * §6.4's "never color alone" taken seriously:
 *
 *   1. colour, from --innsegl-color-mismatch-*;
 *   2. a <mark> carrying a wavy underline from the sheet — an element and a
 *      text decoration, so the cue exists in the markup rather than only in a
 *      stylesheet;
 *   3. the name of the differing segment, in VISIBLE prose. A reader looking
 *      at a greyscale printout of an audit report gets nothing from 1 and
 *      little from 2; "the run-id segment differs" survives any rendering.
 */

import { Fragment } from "react";

import { IdentifierChip } from "../common/IdentifierChip";
import { diffIdentity, segmentsOf } from "./identity";
import type { IdentityDiff } from "./identity";
import { strings } from "./strings";
import {
  comparisonRow,
  identifierText,
  mismatchMark,
  mutedText,
  secondaryText,
  srOnly,
} from "./styles";

export interface IdentityComparisonProps {
  /** The anchor the mismatch alert links to (doc 06 §4.5, P1). */
  readonly id: string;
  /** The Agent-Identity trailer: what the commit CLAIMS. */
  readonly trailer: string;
  /** The certificate's URI SAN: what the signer PROVED. */
  readonly certificate: string;
}

export function IdentityComparison({ id, trailer, certificate }: IdentityComparisonProps) {
  const diff = diffIdentity(trailer, certificate);
  return (
    <div id={id} className="flex flex-col gap-2">
      <h4 className="font-medium">{strings.identity.heading}</h4>
      <p className={secondaryText}>{summaryOf(diff)}</p>
      <dl className="flex flex-col gap-2">
        <Row label={strings.identity.trailer} value={trailer} diff={diff} />
        <Row label={strings.identity.certificate} value={certificate} diff={diff} />
      </dl>
    </div>
  );
}

function summaryOf(diff: IdentityDiff): string {
  if (diff.kind === "same") return strings.identity.agree;
  if (diff.kind === "segment") return strings.identity.differs(diff.name);
  return strings.identity.uncomparable;
}

function Row({
  label,
  value,
  diff,
}: {
  readonly label: string;
  readonly value: string;
  readonly diff: IdentityDiff;
}) {
  return (
    <div className={comparisonRow}>
      <dt className={mutedText}>{label}</dt>
      <dd className={identifierText}>
        {value === "" ? (
          <span className={secondaryText}>{strings.identity.absent}</span>
        ) : diff.kind === "same" ? (
          <IdentifierChip value={value} kind="spiffe" />
        ) : (
          <Segmented value={value} diff={diff} />
        )}
      </dd>
    </div>
  );
}

/** The identity in full, with the differing segment marked. */
function Segmented({ value, diff }: { readonly value: string; readonly diff: IdentityDiff }) {
  return (
    <span className="break-all">
      {segmentsOf(value, diff).map((segment, index) => (
        <Fragment key={`${index}-${segment.name}`}>
          {segment.separator}
          {segment.differs ? (
            <>
              <mark className={mismatchMark}>{segment.value}</mark>
              <span className={srOnly}>{strings.identity.marked}</span>
            </>
          ) : (
            <span>{segment.value}</span>
          )}
        </Fragment>
      ))}
    </span>
  );
}
