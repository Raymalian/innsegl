// SPDX-License-Identifier: Apache-2.0

/*
 * The anchoring heartbeat, as the overview supplies it — doc 06 §3.1, P2, P3.
 * Driven by FE-005, and by FE-070/FE-071 (proposed).
 *
 *   §3.1: "Anchoring heartbeat in the persistent header (all views): 'Ledger
 *   segment N anchored M min ago.' Exceeding the configured anchoring-lag
 *   bound turns this amber with the lag duration; it is the system's public
 *   tamper-evidence pulse and is never hidden."
 *
 * `components/common/AnchoringHeartbeat` renders the pulse and owns the
 * amber-past-the-bound behaviour. This composes it. What is here is the part
 * the component cannot do, because it is about the data rather than the
 * rendering:
 *
 * ── THE STATE THE SHARED COMPONENT HAS NO WORDS FOR ────────────────────────
 *
 * `AnchoringHeartbeat` takes `anchoredAt`, and a null means "no segment
 * anchored yet". `internal/api`'s AnchorHeartbeat has three states, not two:
 * nothing sealed, sealed and anchored, and — because doc 02 §3 puts the
 * anchoring members on a SUPERSEDING `segment_sealed` event "once Rekor
 * confirms" — sealed and waiting. That third state is ordinary and healthy
 * for as long as Rekor takes to answer, and it is the state the system is in
 * during exactly the outage the heartbeat exists to make visible (IP §6.4:
 * "anchoring lag is a monitored, bounded degradation ... Dashboard heartbeat
 * must show the lag").
 *
 * Mapping it onto either of the component's two states is a lie:
 *   - as `anchoredAt = sealed_at` it reads "anchored M min ago" about a
 *     segment Rekor has never seen, which is the one claim this product must
 *     never make (I5);
 *   - as `anchoredAt = null` it reads "no segment anchored yet", which the
 *     response does not say either — it names the NEWEST sealed segment, and
 *     an older one may well be anchored.
 *
 * So the third state is rendered here, in the same shape and the same tokens,
 * measuring the lag from the seal — which is what `internal/segment`'s
 * `Anchorer.Lag()` does too: "measured from the oldest unanchored seal when
 * anything is pending". The right fix is for that state to exist in the shared
 * component; this issue does not own it, so it is reported rather than
 * reached into.
 *
 * ── AND THE STATE THE RESPONSE ITSELF MAY NOT ARRIVE IN ────────────────────
 *
 * A heartbeat that is "never hidden" cannot be hidden by its own fetch
 * failing. `anchor === null` means the query API did not answer, and that is
 * rendered as what it is: unknown, in amber, never as calm.
 *
 * Colour: amber, from the degraded group — doc 06 §5.3 gives "anchoring lag"
 * to amber. Never red: red is verification failure and integrity alerts, and a
 * late anchor is neither. Never green: an anchor arriving on time is not a
 * cryptographic verification.
 */

import type { ReactNode } from "react";

import {
  AnchoringHeartbeat,
  Icon,
  IdentifierChip,
  elapsedSince,
  formatAbsoluteUtc,
  formatDuration,
  strings as commonStrings,
  toDateTimeAttribute,
} from "../../components/common";
import { strings } from "./strings";
import {
  cardRow,
  degraded,
  listHeading,
  mutedText,
  pulseBreach,
  pulseShell,
  secondaryText,
} from "./styles";
import type { AnchorHeartbeat } from "./types";

/**
 * The bound past which the pulse goes amber when the deployment does not say.
 *
 * `internal/segment/anchor.go`'s `defaultAnchorBound` is 15 minutes and is the
 * same number. It is duplicated rather than served: nothing in the query API
 * carries `bound_seconds`, though `internal/segment`'s LagSnapshot has it.
 * A dashboard that guesses the bound can raise a false alarm or miss a real
 * one, so this is reported as a gap rather than treated as a decision.
 */
export const DEFAULT_LAG_BOUND_MS = 15 * 60 * 1000;

export interface AnchoringPulseProps {
  /** The query API's AnchorHeartbeat; null when it did not answer, undefined
   * while the read is still in flight. Required either way — a heartbeat that
   * is "never hidden" is not a prop a caller can leave off. */
  readonly anchor: AnchorHeartbeat | null | undefined;
  readonly lagBoundMs: number;
  /** Injected for determinism; defaults to the wall clock. */
  readonly now?: Date;
}

export function AnchoringPulse({ anchor, lagBoundMs, now }: AnchoringPulseProps) {
  const at = now ?? new Date();

  if (anchor === undefined) {
    return (
      <Pulse state="reading">
        <p
          aria-label={commonStrings.heartbeat.regionLabel}
          className={`${pulseShell} ${secondaryText}`}
        >
          <Icon name="busy" className="shrink-0" />
          <span>{strings.heartbeat.reading}</span>
        </p>
      </Pulse>
    );
  }

  if (anchor === null) {
    return (
      <Pulse state="unreadable">
        <p
          aria-label={commonStrings.heartbeat.regionLabel}
          className={`${pulseShell} ${degraded} ${pulseBreach}`}
        >
          <Icon name="unreachable" className="shrink-0" />
          <span>{strings.heartbeat.unreadable}</span>
        </p>
      </Pulse>
    );
  }

  const segment = segmentNumberOf(anchor);
  const sealedAt = sealedAtOf(anchor);

  /* Nothing sealed, or a response too incomplete to name a segment. Either
   * way the shared component's own "nothing anchored yet" is the honest
   * rendering, and it is neither calm nor an alarm. */
  if (segment === null || sealedAt === null) {
    return (
      <Pulse state="nothing-sealed">
        <AnchoringHeartbeat
          segment={null}
          anchoredAt={null}
          lagBoundMs={lagBoundMs}
          now={at}
        />
      </Pulse>
    );
  }

  if (anchor.anchored) {
    return (
      <Pulse state="anchored">
        <AnchoringHeartbeat
          segment={segment}
          anchoredAt={sealedAt}
          lagBoundMs={lagBoundMs}
          now={at}
        />
      </Pulse>
    );
  }

  const lagMs = at.getTime() - sealedAt.getTime();
  const beyond = lagMs > lagBoundMs;
  return (
    <Pulse state={beyond ? "pending-beyond-bound" : "pending-within-bound"}>
      <p
        aria-label={commonStrings.heartbeat.regionLabel}
        className={`${pulseShell} ${beyond ? `${degraded} ${pulseBreach}` : secondaryText}`}
      >
        <Icon name={beyond ? "anchor-lag" : "anchor-pulse"} className="shrink-0" />
        <span>
          {strings.heartbeat.sealedPrefix(segment)}
          <time
            dateTime={toDateTimeAttribute(sealedAt)}
            title={formatAbsoluteUtc(sealedAt)}
            className="font-mono"
          >
            {`${elapsedSince(sealedAt, at)} ago`}
          </time>
          {strings.heartbeat.sealedSuffix}
          {beyond
            ? strings.heartbeat.beyondBound(
                formatDuration(lagMs - lagBoundMs),
                formatDuration(lagBoundMs),
              )
            : ""}
        </span>
      </p>
    </Pulse>
  );
}

/**
 * The material behind the pulse (doc 06 P1): which segment, over which chain
 * positions, and the Rekor entry that proves it — or the absence of one, said
 * out loud.
 */
export function AnchoringEvidence({
  anchor,
}: {
  readonly anchor: AnchorHeartbeat | null | undefined;
}) {
  if (anchor === null || anchor === undefined || !anchor.present) return null;
  const first = anchor.first_position;
  const last = anchor.last_position;
  return (
    <div className="flex flex-col gap-1">
      <h2 className={listHeading}>{strings.heartbeat.detailHeading}</h2>
      {first === undefined || last === undefined ? null : (
        <p className={mutedText}>{strings.heartbeat.segmentRange(first, last)}</p>
      )}
      {anchor.segment_id === undefined ? null : (
        <p className={cardRow}>
          <span className={mutedText}>{strings.heartbeat.segmentLabel}</span>
          <IdentifierChip value={anchor.segment_id} />
        </p>
      )}
      <p className={cardRow}>
        <span className={mutedText}>{strings.heartbeat.rekorLabel}</span>
        {anchor.anchored && anchor.rekor_log_index !== undefined ? (
          <IdentifierChip value={String(anchor.rekor_log_index)} kind="rekor" />
        ) : (
          <span className={mutedText}>{strings.heartbeat.pendingRekor}</span>
        )}
      </p>
    </div>
  );
}

/**
 * "Segment N", where the ledger has no N.
 *
 * doc 06 §3.1 says "Ledger segment N" and `AnchoringHeartbeat` takes a number,
 * but doc 02 §3's `segment_id` is a content digest and no table numbers
 * segments. `internal/segment`'s LagSnapshot settles it in a comment —
 * "Segments are identified to people by their position range, not by their
 * content-addressed id (ADR-0006)" — so N is the last chain position the
 * segment covers, and the digest and the full range are rendered beside the
 * pulse rather than lost.
 */
function segmentNumberOf(anchor: AnchorHeartbeat): number | null {
  if (!anchor.present) return null;
  return anchor.last_position ?? null;
}

function sealedAtOf(anchor: AnchorHeartbeat): Date | null {
  if (!anchor.present || anchor.sealed_at === undefined) return null;
  const at = new Date(anchor.sealed_at);
  return Number.isNaN(at.getTime()) ? null : at;
}

/** The one wrapper every state renders through, so no branch can forget to. */
function Pulse({
  state,
  children,
}: {
  readonly state: string;
  readonly children: ReactNode;
}) {
  return (
    <div data-testid="overview-heartbeat" data-state={state} className="min-w-0">
      {children}
    </div>
  );
}
