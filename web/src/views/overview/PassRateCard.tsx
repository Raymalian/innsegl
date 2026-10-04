// SPDX-License-Identifier: Apache-2.0

/*
 * The verification pass rate — and the conflict it sits on.
 *
 * ── THE CONFLICT ───────────────────────────────────────────────────────────
 *
 * doc 06 §3.1 asks for four metric cards, and the fourth is "verification pass
 * rate", with "Pass rate below 100% is rendered as a warning state, not a
 * neutral number."
 *
 * doc 06 P2 and IP §6.11 forbid the only rate this system can cheaply produce:
 *
 *   IP §6.11: "Dashboard never renders 'verified' from cached state alone if
 *   the underlying proof check errored ... it never downgrades to
 *   database-only 'trust us' answers (I5)."
 *
 * `internal/api` reached the same conclusion and acted on it. `query.go`'s
 * `Overview` carries no rate, and says why in its own comment: "a rate
 * computed from these tables would be a database-only verdict, which IP §6.11
 * and FD P2 forbid in terms, and FD anti-pattern 10 warns about metrics chosen
 * because they are easy. A live pass rate has to come from running the three
 * checks ... and costs a Fulcio and a Rekor round trip per commit."
 *
 * Two further problems are this view's own and neither is resolved by finding
 * the data:
 *
 *   §3.1 says what a rate BELOW 100% renders as and never says what a rate AT
 *   100% renders as. Green is unavailable — doc 06 §5.3 gives it to
 *   cryptographic verification alone, and doc 06 §8 anti-pattern 4 forbids a
 *   verification summary that cannot be expanded to the three checks, which a
 *   card aggregating thousands of commits can never be. Neutral is the only
 *   remaining reading, and a neutral "nothing failed lately" is close to the
 *   positive-trend framing §5.3 rules out.
 *
 *   A SCALAR RATE COLLAPSES FAILED INTO UNAVAILABLE. "98%" cannot say whether
 *   the missing 2% failed verification or could not be checked, and doc 06 §8
 *   anti-pattern 2 makes that collapse a defect. So a rate is never rendered
 *   alone here: the two are always spelled out beside it, and they drive two
 *   different colours.
 *
 * ── WHAT THIS CARD DOES, PENDING A HUMAN RULING ────────────────────────────
 *
 * It never states a rate that no live check produced. With nothing measured —
 * which is every deployment of this build, because nothing produces a
 * `PassRate` — it renders "Not measured", in amber, with the reason and a link
 * to the page where the reader can run a live check themselves. That is doc 06
 * P2's third state said out loud: not verified, not failed, not checked.
 *
 * Amber rather than neutral, deliberately. A neutral card reads as "nothing to
 * see", and an unchecked system that looks like a checked one is the exact
 * collapse P2 exists to prevent. The cost is an amber that is always on, which
 * is a real cost — flagged for the ruling.
 *
 * `liveness` is required on `PassRate` and has no default, which is
 * `VerificationPanel`'s contract (FE-039) one level up: a caller holding a
 * retained rate cannot report it by saying nothing. A cached rate is refused
 * outright — doc 06 §8 anti-pattern 1 is a cached green, and a cached 100% is
 * that, wearing a metric card.
 */

import { elapsedSince } from "../../components/common";
import { formatCount, formatRate } from "./format";
import { Icon } from "../../components/common";
import type { MetricTone } from "./MetricCard";
import { strings } from "./strings";
import { degraded, hairline, integrityAlert, link, neutralSurface, srOnly } from "./styles";
import type { PassRate } from "./types";

export interface PassRateCardProps {
  /** The denominator the ledger does know: commits it holds a record for. */
  readonly commitsRecorded: number;
  /** A live measurement, if one was ever made. Nothing in this build makes
   * one; see the report. */
  readonly rate?: PassRate;
  /** A live measurement is running; say so rather than "Not measured". */
  readonly measuring?: boolean;
  readonly now: Date;
  /** doc 06 §3.6's page, where the reader can run the check this card did
   * not. */
  readonly verifyHref: string;
}

export function PassRateCard({
  commitsRecorded,
  rate,
  measuring = false,
  now,
  verifyHref,
}: PassRateCardProps) {
  const measured = isLive(rate) ? rate : undefined;

  if (measured === undefined && measuring) {
    return (
      <Line
        tone="neutral"
        value={strings.passRate.measuring}
        hover={strings.passRate.measuringMeaning}
        note={strings.passRate.measuringMeaning}
        href={verifyHref}
      />
    );
  }

  if (measured === undefined) {
    return (
      <Line
        tone="degraded"
        value={strings.passRate.notMeasured}
        hover={strings.passRate.checkedRatio(
          formatCount(0),
          formatCount(commitsRecorded),
        )}
        note={
          rate === undefined
            ? strings.passRate.notMeasuredMeaning
            : strings.passRate.cachedMeaning
        }
        href={verifyHref}
      />
    );
  }

  const breakdown =
    measured.failed === 0 && measured.unavailable === 0
      ? ""
      : ` ${strings.passRate.breakdown(
          formatCount(measured.failed),
          formatCount(measured.unavailable),
        )}`;
  return (
    <Line
      tone={toneOf(measured)}
      value={formatRate(measured.verified, measured.checked)}
      hover={strings.passRate.verifiedRatio(
        formatCount(measured.verified),
        formatCount(measured.checked),
      )}
      note={`${strings.passRate.measuredAt(elapsedSince(measured.measuredAt, now))}${breakdown}`}
      href={verifyHref}
    />
  );
}

/**
 * Verification as one line, not a card (RM-331): the label, the state, a
 * short note, and the link to the live check. The amber and red treatments are
 * the same ones the card carried; only the room they take has changed.
 */
function Line({
  tone,
  value,
  hover,
  note,
  href,
}: {
  readonly tone: MetricTone;
  readonly value: string;
  readonly hover: string;
  readonly note: string;
  readonly href: string;
}) {
  const skin = tone === "alert" ? integrityAlert : tone === "degraded" ? degraded : neutralSurface;
  const icon = tone === "alert" ? "integrity-alert" : tone === "degraded" ? "unknown" : null;
  return (
    <p
      data-testid="metric-pass-rate"
      data-tone={tone}
      className={`flex flex-wrap items-center gap-x-3 gap-y-1 rounded-md px-3 py-2 ${hairline} ${skin}`}
    >
      {icon === null ? null : <Icon name={icon} className="shrink-0" />}
      <span className="font-semibold">{strings.passRate.label}</span>
      <span title={hover}>
        {value}
        <span className={srOnly}>{hover}</span>
      </span>
      <span className="text-micro">{note}</span>
      <a href={href} className={link}>
        {strings.passRate.verifyLink}
      </a>
    </p>
  );
}

function isLive(rate: PassRate | undefined): boolean {
  if (rate === undefined) return false;
  if (rate.liveness.source !== "live") return false;
  if (rate.liveness.liveError !== undefined && rate.liveness.liveError !== "") {
    return false;
  }
  return rate.checked > 0;
}

/**
 * doc 06 §3.1's "below 100% is a warning, not a neutral number", split so that
 * the warning says which kind it is (§8 anti-pattern 2).
 *
 * A failed check is red: doc 06 §5.3 gives red to "verification failed". A
 * check that could not run is amber: "verification unavailable". A rate with
 * neither is neutral — never green, because this card is an aggregate that
 * cannot expand to three checks and their inputs (§8 anti-pattern 4), and
 * because "nothing failed lately" is not a cryptographic verification.
 */
function toneOf(rate: PassRate): MetricTone {
  if (rate.failed > 0) return "alert";
  if (rate.unavailable > 0) return "degraded";
  return "neutral";
}
