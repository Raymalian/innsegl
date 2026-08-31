// SPDX-License-Identifier: Apache-2.0

/*
 * A relative time that always carries its absolute one — doc 06 §6.2, this
 * issue's stated acceptance criterion:
 *
 *   "Absolute timestamps with timezone on hover for every relative time
 *    ('12 min ago')."
 *
 * ── WHY THIS IS NOT A `title` ATTRIBUTE ────────────────────────────────────
 *
 * "On hover" is how the specification describes the affordance, and taken
 * literally it excludes most of the people who need it. A keyboard user never
 * hovers. A touch user has no hover at all. A screen-reader user hears
 * whatever the accessible name says and nothing about a pointer. doc 06 §6.4
 * is titled "(gating, not aspirational)" and requires full keyboard
 * operability and that truncated or abbreviated material reach assistive
 * technology — so "12 min ago" with the real timestamp behind a mouse is a
 * defect in three of the four input modes, in an audit console where "3
 * minutes ago" alone is unusable.
 *
 * So the absolute value reaches the reader by four independent routes, and no
 * two of them share a failure:
 *
 *   1. `title` — the native tooltip, for a pointer, with no JavaScript.
 *   2. A `role="tooltip"` popover on hover AND on keyboard focus.
 *   3. A click or tap pins that popover open, which is the only route a touch
 *      device has. It is a disclosure, not a mutation: doc 06 P6 forbids
 *      controls that write, and this one reveals a value already on the page.
 *   4. The accessible name of the control, which is the absolute timestamp and
 *      the relative one together — so a screen-reader user hears "registered:
 *      2026-08-31 11:52:00 UTC, 8 min ago" and never hears "8 min ago" alone.
 *
 * The visible relative text is `aria-hidden`, exactly as `IdentifierChip`
 * hides its truncated glyphs: assistive technology receives the complete
 * statement once rather than the abbreviation twice.
 *
 * The absolute rendering is UTC and says so, from components/common's `time`
 * module. That is a deliberate property of the whole product rather than of
 * this component: a timestamp pasted into a ticket and compared against a
 * Rekor integration time must mean the same thing to both readers.
 */

import { useCallback, useId, useState } from "react";

import {
  elapsedSince,
  formatAbsoluteUtc,
  formatDuration,
  toDateTimeAttribute,
} from "../../components/common/time";
import { strings } from "./strings";
import { identifierText, popover, srOnly, timeTrigger } from "./styles";

export interface RelativeTimeProps {
  /** The instant. */
  readonly at: Date;
  /** Injected so a render is deterministic, exactly as `ReadPathState` does. */
  readonly now: Date;
  /** What this time is — "Registered", "Expires". Spoken before the value, so
   * an announcement is never a bare number. */
  readonly label: string;
}

export function RelativeTime({ at, now, label }: RelativeTimeProps) {
  const tooltipId = useId();
  const [hovered, setHovered] = useState(false);
  const [focused, setFocused] = useState(false);
  const [pinned, setPinned] = useState(false);

  const toggle = useCallback(() => setPinned((was) => !was), []);

  const absolute = formatAbsoluteUtc(at);
  /* A credential expiry is in the future, and "0 s ago" for a future instant
   * is false. doc 06 §6.2 asks for exact; the direction is part of exact. */
  const ahead = at.getTime() > now.getTime();
  const relative = ahead
    ? strings.time.ahead(formatDuration(at.getTime() - now.getTime()))
    : strings.time.ago(elapsedSince(at, now));
  const revealed = hovered || focused || pinned;

  return (
    <span className="relative inline-flex items-center">
      <button
        type="button"
        title={absolute}
        aria-describedby={revealed ? tooltipId : undefined}
        aria-expanded={pinned}
        onClick={toggle}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
        className={timeTrigger}
      >
        <time dateTime={toDateTimeAttribute(at)} aria-hidden="true">
          {relative}
        </time>
        <span className={srOnly}>
          {strings.time.announce(label, absolute, relative)}
        </span>
      </button>

      {revealed ? (
        <span
          role="tooltip"
          id={tooltipId}
          className={`${popover} ${identifierText} top-full left-0 whitespace-nowrap text-ink`}
        >
          {absolute}
        </span>
      ) : null}
    </span>
  );
}

/**
 * The same component for a timestamp the ledger returned in a shape this
 * dashboard cannot read.
 *
 * doc 06 P2: an unreadable timestamp is not a missing one and is certainly not
 * the epoch. It is rendered as the raw value under a label saying it could not
 * be read, so the reader can go and look at what the API actually returned.
 */
export function Instant({
  value,
  now,
  label,
}: {
  readonly value: string | undefined;
  readonly now: Date;
  readonly label: string;
}) {
  if (value === undefined || value === "") return null;
  const at = new Date(value);
  if (Number.isNaN(at.getTime())) {
    return (
      <span className={identifierText} title={strings.time.unparseable}>
        <span className={srOnly}>{`${strings.time.unparseable}: `}</span>
        {value}
      </span>
    );
  }
  return <RelativeTime at={at} now={now} label={label} />;
}
