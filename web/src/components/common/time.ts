// SPDX-License-Identifier: Apache-2.0

/*
 * Time and duration formatting — doc 06 §6.2.
 *
 *   "Absolute timestamps with timezone on hover for every relative time
 *    ('12 min ago'). Counts are exact, never rounded vanity numbers."
 *
 * Two decisions worth stating, because both could reasonably have gone the
 * other way:
 *
 * 1. Absolute timestamps are rendered in UTC, always, and say so. An audit
 *    console's timestamps get pasted into tickets and compared against Rekor
 *    integration times; a value that means something different depending on
 *    who is reading it is not evidence. It also makes every render
 *    deterministic, which is why the tests can assert on exact strings.
 *
 * 2. Durations are floored to whole units and never rounded up. "59 min" is
 *    not "1 h": doc 06 §6.2 asks for exact, and a lag bound that reads as
 *    breached one minute early is a false alarm in the one component whose
 *    whole job is to be believed.
 */

const SECOND = 1_000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** `2026-08-30 14:32:05 UTC` — ISO order, space-separated, timezone named. */
export function formatAbsoluteUtc(at: Date): string {
  const iso = at.toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 19)} UTC`;
}

/** The machine-readable twin of the above, for `<time datetime>`. */
export function toDateTimeAttribute(at: Date): string {
  return at.toISOString();
}

/**
 * A duration in at most two units, floored. Never a bare number: the unit is
 * always spoken, because "12" in a header is not a fact.
 */
export function formatDuration(ms: number): string {
  const abs = Math.max(0, Math.floor(ms));
  if (abs < MINUTE) return `${Math.floor(abs / SECOND)} s`;
  if (abs < HOUR) return `${Math.floor(abs / MINUTE)} min`;
  if (abs < DAY) {
    const hours = Math.floor(abs / HOUR);
    const minutes = Math.floor((abs % HOUR) / MINUTE);
    return minutes === 0 ? `${hours} h` : `${hours} h ${minutes} min`;
  }
  const days = Math.floor(abs / DAY);
  const hours = Math.floor((abs % DAY) / HOUR);
  return hours === 0 ? `${days} d` : `${days} d ${hours} h`;
}

/** How long ago `at` was, measured from `now`. Formatted as above. */
export function elapsedSince(at: Date, now: Date): string {
  return formatDuration(now.getTime() - at.getTime());
}
