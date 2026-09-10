// SPDX-License-Identifier: Apache-2.0

/**
 * How old the ledger's claim about a run is.
 *
 * ── WHY THIS EXISTS ────────────────────────────────────────────────────────
 *
 * "Active" is a fact about the LEDGER — no `run_retired` and no `run_expired`
 * for this run. It reads as a fact about the WORLD: this agent is working.
 * Those coincide only while something retires finished runs and expires
 * crashed ones.
 *
 * Measured on this project's own deployment on 2026-09-10: six runs showing
 * Active, five of them dead, three silent for seventeen hours. The reaper that
 * would have expired them was switched off after it killed two live agents
 * (#180), and a hook bug lost three run markers before they could be retired.
 * Both are fixed — and the page must not depend on that, because the next
 * outage is a different one.
 *
 * doc 06 P2: a view may not present something it does not know. It does not
 * know that a run silent since yesterday is working. So the badge keeps saying
 * what the ledger says, and this says how old that claim is.
 *
 * ── WHY SILENCE BELOW A MINUTE IS NOT REPORTED ─────────────────────────────
 *
 * A live agent is between tool calls most of the time. Annotating every
 * healthy row with "last seen 12 seconds ago" would put noise on the rows a
 * reader has no question about, and a reader who learns to ignore an
 * annotation ignores it on the row that matters.
 */

/** Below this, a run is simply working and the badge stands unqualified. */
const QUIET_ENOUGH_TO_MENTION_MS = 60_000;

/**
 * lastSeen renders the age of a run's most recent event, or null when there is
 * nothing honest to say.
 *
 * Null for four distinct reasons, all of them "we do not know" rather than
 * "nothing happened": the run is active right now, the ledger recorded no
 * timestamp, the timestamp is unreadable, or it is in the future — which is
 * clock skew between the ledger and this browser, and "last seen -2 minutes
 * ago" is worse than silence.
 */
export function lastSeen(lastEventAt: string, now: Date): string | null {
  if (!lastEventAt) return null;
  const at = new Date(lastEventAt);
  const ms = at.getTime();
  if (Number.isNaN(ms)) return null;

  const elapsed = now.getTime() - ms;
  if (elapsed < QUIET_ENOUGH_TO_MENTION_MS) return null;

  return `last seen ${age(elapsed)} ago`;
}

/** age renders a duration in the largest unit that leaves it readable. */
function age(ms: number): string {
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 60) return plural(minutes, "minute");
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return plural(hours, "hour");
  return plural(Math.floor(hours / 24), "day");
}

/** plural, because "1 hours ago" is the kind of detail that costs trust. */
function plural(n: number, unit: string): string {
  return `${n} ${unit}${n === 1 ? "" : "s"}`;
}
