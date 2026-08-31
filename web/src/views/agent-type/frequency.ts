// SPDX-License-Identifier: Apache-2.0

/*
 * Run frequency across a window — doc 06 §3.5's first metric.
 *
 *   "All runs of one agent type across time: run frequency, repos touched,
 *    aggregate verification status."
 *
 * ── WHY THE BUCKETS ARE CUMULATIVE DIFFERENCES ─────────────────────────────
 *
 * doc 06 §7 forbids shipping the table to the client, so a frequency cannot be
 * a histogram of rows the browser fetched and binned. Every number below is
 * one the SERVER counted: internal/api's listRunsSQL reports
 * `count(*) OVER ()` over the whole filtered set, so a request with a window
 * and `limit=1` is a count query that happens to return one row.
 *
 * The obvious shape — one request per bucket, each with the bucket's own two
 * bounds — is wrong, and quietly. internal/api's run filter is
 *
 *     registered_at >= from AND registered_at <= to
 *
 * closed at BOTH ends. Six adjacent buckets sharing their boundaries would
 * count a run registered exactly on a boundary twice; six buckets that backed
 * the upper bound off by a second would lose it. A frequency that does either
 * is not a frequency, and neither error is visible in the rendered table.
 *
 * So the view asks a different question, once per interior boundary: how many
 * runs fall between the window's start and this instant. Those answers are
 * closed-closed too — but the DIFFERENCE of two of them is a half-open
 * interval, which is exactly what a bucket is. Nothing is counted twice and
 * nothing falls between the buckets, and the counts sum to the window's own
 * total, which the page request already returned.
 */

export interface Bucket {
  /** Inclusive for the first bucket, exclusive for every other: a bucket's
   * lower bound is the previous bucket's upper bound, and a run on a boundary
   * belongs to the earlier of the two. */
  readonly from: Date;
  /** Inclusive. This is the instant the bucket's cumulative query ends at. */
  readonly to: Date;
}

/**
 * Six, which is enough to show a shape without asking the server for a count
 * per day of a month-long window. It is a constant rather than a function of
 * the span because a bucket count that changed with the window would make two
 * renders of the same view incomparable.
 */
export const FREQUENCY_BUCKETS = 6;

/**
 * The buckets that tile [from, to] exactly.
 *
 * The last boundary is the window's own end rather than a computed one, so
 * rounding cannot leave a sliver of the window outside every bucket.
 */
export function bucketsOf(from: Date, to: Date, count: number): readonly Bucket[] {
  const span = to.getTime() - from.getTime();
  if (!Number.isFinite(span) || span <= 0 || count <= 0) return [];

  const buckets: Bucket[] = [];
  let lower = new Date(from.getTime());
  for (let k = 1; k <= count; k += 1) {
    const upper =
      k === count
        ? new Date(to.getTime())
        : new Date(from.getTime() + Math.round((k * span) / count));
    buckets.push({ from: lower, to: upper });
    lower = upper;
  }
  return buckets;
}

/**
 * One bucket's count per cumulative answer, in order.
 *
 * Clamped at zero. The last bucket of a default window ends at "now", so a run
 * appended between two of the requests can make a later cumulative smaller
 * than an earlier one. A negative frequency is not a fact; zero is, and the
 * next render corrects it.
 */
export function bucketCounts(cumulative: readonly number[]): readonly number[] {
  const counts: number[] = [];
  let previous = 0;
  for (const total of cumulative) {
    counts.push(Math.max(0, total - previous));
    previous = total;
  }
  return counts;
}
