// SPDX-License-Identifier: Apache-2.0

/*
 * The account page's own date formatting: "Added" and "Last used" need to
 * read the same way for every viewer and in every visual-regression
 * screenshot, so the locale and time zone are fixed rather than read from
 * the browser (doc 06 §6.2's "numbers and dates set as data, formatted
 * consistently" applied to a value this directory owns).
 */

const dateFormatter = new Intl.DateTimeFormat("en-US", {
  dateStyle: "medium",
  timeZone: "UTC",
});

/** A UTC, en-US medium date ("Oct 1, 2026") for a `time.Time`-shaped ISO
 * string. An unparseable value is returned verbatim rather than hidden,
 * per P2: an admitted failure to format beats a silently wrong one. */
export function formatDate(iso: string): string {
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return iso;
  return dateFormatter.format(parsed);
}
