// SPDX-License-Identifier: Apache-2.0

/*
 * Identifier truncation — doc 06 P4, §4.3, §8 anti-pattern 6.
 *
 * doc 06 P4: identifiers "render in monospace, are copyable in one click,
 * truncate intelligently (never mid-segment), and link to their canonical
 * view." doc 06 §4.3 names what must survive the cut: "middle-truncation
 * preserving trust domain and final segment". doc 06 §8 makes losing the trust
 * domain a defect.
 *
 * Two shapes of identifier appear in this product and they truncate
 * differently, which is the whole content of this file:
 *
 *   SEGMENTED — a SPIFFE ID, or any path-like run reference. It has internal
 *   structure a reader navigates by, so only WHOLE segments are ever removed,
 *   and the two segments that carry the meaning — the trust domain at the
 *   front and the final segment at the back — are never among them. If they do
 *   not fit the requested width, the width loses: a chip wider than asked for
 *   is a layout problem, a chip that says `spiffe://inn…5PDC` is a lie about
 *   which trust domain signed something.
 *
 *   SINGLE-TOKEN — a 40-character commit SHA, a Rekor entry index. There are
 *   no segments, so "never mid-segment" is vacuous and the honest rule is the
 *   one a reader can act on: keep both ends, so the value can still be matched
 *   against `git log` output at the front and against a Rekor record at the
 *   back. A head-only abbreviation would hide the end entirely.
 *
 * Nothing here truncates for cosmetics: a value that already fits is returned
 * untouched, and so is one that cannot be shortened without breaking a rule.
 */

/** The only ellipsis in the product. One character, never three periods. */
export const ELLIPSIS = "…";

export type IdentifierKind = "spiffe" | "sha" | "run" | "rekor" | "generic";

export interface TruncateOptions {
  readonly kind?: IdentifierKind;
  /** Preferred maximum rendered length. Segment integrity outranks it. */
  readonly maxLength?: number;
}

/** Wide enough for a short SPIFFE ID or an abbreviated SHA in a table cell. */
export const DEFAULT_MAX_LENGTH = 44;

/**
 * The scheme-and-authority head of a URI-shaped identifier — for a SPIFFE ID,
 * `spiffe://innsegl.dev`, which is the part doc 06 §8 forbids losing.
 * Returns null for anything that is not URI-shaped.
 */
export function trustDomainOf(value: string): string | null {
  const match = /^[a-z][a-z0-9+.-]*:\/\/[^/]+/.exec(value);
  return match === null ? null : match[0];
}

/**
 * Segmented means "has a droppable interior", not merely "contains a slash":
 * `spiffe://innsegl.dev/01HQ…` has a head and a tail and nothing between them,
 * so there is nothing to remove and the segmented path returns it whole.
 */
function isSegmented(value: string): boolean {
  return splitSegments(value).tail !== "";
}

/**
 * Split an identifier into the head that must survive, the droppable middle,
 * and the tail that must survive. For a URI the head is the trust domain; for
 * a bare path it is the first segment.
 */
function splitSegments(value: string): {
  head: string;
  segments: readonly string[];
  tail: string;
} {
  const domain = trustDomainOf(value);
  const rest = domain === null ? value : value.slice(domain.length);
  const parts = rest.split("/").filter((part) => part.length > 0);

  if (domain === null) {
    // A bare path: the first segment is the head, the last is the tail.
    if (parts.length < 2) return { head: value, segments: [], tail: "" };
    const [first, ...others] = parts;
    const tail = others[others.length - 1] as string;
    return { head: first as string, segments: others.slice(0, -1), tail };
  }

  if (parts.length === 0) return { head: value, segments: [], tail: "" };
  const tail = parts[parts.length - 1] as string;
  return { head: domain, segments: parts.slice(0, -1), tail };
}

function truncateSegmented(value: string, maxLength: number): string {
  const { head, segments, tail } = splitSegments(value);
  if (tail === "") return value; // nothing droppable; never cut mid-segment

  const kept: string[] = [head];
  const render = (parts: readonly string[]): string =>
    `${parts.join("/")}/${ELLIPSIS}/${tail}`;

  for (const segment of segments) {
    const candidate = [...kept, segment];
    if (render(candidate).length > maxLength) break;
    kept.push(segment);
  }

  // Every middle segment fitted, which means nothing needed dropping.
  if (kept.length === segments.length + 1) return value;
  return render(kept);
}

function truncateSingleToken(value: string, maxLength: number): string {
  if (maxLength < 3) return value; // narrower than head + ellipsis + tail
  const budget = maxLength - ELLIPSIS.length;
  const headLength = Math.ceil(budget / 2);
  const tailLength = budget - headLength;
  return (
    value.slice(0, headLength) + ELLIPSIS + value.slice(value.length - tailLength)
  );
}

/**
 * Middle-truncate an identifier for display. The full value is always what
 * gets copied and what reaches assistive technology; this is glyphs only.
 */
export function truncateIdentifier(
  value: string,
  options: TruncateOptions = {},
): string {
  const maxLength = options.maxLength ?? DEFAULT_MAX_LENGTH;
  if (value.length <= maxLength) return value;
  if (options.kind === "rekor") return value; // a log index is never abbreviated
  return isSegmented(value)
    ? truncateSegmented(value, maxLength)
    : truncateSingleToken(value, maxLength);
}
