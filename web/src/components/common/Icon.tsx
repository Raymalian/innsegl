// SPDX-License-Identifier: Apache-2.0

/*
 * The icon set — doc 06 §5.3, §6.4.
 *
 *   "Every semantic color is paired with an icon and a text label."
 *   "Never color alone: every tri-state verification result carries icon +
 *    label."
 *
 * That rule is why this file exists at all. An icon here is not decoration: it
 * is the redundant channel that carries the meaning for a reader who cannot
 * separate the hues, or who is looking at a greyscale printout of an audit
 * report. So the set is small, every shape is distinguishable from every other
 * shape at 16px, and two states that mean different things never share one.
 *
 * Three properties are deliberate:
 *
 *   - Drawn inline, from paths in this file. doc 06 §7 budgets the public
 *     verification page for "no heavy framework payloads", ADR-0038 decision 7
 *     removes the webfont, and an icon font or an icon package would put one
 *     of the two back. Nothing here is fetched.
 *   - `currentColor` throughout, so an icon takes the colour of the token its
 *     label already uses. There is no icon colour to drift out of step with
 *     the text beside it, and no route to a colour outside the sheet.
 *   - `aria-hidden` always. The icon duplicates the label for sighted readers;
 *     announcing it as well would read the same fact twice.
 */

import type { ReactNode } from "react";

export type IconName =
  | "copy"
  | "open"
  | "status-active"
  | "status-retired"
  | "status-expired"
  | "staleness"
  | "anchor-pulse"
  | "anchor-lag"
  | "unknown"
  | "integrity-alert"
  | "busy"
  | "empty"
  | "unreachable";

/*
 * One 16x16 path per name, stroked. The shapes are chosen to differ in
 * silhouette, not only in detail — a filled disc, a hollow ring, a dashed
 * ring, a triangle and a bar read apart from each other with no colour at all.
 */
const PATHS: Record<IconName, ReactNode> = {
  copy: (
    <>
      <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
      <path d="M10.5 3.5v-1a1 1 0 0 0-1-1h-7a1 1 0 0 0-1 1v7a1 1 0 0 0 1 1h1" />
    </>
  ),
  open: (
    <>
      <path d="M9.5 2.5h4v4" />
      <path d="M13.5 2.5 7 9" />
      <path d="M12 9.5v3a1 1 0 0 1-1 1H3.5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h3" />
    </>
  ),
  /* Active: a filled disc. The only solid shape in the set. */
  "status-active": <circle cx="8" cy="8" r="4" fill="currentColor" />,
  /* Retired: a hollow ring crossed by a bar — closed, deliberately. */
  "status-retired": (
    <>
      <circle cx="8" cy="8" r="5" />
      <path d="M5.5 8h5" />
    </>
  ),
  /* Expired: a DASHED ring with a clock hand past the hour. Different
   * silhouette from Retired, not a different hue — doc 06 §3.2 requires the
   * two to be told apart, and §5.3 assigns both to neutral grey. */
  "status-expired": (
    <>
      <path d="M8 3a5 5 0 0 1 4.33 2.5" />
      <path d="M13 8a5 5 0 0 1-2.5 4.33" />
      <path d="M8 13a5 5 0 0 1-4.33-2.5" />
      <path d="M3 8a5 5 0 0 1 2.5-4.33" />
      <path d="M8 5.5V8l2 1.5" />
    </>
  ),
  /* Staleness: a clock with a rewind arrow. The data is from the past. */
  staleness: (
    <>
      <circle cx="8" cy="8.5" r="4.5" />
      <path d="M8 6v2.5l1.75 1.25" />
      <path d="M3.5 4.5v2h2" />
    </>
  ),
  /* The heartbeat, calm: a flat pulse trace. */
  "anchor-pulse": <path d="M1.5 8h3l1.5-3 2.5 6L11 8h3.5" />,
  /* The heartbeat, breached: the same trace, interrupted. */
  "anchor-lag": (
    <>
      <path d="M1.5 8h3l1.5-3 1 2" />
      <path d="M11.5 8h3" />
      <path d="M8 6.5v3.5" />
      <path d="M8 12.5v.5" />
    </>
  ),
  unknown: (
    <>
      <circle cx="8" cy="8" r="5.5" />
      <path d="M6.5 6.5a1.5 1.5 0 1 1 1.5 1.5V9.5" />
      <path d="M8 11.5v.5" />
    </>
  ),
  /* The P3 alarm: a triangle. Nothing else in the set has corners. */
  "integrity-alert": (
    <>
      <path d="M8 2 14.5 13.5h-13z" />
      <path d="M8 6.5v3.5" />
      <path d="M8 12v.5" />
    </>
  ),
  /* Loading. Three dots, not a spinner: ADR-0038 decision 4 ships no keyframe
   * animation, and doc 06 §5.5 allows motion for "state transitions and focus
   * movement only". The state transition this component makes is the one into
   * the timed-out error. */
  busy: (
    <>
      <circle cx="3.5" cy="8" r="1.25" fill="currentColor" stroke="none" />
      <circle cx="8" cy="8" r="1.25" fill="currentColor" stroke="none" />
      <circle cx="12.5" cy="8" r="1.25" fill="currentColor" stroke="none" />
    </>
  ),
  empty: (
    <>
      <path d="M2.5 5.5h11" />
      <path d="M2.5 8.5h11" />
      <path d="M2.5 11.5h11" strokeDasharray="2 2" />
    </>
  ),
  /* A severed link: the dependency is not there. */
  unreachable: (
    <>
      <path d="M6.5 9.5 4.75 11.25a2.475 2.475 0 0 1-3.5-3.5L3 6" />
      <path d="M9.5 6.5l1.75-1.75a2.475 2.475 0 0 1 3.5 3.5L13 10" />
      <path d="M6 10 10 6" strokeDasharray="1.5 2" />
    </>
  ),
};

export interface IconProps {
  readonly name: IconName;
  /** Extra classes for size or spacing only. Colour comes from currentColor. */
  readonly className?: string;
}

/**
 * A 1em-square icon that inherits its colour from the text it sits beside.
 * Always hidden from assistive technology: the label next to it carries the
 * meaning, and doc 06 §6.4 requires that label to exist.
 */
export function Icon({ name, className }: IconProps) {
  return (
    <svg
      aria-hidden="true"
      focusable="false"
      data-icon={name}
      viewBox="0 0 16 16"
      width="1em"
      height="1em"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.25"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      {PATHS[name]}
    </svg>
  );
}
