// SPDX-License-Identifier: Apache-2.0

/*
 * The class strings this view uses — doc 06 §5, ADR-0038.
 *
 * One file to audit for doc 06 §5.3, exactly as `components/common/styles.ts`
 * and `components/verification/styles.ts` are for their directories. Nothing
 * here is a value: every entry is a Tailwind utility that resolves through
 * `tailwind-theme.css` into `var(--innsegl-…)`, or an arbitrary property
 * naming an `--innsegl-*` token outright.
 *
 * ── THE GREEN IS NOT HERE, AND CANNOT BE ───────────────────────────────────
 *
 * `proof-verified` does not appear in this file or anywhere else in this
 * directory, and FE-086 asserts it. doc 06 §5.3 gives green one meaning —
 * "cryptographic verification passed" — and the only component entitled to
 * make that claim is the three-check panel, which this view composes rather
 * than reimplements. A timeline node is a statement that the ledger holds an
 * event; that is not a verification of anything, and a run that finished is
 * doc 06 §5.3's "not 'run completed'" in as many words.
 *
 * Geometry — badge shape, hairline, focus ring, notice layout, the
 * screen-reader class — is imported from components/common rather than
 * restated. There is one badge shape in this product.
 */

import {
  focusRing as focus,
  hairline as rule,
  stateTransition as transition,
} from "../../components/common/styles";

export {
  badgeBase,
  degraded,
  degradedText,
  emphasisBorder,
  expiredOutline,
  focusRing,
  hairline,
  identifierText,
  integrityAlert,
  link,
  mutedText,
  neutralSurface,
  noticeBase,
  noticeBody,
  noticeTitle,
  popover,
  secondaryText,
  srOnly,
  stateTransition,
} from "../../components/common/styles";

/* ── the page ───────────────────────────────────────────────────────────── */

/** The view's own stack. Air between blocks, density inside them (§5.4). */
export const viewShell = "flex flex-col gap-4";

/** A block: header, timeline, each with a hairline and a raised ground. */
export const block = "flex flex-col gap-3 rounded-md bg-surface p-panel";

/** doc 06 §5.2: weight carries hierarchy before size does. */
export const pageHeading = "text-heading font-semibold leading-tight text-ink";
export const sectionHeading = "text-prose font-semibold leading-tight text-ink";
export const fieldLabel = "text-micro text-ink-muted";

/** The header's field grid: a label above its value, wrapping. */
export const fieldGrid = "flex flex-wrap gap-x-6 gap-y-3";
export const field = "flex min-w-0 flex-col gap-1";

/* ── the timeline ───────────────────────────────────────────────────────── */

/** An ordered list, because the order is the chain (doc 06 §6.4: real
 * semantics, not divs pretending). */
export const timelineList = "flex list-none flex-col gap-2 p-0";

/** One node. The tone classes below replace the ground and the border. */
export const nodeShell = "flex flex-col gap-2 rounded-md p-3";

/** Calm. doc 06 P3: the healthy state is what is left after the alarm. */
export const nodeNeutral = "text-ink bg-sunken border-line";

/* The other two tones a node can take are `degraded` and `integrityAlert`,
 * re-exported above from components/common. They are not restated here:
 * amber means the same thing on a timeline node that it means on a staleness
 * marker, and a second spelling of it is a second thing to keep in agreement.
 *
 *   degraded       an event that says something was started and never
 *                  finished, and the mark on history the reconciler repaired.
 *                  Degraded, not failed (P2).
 *   integrityAlert doc 06 §4.5's drift detection and §5.3's integrity alert,
 *                  which is what the two alert event types of doc 02 §3 are.
 */

/** The node's first line: what happened, and when. */
export const nodeHeadline = "flex flex-wrap items-baseline gap-x-3 gap-y-1";
export const nodeTitle = "font-medium";

/** A row of small facts under a node. */
export const factRow = "flex flex-wrap items-center gap-x-3 gap-y-1";
export const factList = "flex flex-col gap-1 p-0";

/** A disclosure summary: keyboard-operable with a visible focus ring, which
 * is what doc 06 §6.4 asks of every expandable panel. */
export const disclosure = "cursor-pointer list-none";

/** The chain-position marker every node carries (doc 06 §3.3). Monospace,
 * because it is a position in a chain a reader can count against. */
export const chainMarker =
  "font-mono text-micro [font-variant-numeric:var(--innsegl-font-variant-numeric-tabular)]";

/**
 * The affordance that reveals an absolute timestamp — doc 06 §6.2, §6.4.
 *
 * A dotted underline rather than a colour: doc 06 §5.3 gives the accent to
 * interactive chrome, and a timeline dense with times would then be a page of
 * accent-coloured text with no hierarchy left. The underline is the affordance
 * and it survives greyscale. Focus ring and hover ground come from the sheet.
 */
export const timeTrigger =
  `inline-flex max-w-full items-center rounded-sm text-left underline decoration-dotted underline-offset-2 hover:bg-hover ${focus} ${transition}`;

/** A node's outline. Hairline by default; the alert and degraded tones bring
 * their own border colour and this brings the width. */
export const nodeOutline = rule;
