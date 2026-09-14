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
  badgeBase as badge,
  focusRing as focus,
  hairline as rule,
  labelText,
  stateTransition as transition,
} from "../../components/common/styles";

export {
  alarmText,
  badgeBase,
  degraded,
  degradedText,
  emphasisBorder,
  expiredOutline,
  factCell,
  factStrip,
  factValue,
  focusRing,
  hairline,
  identifierText,
  labelText,
  integrityAlert,
  link,
  mutedText,
  neutralSurface,
  noticeBase,
  numericCell,
  noticeBody,
  noticeTitle,
  popover,
  secondaryText,
  srOnly,
  stateTransition,
  /* The one table treatment in the product (FE-121). The credential expiry
   * history doc 06 §3.3 asks for is rows of one shape — issued, expires,
   * audience, chain position — so it is a real table (doc 06 §6.4), and it
   * draws from the same module the runs table and the overview's recent runs
   * draw from rather than growing a third set of cell classes. */
  cell,
  columnHeader,
  table,
  tableCaption,
  tablePanel,
  tableScroll,
} from "../../components/common/styles";

/* ── the page ───────────────────────────────────────────────────────────── */

/** The view's own stack. Air between blocks, density inside them (§5.4). */
export const viewShell = "flex flex-col gap-4";

/** A block: a panel with a raised ground, for content dense enough to need
 * one. The activity log is one; the timeline is deliberately not (below). */
export const block = "flex flex-col gap-3 rounded-md bg-surface p-panel";

/** The timeline's panel, which is not one.
 *
 * The rail sits on the PAGE ground, and that is load-bearing rather than
 * cosmetic: doc 06 §5.4 builds structure out of "hairline borders and
 * background steps", and a step only exists if there is something to step from.
 * On a raised surface the commit card and the two bands were a card on a card
 * and read as neither. The pairs this puts on the page ground — muted and
 * secondary ink, the accent — are all declared in contrast-pairs.txt and
 * measured in both modes by FE-100. */
export const timelinePanel = "flex flex-col gap-3";

/** doc 06 §5.2: weight carries hierarchy before size does — and since the
 * amendment of 2026-09-14, a view heading is set in the display serif. This is
 * a heading and not an identifier: the run's SPIFFE ID is rendered under it in
 * mono, where P4 puts it. */
export const pageHeading =
  "font-serif text-display font-semibold leading-tight tracking-display text-ink";
export const sectionHeading = "text-prose font-semibold leading-tight text-ink";

/** A field label. ONE class string, shared with the runs view's filter labels
 * and with every table's column headers — see components/common/styles.ts's
 * `labelText` for why the three are the same thing (FE-122). */
export const fieldLabel = labelText;

/** The run's identity, directly under the heading and carrying no label of its
 * own (doc 06 §3.3, P4).
 *
 * A label here would be answering a question nobody asked: a SPIFFE ID is
 * self-describing to the reader this page is for, and the word "Agent identity"
 * above it took a line of the header to restate the URI scheme. `min-w-0` is
 * what lets the chip's `break-all` actually take effect inside a flex column. */
export const identityLine = "flex min-w-0 flex-col";

/** The header's own stack: heading, identity, strip. */
export const headerStack = "flex flex-col gap-3";

/* ── the timeline ───────────────────────────────────────────────────────── */

/** An ordered list, because the order is the chain (doc 06 §6.4: real
 * semantics, not divs pretending). */
export const timelineList = "flex list-none flex-col p-0";

/* ── THE RAIL ────────────────────────────────────────────────────────────────
 *
 * doc 06 §3.3's timeline is "the ordered event chain from the ledger", and the
 * order is the evidence. A stack of panels does not draw an order — it draws a
 * set, and a reader has to infer the sequence from the chain positions printed
 * inside each one. The rail draws it: one marker per event, a connector between
 * markers, content to the right of both.
 *
 * The connector stops at the last marker. A line continuing past it would be a
 * stroke asserting that the chain goes on beyond what this response holds,
 * which is a claim about events that are not on the page (P1).
 *
 * The rail and its markers are NEUTRAL, and that is governed rather than
 * chosen. doc 06 §5.3 gives colour a meaning in this product; a node is a
 * statement that the ledger holds an event, which is not a verdict on anything,
 * and a coloured rail would put a claim under every row. The severity of an
 * event is carried by the band around its CONTENT, where it belongs.
 */
export const railRow = "grid grid-cols-[var(--innsegl-space-5)_minmax(0,1fr)] gap-3";
/** The gutter: the marker, then the connector filling whatever is left. */
export const railGutter = "flex flex-col items-center gap-1 pt-1";
/** The connector. A hairline-wide rule in the hairline's own colour, so the
 * rail is the same weight as every other division on the page (doc 06 §5.4). */
export const railLine =
  "w-[length:var(--innsegl-border-width-hairline)] flex-1 bg-line";
/** The marker itself. Muted, because it is structure and not a verdict. */
export const railMarker = "text-ink-muted";

/** A node's content, and the space under it that the connector spans. */
export const nodeBody = "flex min-w-0 flex-col gap-2 pb-4";

/**
 * A node the reader should stop at. The tone classes bring the ground and the
 * border colour; this brings the box.
 *
 * ORDINARY EVENTS DO NOT GET ONE. doc 06 P3 designs the alarm first, and what
 * follows from that is a rule about the calm state: a timeline that draws every
 * event as a panel has spent its whole vocabulary on the ordinary case and has
 * nothing left to say "this one is different" with. The amber band and the red
 * fill work because the rows around them are bare.
 */
export const nodeBand = `${rule} rounded-md p-3`;

/**
 * A recorded commit: the one ordinary event that IS a document.
 *
 * doc 06 §3.3 makes the per-commit three-check panel "the load-bearing
 * component", and this node is where a reader reaches it — repository, commit
 * SHA, Rekor entry, and the control that runs the checks. It gets a card for
 * that reason and not for emphasis, so the card is neutral: doc 06 §5.3 is
 * explicit that a commit the ledger holds is not a verification, and the green
 * stays behind the panel the card opens.
 */
export const commitCard = `${rule} rounded-md p-3 text-ink bg-surface border-line`;

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
  "font-mono text-micro text-ink-muted [font-variant-numeric:var(--innsegl-font-variant-numeric-tabular)]";

/**
 * The summary of a folded run of tool calls — doc 06 §3.3's "count, expandable
 * to digests" as one control rather than as a line of text.
 *
 * A pill, because it is the only thing on the rail a reader can open and it has
 * to look like it. It sits on the panel's own ground with a hairline, which is
 * the one place in this timeline a neutral outline appears around something
 * that is not an exception — a control is allowed to look like a control
 * (doc 06 §5.3 gives interactive chrome no semantic weight).
 */
/** The count inside the fold pill: the only bold thing on it, because the
 * count is what the reader is choosing between. */
export const foldCount = "font-medium";

export const foldPill =
  `${rule} inline-flex max-w-full flex-wrap items-center gap-2 rounded-pill px-3 py-1 text-ink bg-surface border-line ${focus} ${transition} cursor-pointer list-none`;

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

/* ── the tab control ────────────────────────────────────────────────────── */

/** The tab row: the strip, and whatever must stay on screen beside it.
 * `items-end` so a chip sits on the tabs' own baseline rather than floating. */
export const tabRow = "flex flex-wrap items-end justify-between gap-2";

/** The strip. It sits on the page ground, above the panels, which are the
 * surfaces — so a tab's own ground is what tells the two states apart. */
export const tabStrip = "flex flex-wrap items-center gap-1";

/**
 * The one thing that must not hide behind a tab — doc 06 P3, §4.5.
 *
 * FE-113 put the integrity BANNER outside both panels because "a condition
 * behind an unselected tab is a condition the reader is not told about at all".
 * A tool-call body that does not hash to the digest the ledger recorded is such
 * a condition, and it is worse placed than the banner's: it can only be found
 * in the tab that is not open by default, because doc 02 §3 gives a `tool_call`
 * event no member for its body and the timeline therefore has nothing to
 * compare.
 *
 * Filled red, and the same filled red the banner uses. doc 06 §5.3 gives red to
 * "verification failed or integrity alert" and a digest that does not match is
 * the first of those; a second, softer red for the same class of claim would be
 * the drift §5.3 exists to prevent. The fill rebinds the ink tokens inside
 * itself (tailwind-theme.css), so the icon and the words are legible on it by
 * construction.
 */
export const alertChip = `${badge} ${rule} px-2 py-1 font-semibold`;

const tabBase =
  `inline-flex items-center gap-2 rounded-sm px-3 py-2 text-prose leading-tight ${focus} ${transition}`;

/** Not the tab you are on. */
export const tabIdle = `${tabBase} font-normal text-ink-secondary hover:bg-hover`;

/**
 * The tab you are on — the same treatment the shell's nav rail gives the view
 * you are on, because it is the same statement.
 *
 * doc 06 §5.3 gives the accent to interactive chrome and gives it no meaning,
 * which is exactly what "this is the one that is open" needs: a tab is not a
 * verdict and must not be coloured like one. And the state is never carried by
 * the colour alone (§6.4) — the weight changes too, so it survives greyscale,
 * and `aria-selected` carries it to a screen reader.
 */
export const tabSelected = `${tabBase} font-semibold bg-accent-surface text-accent`;

/**
 * The count on a tab: what is behind the tab, for a reader who is not looking
 * at it. Smaller than the label, because it is not what the tab IS — but it
 * takes the tab's own colour rather than a muted one, so it cannot end up as
 * the one pair on this page that nobody measured against the selected tab's
 * ground. Tabular figures so two tabs' counts sit on the same rhythm.
 */
export const tabCount =
  "text-micro [font-variant-numeric:var(--innsegl-font-variant-numeric-tabular)]";
