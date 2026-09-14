// SPDX-License-Identifier: Apache-2.0

/*
 * Every class string this view uses — ADR-0038, doc 06 §5.
 *
 * Same shape and same reason as `components/common/styles.ts`: one file to
 * audit for doc 06 §5.3, so a reviewer asking "where could a green get in"
 * reads this file and is done. `colour-discipline.test.ts` in this directory
 * enforces that no sibling names a surface or border colour of its own.
 *
 * NOTHING HERE IS GREEN, and there is no entry that could become one. doc 06
 * §5.3 gives green to cryptographic verification alone, and this view performs
 * none: it counts rows in a ledger and reports how late an anchor is. The only
 * route to a green in the build is `text-proof-verified`, that belongs to the
 * three-check panel, and the word does not appear below.
 *
 * Nothing here is a value either. Every entry is a Tailwind utility that
 * resolves through `tailwind-theme.css` into `var(--innsegl-…)`, or an
 * arbitrary property naming an `--innsegl-*` token outright. There are no
 * `dark:` variants: every token is a `light-dark()` pair in the sheet.
 */

/** doc 06 §6.4: "Visible focus states." Geometry from the sheet. */
export const focusRing =
  "focus-visible:outline-focus focus-visible:outline-[length:var(--innsegl-focus-ring-width)] focus-visible:outline-offset-[var(--innsegl-focus-ring-offset)]";

export const hairline =
  "border-[length:var(--innsegl-border-width-hairline)] border-solid";

/** Visually hidden, still announced (doc 06 §6.4). */
export const srOnly = "sr-only";

/* ── the page ──────────────────────────────────────────────────────────── */

export const page = "flex flex-col gap-5";
/** The view heading. doc 06 §5.2, amended 2026-09-14: the display serif sets
 * view headings and headline figures, and this is one of the two. */
export const heading = "font-serif text-display font-semibold leading-tight tracking-display";
/** doc 06 §5.4: "air belongs to explanation". */
export const prose = "max-w-prose leading-prose text-ink-secondary";

/* ── metric cards ──────────────────────────────────────────────────────── */

/** doc 06 §5.4: hairline borders and background steps for structure, no
 * shadows and no gradients. */
export const cardGrid = "grid gap-4 sm:grid-cols-2 lg:grid-cols-4";
export const cardBase = "flex flex-col gap-1 rounded-md p-4";
/** Small, uppercase, tracked open — the same treatment a table column header
 * gets, because it is the same thing: a name for the value under it, and not
 * part of the value. Never the serif: doc 06 §5.2 keeps the serif off labels. */
export const cardLabel = "text-micro font-semibold uppercase tracking-label";
/** The headline figure. doc 06 §5.2's second sanctioned serif: "a display
 * serif for view headings and the largest metric figures".
 *
 * A count is a number and not an identifier, so it is not mono (doc 06 §5.2,
 * P4) — but it is tabular, so a column of them lines up. */
export const cardValue =
  "font-serif text-display font-semibold leading-tight tracking-display [font-variant-numeric:var(--innsegl-font-variant-numeric-tabular)]";
/** The same slot, holding a WORD rather than a figure.
 *
 * doc 06 P2's third state — "not verified, not failed, not checked" — is a
 * sentence and not a number, and "Not measured" set at the figure size wraps
 * across two lines in a four-up grid, which makes the card that has the least
 * to say the loudest thing in the row. One step down, same face, same weight:
 * it is still the card's headline, so it is still doc 06 §5.2's headline slot
 * and not a label. */
export const cardValueWord =
  "font-serif text-heading font-semibold leading-tight tracking-display";
/** What the number counts and over what window. doc 06 P1: the meaning travels
 * with the claim. */
export const cardMeaning = "text-micro leading-default";
export const cardRow = "flex items-center gap-2";

/* ── the heartbeat ─────────────────────────────────────────────────────── */

/** The same geometry the shared component uses, so the states this view has to
 * render itself do not look like a different component. */
export const pulseShell =
  "inline-flex items-center gap-2 rounded-md py-1 text-body leading-tight";
export const pulseBreach = `${hairline} px-2`;

/* ── the recent runs table ─────────────────────────────────────────────── */

/* The table's own classes belong to one module and this view is not it — see
 * components/common/styles.ts and FE-121. doc 06 §3.1's recent runs and doc 06
 * §3.2's runs table are one treatment; keeping two copies of it in agreement
 * by hand is what drifts. */
export {
  cell,
  columnHeader,
  numericCell,
  rowHeader,
  table,
  tableCaption,
  tablePanel,
  tablePanelHeader,
  tableScroll,
} from "../../components/common/styles";

/** A panel heading. doc 06 §5.2's serif, and the last of the three places this
 * view spends it. */
export const listHeading = "font-serif text-prose font-semibold leading-tight";
/** The qualification beside a heading — "newest first". Not the serif: it is a
 * sentence about the table, which is copy. */
export const listNote = "text-micro text-ink-muted";

/** A run's agent type and task in a table cell: neither is an identifier a
 * reader recomputes, so neither is mono (doc 06 P4 read the right way round). */
export const cellText = "text-ink";

/*
 * ── the semantic groups ────────────────────────────────────────────────────
 * doc 06 §5.3 read as a table. A component picks a group by what it MEANS.
 */

/** Neutral. Structure and chrome, and every count this view can state exactly. */
export const neutralSurface = "bg-surface border-line text-ink";
export const secondaryText = "text-ink-secondary";
export const mutedText = "text-ink-muted";

/** Amber: "verification unavailable, anchoring lag, staleness" (doc 06 §5.3).
 * The pass-rate card lives here, and the argument for that is in PassRateCard. */
export const degraded = "text-degraded bg-degraded-surface border-degraded-line";
export const degradedText = "text-degraded";

/** Red, filled. The P3 alarm: a verification that failed, or an integrity
 * alert. Nothing else reaches it. */
export const integrityAlert =
  "text-integrity-alert bg-integrity-alert-surface border-integrity-alert-line";

/** The accent: interactive chrome, semantically meaningless (doc 06 §5.3). */
export const link = `text-accent underline underline-offset-2 ${focusRing}`;
