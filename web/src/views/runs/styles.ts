// SPDX-License-Identifier: Apache-2.0

/*
 * Every class string this view uses — ADR-0038, doc 06 §5.
 *
 * The same arrangement components/common and components/verification use, for
 * the same reason: there is exactly ONE file in this directory to audit for
 * doc 06 §5.3, and FE-054 scans the directory to keep it that way.
 *
 * Nothing here is a value. Every entry is a Tailwind utility that resolves
 * through `tailwind-theme.css` into `var(--innsegl-…)`, or an arbitrary
 * property naming an `--innsegl-*` token outright where Tailwind has no scale
 * (border width, border style, focus-ring geometry). ADR-0038 deleted
 * Tailwind's default palette, spacing, type, radius and shadow scales, so a
 * utility that is not backed by a token does not compile.
 *
 * There is no green in this file and there is no route to one from here. A
 * verification verdict in this view is rendered by
 * components/verification/VerificationSummary, which owns the only green in
 * the product; a run row spends none of its own. FE-055 audits the rendered
 * output for that rather than trusting this comment.
 *
 * There are no `dark:` variants: every token is a `light-dark()` pair inside
 * the sheet (ADR-0038 decision 3).
 */

/** doc 06 §6.4: "Visible focus states." Geometry from the sheet. */
export const focusRing =
  "focus-visible:outline-focus focus-visible:outline-[length:var(--innsegl-focus-ring-width)] focus-visible:outline-offset-[var(--innsegl-focus-ring-offset)]";

/** A 1px rule that separates without claiming anything. */
const hairlineWidth = "border-[length:var(--innsegl-border-width-hairline)]";

/* The table itself is not this view's to style — FE-121. doc 06 §3.1's recent
 * runs and doc 06 §3.2's runs table are the same treatment, and two copies of
 * it kept in agreement by hand is the thing that drifts. Both draw from
 * components/common/styles.ts and neither restyles a cell alone. */
export {
  cell,
  columnHeader,
  numericCell,
  rowHeader,
  table,
  tableCaption,
  tablePanel,
  tableScroll,
} from "../../components/common/styles";

import { labelText } from "../../components/common/styles";

/* ── the view ─────────────────────────────────────────────────────────────── */

export const view = "flex flex-col gap-4";
export const heading = "font-serif text-display font-semibold leading-tight tracking-display text-ink";

/* ── the filter form ──────────────────────────────────────────────────────── */

export const filterForm = `flex flex-col gap-3 rounded-md p-4 bg-surface border-line border-solid ${hairlineWidth}`;
export const filterGrid = "flex flex-wrap gap-3";
export const filterField = "flex min-w-0 flex-col gap-1";
/* ONE field label in the product (FE-122). A filter's label, a table's column
   header and a cell of the run header's facts strip are the same thing — a
   small word ABOUT a value rather than part of it — and doc 06 §5.4 governs
   all three together. Two views that reached for the same tokens separately
   still drift; this is the same argument FE-121 makes about the two tables,
   one level down. */
export const filterLabel = labelText;
export const filterControl = `rounded-sm bg-page px-2 py-1 text-body text-ink border-line border-solid ${hairlineWidth} ${focusRing}`;
export const filterActions = "flex flex-wrap items-center gap-3";
export const filterHint = "text-micro text-ink-muted";
export const primaryButton = `rounded-sm px-3 py-1 text-body font-medium bg-accent-surface text-accent border-accent-line border-solid ${hairlineWidth} ${focusRing}`;
export const secondaryButton = `rounded-sm px-3 py-1 text-body text-ink-secondary underline underline-offset-2 ${focusRing}`;

/* ── the table ────────────────────────────────────────────────────────────── */

/* The table's own classes are re-exported above, from the one module that owns
 * them. What is left here is what belongs to a RUN row rather than to a table:
 * the stack inside a cell, the task, the repository link, the count. */
export const cellStack = "flex flex-col items-start gap-1";
export const taskText = "text-ink";
export const repoLink = `text-accent underline underline-offset-2 ${focusRing}`;
export const commitCount = "text-ink";

/** A cell saying what it does not hold: no repository, no check. */
export const mutedCell = "text-micro text-ink-muted";

/* The age of the ledger's claim, under the status badge rather than beside it.
   Inline, it wrapped mid-phrase — "last seen 17 / hours ago" — which reads as
   two facts and is exactly the kind of ambiguity this line exists to remove.
   `block` with a little space above puts it on its own line, the way the
   verification cell already stacks its second line. */
export const lastSeenLine = "mt-1 block text-micro text-ink-muted";

/* ── the row's verification cell ──────────────────────────────────────────── */

/* Neutral, deliberately. doc 06 §5.3 gives amber to "verification unavailable"
 * — a verdict — and this is not one: no check was asked for, so there is no
 * result to be unavailable. Painting every row amber would make the calm state
 * loud, which is doc 06 P3 read backwards, and would make an actually
 * unavailable verification harder to see rather than easier. */
export const notChecked = "flex items-start gap-1 text-micro text-ink-muted";

/* ── pagination ───────────────────────────────────────────────────────────── */

export const pager = "flex flex-wrap items-center gap-3 text-body text-ink-secondary";
export const pagerLink = `text-accent underline underline-offset-2 ${focusRing}`;
export const pagerNote = "text-micro text-ink-muted";

/** Visually hidden, still announced (doc 06 §6.4). */
export const srOnly = "sr-only";

/** A list inside a cell: no marker, no indent, the cell's own rhythm. */
export const cellList = "flex flex-col items-start gap-1 list-none p-0";

/* The order control in the Run ID header. A link and not a button: it
   navigates, so it must be copyable and middle-clickable like every other
   filter in this view. Follows repoLink and pagerLink rather than inventing
   a third link idiom. */
export const orderToggle = `text-accent underline underline-offset-2 ${focusRing}`;
