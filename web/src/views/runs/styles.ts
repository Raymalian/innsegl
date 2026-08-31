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
const hairlineBottom =
  "border-b-[length:var(--innsegl-border-width-hairline)]";

/* ── the view ─────────────────────────────────────────────────────────────── */

export const view = "flex flex-col gap-4";
export const heading = "text-heading font-semibold text-ink";

/* ── the filter form ──────────────────────────────────────────────────────── */

export const filterForm = `flex flex-col gap-3 rounded-md p-4 bg-surface border-line border-solid ${hairlineWidth}`;
export const filterGrid = "flex flex-wrap gap-3";
export const filterField = "flex min-w-0 flex-col gap-1";
export const filterLabel = "text-micro font-medium text-ink-secondary";
export const filterControl = `rounded-sm bg-page px-2 py-1 text-body text-ink border-line border-solid ${hairlineWidth} ${focusRing}`;
export const filterActions = "flex flex-wrap items-center gap-3";
export const filterHint = "text-micro text-ink-muted";
export const primaryButton = `rounded-sm px-3 py-1 text-body font-medium bg-accent-surface text-accent border-accent-line border-solid ${hairlineWidth} ${focusRing}`;
export const secondaryButton = `rounded-sm px-3 py-1 text-body text-ink-secondary underline underline-offset-2 ${focusRing}`;

/* ── the table ────────────────────────────────────────────────────────────── */

/* doc 06 §5.4: "tables full-width within it ... compact rows in tables". The
 * cell padding is the sheet's own table-density token, so a rebrand changes
 * the density of every table at once. */
export const tableScroll = "w-full overflow-x-auto";
export const table = "w-full border-collapse text-body text-ink";
export const tableCaption = "text-left text-micro text-ink-secondary pb-2";
export const columnHeader = `px-cell-x py-cell-y text-left align-bottom font-semibold text-ink-secondary border-line border-solid ${hairlineBottom}`;
export const cell = `px-cell-x py-cell-y align-top border-line border-solid ${hairlineBottom}`;
/* A row header is a heading in the accessibility tree, not in the type scale:
 * doc 06 §5.2 puts weight before size and a bolded run id in every row would
 * be noise. */
export const rowHeader = `${cell} text-left font-regular`;
export const cellStack = "flex flex-col items-start gap-1";
export const taskText = "text-ink";
export const repoLink = `text-accent underline underline-offset-2 ${focusRing}`;
export const commitCount = "text-ink";

/** A cell saying what it does not hold: no repository, no check. */
export const mutedCell = "text-micro text-ink-muted";

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
