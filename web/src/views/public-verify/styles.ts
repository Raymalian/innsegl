// SPDX-License-Identifier: Apache-2.0

/*
 * Every class string this view uses, named once — the same discipline
 * components/common and components/verification keep, and for the same reason
 * ADR-0038 gives: one file to audit for doc 06 §5.3.
 *
 * The geometry is imported rather than restated. There is one badge shape, one
 * hairline, one focus ring and one notice layout in this product, and a view
 * that drew its own would be a second design language wearing the first one's
 * tokens.
 *
 * WHAT IS DELIBERATELY ABSENT: a green. `--innsegl-color-proof-verified-*` is
 * reachable from components/verification/styles.ts and from nowhere else, and
 * this view spends none. Everything on this page that means "this commit is
 * proven" is rendered by the three-check panel, which is the only component
 * entitled to say it. FE-064 asserts the absence from this directory's
 * sources; FE-007 asserts it from the rendered output of ten failure modes.
 */

export {
  badgeBase,
  degraded,
  focusRing,
  hairline,
  identifierText,
  link,
  mutedText,
  neutralSurface,
  noticeBase,
  noticeBody,
  noticeTitle,
  secondaryText,
  srOnly,
  stateTransition,
} from "../../components/common/styles";

/** The page. doc 06 §5.4: a fixed max content width, air around explanation. */
export const pageShell = "flex flex-col gap-6";

/** doc 06 §5.4: "Generous line height in prose panels". */
export const proseText = "max-w-prose leading-prose text-ink-secondary";

/** The question the page asks. doc 06 §5.2's display serif: a view heading,
 * and the largest thing on a page a stranger screenshots into a report. */
export const pageHeading =
  "font-serif text-display font-semibold leading-tight tracking-display text-balance";

/** One block of the proof chain. */
export const sectionShell = "flex flex-col gap-2 rounded-md bg-surface p-panel";

export const sectionHeading = "text-heading font-semibold leading-tight";

/** A label/value pair. The label is prose, the value is verbatim material. */
export const factList = "flex flex-col gap-2";
export const factRow = "flex flex-col gap-1";
export const factLabel = "text-micro text-ink-muted";

/** A block of material a reader copies: PEM, JSON, a commit object. */
export const materialBlock =
  "overflow-x-auto rounded-sm bg-sunken p-3 font-mono text-micro leading-default";

/** doc 06 §6.4: "tables are real tables". This one is the live-check record. */
export const table = "w-full border-collapse text-body";
export const tableHeaderCell =
  "border-b-[length:var(--innsegl-border-width-hairline)] border-solid border-line px-cell-x py-cell-y text-left text-micro font-medium text-ink-muted";
export const tableCell =
  "border-b-[length:var(--innsegl-border-width-hairline)] border-solid border-line px-cell-x py-cell-y align-top";

/** The form. Read-only product, so the only control is a read (doc 06 P6). */
export const fieldStack = "flex flex-col gap-1";
export const fieldLabel = "font-medium";
export const fieldInput =
  "w-full rounded-sm border-[length:var(--innsegl-border-width-hairline)] border-solid border-line-strong bg-raised px-3 py-2 font-mono text-body text-ink";
export const submitButton =
  "self-start rounded-sm border-[length:var(--innsegl-border-width-hairline)] border-solid border-accent-line bg-accent-surface px-4 py-2 font-medium text-accent whitespace-nowrap";

/** The SHA and its control on one row (doc 06 §3.6, the approved artboard).
 *
 * A commit SHA is 40 characters of mono and the control that acts on it is two
 * words: stacking them put the button under a field the width of the page,
 * which reads as two separate steps. `items-end` rather than `items-center`
 * because the field carries a label above it and a hint below, and the control
 * has to line up with the input rather than with the block. Wraps on a narrow
 * viewport, where a full-width control is the right answer instead. */
export const fieldRow = "flex flex-wrap items-end gap-3";
/** The field half of that row: it takes the space, the control does not. */
export const fieldGrow = "flex min-w-[16rem] flex-1 flex-col gap-1";
