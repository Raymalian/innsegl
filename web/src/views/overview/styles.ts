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

export const page = "flex flex-col gap-4";
export const heading = "text-heading font-semibold leading-tight";
/** doc 06 §5.4: "air belongs to explanation". */
export const prose = "max-w-prose leading-prose text-ink-secondary";

/* ── metric cards ──────────────────────────────────────────────────────── */

/** doc 06 §5.4: hairline borders and background steps for structure, no
 * shadows and no gradients. */
export const cardGrid = "grid gap-4 sm:grid-cols-2 lg:grid-cols-4";
export const cardBase = "flex flex-col gap-1 rounded-md p-4";
export const cardLabel = "text-micro font-medium";
/** A count is a number, not an identifier, so it is not mono (doc 06 §5.2) —
 * but it is tabular, so a column of them lines up. */
export const cardValue =
  "text-display font-semibold leading-tight [font-variant-numeric:var(--innsegl-font-variant-numeric-tabular)]";
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

/* ── the recent runs list ──────────────────────────────────────────────── */

export const listBase = "flex flex-col rounded-md";
export const listRow = `${hairline} flex flex-wrap items-center gap-3 border-0 border-t px-2 py-cell-y first:border-t-0`;
export const listHeading = "text-prose font-semibold leading-tight";

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
