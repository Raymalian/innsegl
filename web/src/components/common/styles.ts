// SPDX-License-Identifier: Apache-2.0

/*
 * Shared class strings — ADR-0038, doc 06 §5.
 *
 * Every colour, space, type size and border width a component in this
 * directory uses is named here, once. Two reasons, and the second is the one
 * that matters:
 *
 *   1. The components read as markup instead of as a wall of utilities.
 *   2. There is exactly one file to audit for doc 06 §5.3. A reviewer asking
 *      "where could a green get in" reads this file and is done; RM-050's
 *      anti-pattern pass (#58) and doc 07's FE-013 have one place to look
 *      rather than nine.
 *
 * Nothing here is a value. Every entry is either a Tailwind utility that
 * resolves through `tailwind-theme.css` into `var(--innsegl-…)`, or an
 * arbitrary property naming an `--innsegl-*` token outright — which is what
 * Tailwind has no scale for (border style, text decoration, focus-ring
 * geometry). ADR-0038 deleted Tailwind's default palette, spacing, type and
 * shadow scales, so a utility that is not backed by a token does not compile.
 *
 * There are no `dark:` variants and there is nothing for one to do: every
 * token is a `light-dark()` pair inside the sheet (ADR-0038 decision 3).
 */

/** doc 06 §6.4: "Visible focus states." Geometry from the sheet, not from Tailwind. */
export const focusRing =
  "focus-visible:outline-focus focus-visible:outline-[length:var(--innsegl-focus-ring-width)] focus-visible:outline-offset-[var(--innsegl-focus-ring-offset)]";

/** A 1px rule that separates without claiming anything (ADR-0038, consequences). */
export const hairline =
  "border-[length:var(--innsegl-border-width-hairline)] border-solid";

export const emphasisBorder =
  "border-[length:var(--innsegl-border-width-emphasis)]";

/** The same rule, on one edge. Table rows separate downwards. */
const hairlineBottom = "border-b-[length:var(--innsegl-border-width-hairline)]";

/* doc 06 §3.2 requires Expired to be "styled distinctly from retired", and
 * doc 06 §5.3 puts both in neutral grey — so the distinction cannot be a hue
 * and this is where it lives instead. The dashed style is a token, so a
 * rebrand can restyle it and no component has to know. */
export const expiredOutline = `border-[length:var(--innsegl-border-width-hairline)] [border-style:var(--innsegl-border-style-status-expired)]`;

/** doc 06 §5.5: state transitions only, and the sheet collapses these to 1ms
 * under prefers-reduced-motion so a component need not ask. */
export const stateTransition =
  "transition-colors duration-[var(--innsegl-motion-duration-fast)] ease-standard";

/** The chip's shell (doc 06 §4.3): monospace, tabular, one-click copyable. */
export const identifierText =
  "font-mono text-body [font-variant-numeric:var(--innsegl-font-variant-numeric-tabular)]";

/** Badge geometry, shared by all three run statuses so only the non-colour
 * cues distinguish them (doc 06 §3.2). */
export const badgeBase =
  "inline-flex items-center gap-1 rounded-pill px-2 py-0 text-micro leading-tight whitespace-nowrap";

/** The three run statuses. Neutral, all of them: none is a verdict (§5.3). */
export const statusActive =
  "text-status-active bg-status-active-surface border-status-active-line";
export const statusRetired =
  "text-status-retired bg-status-retired-surface border-status-retired-line";
export const statusExpired =
  "text-status-expired bg-status-expired-surface border-status-expired-line";

/** A block a whole view can sit under: staleness, empty, error. */
export const noticeBase =
  "flex items-start gap-2 rounded-md p-4 text-body leading-default";

/** A banner title: weight carries the hierarchy before size does (§5.2). */
export const noticeTitle = "text-prose font-semibold leading-tight";

/** The stack a notice puts its title, detail and evidence link into. */
export const noticeBody = "flex flex-col items-start gap-1";

/* ── tables ─────────────────────────────────────────────────────────────────
 *
 * ONE table treatment, used by every table in the product (FE-121).
 *
 * doc 06 §5.4 puts the density in the sheet — "compact rows in tables" — and
 * §5.1 puts every value behind a token so "a downstream deployment can rebrand
 * without touching components". Two tables that reached for the same tokens
 * independently still drift: one grows a header ground, the other keeps a
 * plain rule, and a reader two clicks apart is looking at two products. The
 * runs table (§3.2) and the overview's recent runs (§3.1) draw from here and
 * from nowhere else, so restyling a table restyles both.
 *
 * doc 06 §6.4: "tables are real tables." These classes decorate <table>,
 * <caption>, <th scope="col"> and <th scope="row">; none of them makes a div
 * look like a row.
 */

/** The card a table sits in: a hairline, a rounded corner, and the table's own
 * rules clipped to it (doc 06 §5.4, "hairline borders and background steps for
 * structure"). Both tables sit in one of these, which is most of what makes
 * them read as one treatment. */
export const tablePanel = `${hairline} overflow-hidden rounded-md bg-surface border-line`;
/** A strip above the table, for a heading and its qualification. */
export const tablePanelHeader = `${hairline} flex flex-wrap items-baseline gap-2 border-0 border-b border-line px-cell-x py-3`;

/** doc 06 §5.4: "tables full-width within it." A table that outgrows its
 * column scrolls inside its own shell rather than pushing the page sideways. */
export const tableScroll = "w-full overflow-x-auto";
export const table = "w-full border-collapse text-body text-ink";
/** The table's accessible name. Visible, because doc 06 §6.2 wants the counts
 * a caption carries in front of the eye as well as in the tree. */
export const tableCaption = "px-cell-x py-cell-y text-left text-micro text-ink-muted";
/** Small, uppercase, tracked open, on the sunken ground: a column name is a
 * label about the data and not part of it, and the step in ground is what
 * doc 06 §5.4 means by "background steps for structure". Muted rather than
 * secondary because muted-on-sunken is the pair contrast-pairs.txt asserts. */
export const columnHeader = `bg-sunken px-cell-x py-cell-y text-left align-bottom text-micro font-semibold uppercase tracking-label text-ink-muted border-line border-solid ${hairlineBottom}`;
export const cell = `px-cell-x py-cell-y align-top border-line border-solid ${hairlineBottom}`;
/** A row header is a heading in the accessibility tree, not in the type scale:
 * doc 06 §5.2 puts weight before size and a bolded identifier in every row
 * would be noise. */
export const rowHeader = `${cell} text-left font-regular`;
/** A count lines up down the column or it cannot be compared by eye (§6.2). */
export const numericCell = `${cell} text-right [font-variant-numeric:var(--innsegl-font-variant-numeric-tabular)]`;

/** The one sanctioned elevation (doc 06 §5.4: "no shadows deeper than subtle
 * elevation for popovers"). */
export const popover =
  "absolute z-10 mt-1 max-w-content rounded-md bg-raised p-2 shadow-popover";

/*
 * ── the semantic groups ────────────────────────────────────────────────────
 * doc 06 §5.3, read as a table. A component picks a group by what it MEANS;
 * it never picks a colour. `verified` is absent from this file on purpose:
 * the only route to a green is `text-proof-verified`, that belongs to the
 * three-check panel (RM-043, #51), and nothing in this directory is a
 * cryptographic verification.
 */

/** Amber. Verification unavailable, anchoring lag, staleness (doc 06 §5.3). */
export const degraded =
  "text-degraded bg-degraded-surface border-degraded-line";
export const degradedText = "text-degraded";

/** Red, filled. The P3 alarm and nothing else. */
export const integrityAlert =
  "text-integrity-alert bg-integrity-alert-surface border-integrity-alert-line";

/** Neutral. Structure, chrome, and every run status (doc 06 §5.3). */
export const neutralSurface = "text-ink bg-surface border-line";
export const secondaryText = "text-ink-secondary";
export const mutedText = "text-ink-muted";

/** The accent: interactive chrome, semantically meaningless (doc 06 §5.3).
 *
 * Correct on a page surface. WRONG on a filled alert, which is why `linkOnFill`
 * exists below. */
export const link = `text-accent underline underline-offset-2 ${focusRing}`;

/** A link inside a filled alert banner.
 *
 * The accent is defined against the page ground, and the integrity banner is a
 * red fill. Measured: --innsegl-color-accent-text on
 * --innsegl-color-integrity-alert-surface is **1.07:1** in light mode
 * (#3a3ea1 on #9b1921) — the evidence link on the product's most important
 * alarm was effectively invisible, on the banner whose entire purpose is P1's
 * "links directly to the evidence". doc 06 §6.4 requires AA in both modes.
 *
 * No gate caught it because contrast-pairs.txt asserts declared pairs, and a
 * component may compose any token over any background. The manifest now names
 * this pair; this class is what makes it hold.
 *
 * `text-inherit` takes the banner's own text colour, so the link's contrast is
 * by construction the same assertion already made for the banner's copy, for
 * every alert kind, including ones added later. The underline is what marks it
 * as a link — never colour alone (§6.4). */
export const linkOnFill = `text-inherit underline underline-offset-2 ${focusRing}`;

/** Visually hidden, still announced. doc 06 §6.4 wants truncated identifiers
 * to reach assistive technology; this is how. */
export const srOnly = "sr-only";
