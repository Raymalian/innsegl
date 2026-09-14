// SPDX-License-Identifier: Apache-2.0

/*
 * The class strings this component uses — and the only file in the product
 * that spends a green.
 *
 * ADR-0038 decision 4 made `--innsegl-color-proof-verified-*` the one route to
 * a green in the entire build, and doc 06 §5.3 says what that green is allowed
 * to mean: "Green = cryptographic verification passed. Nothing else is ever
 * green." Three lines below reach it. FE-035 asserts that no other file in
 * this directory names it, and FE-034 asserts that nothing in
 * components/common does either, so the audit doc 07's FE-013 performs at the
 * end of Phase 4 has exactly one place to look.
 *
 * The geometry — badge shape, hairline, focus ring, notice layout, the
 * screen-reader class — is imported from components/common rather than
 * restated. There is one badge shape in this product and this is not a second
 * one.
 */

import { hairline as rule } from "../common/styles";

export {
  badgeBase,
  emphasisBorder,
  focusRing,
  hairline,
  identifierText,
  integrityAlert,
  link,
  mutedText,
  noticeBase,
  noticeBody,
  noticeTitle,
  secondaryText,
  srOnly,
  stateTransition,
} from "../common/styles";

/* ── the verification tri-state (doc 06 §4.2, §5.3) ────────────────────────
 * Three groups, three palette families, never collapsed into one another.
 * Each is paired with an icon and a label at every use site (§6.4). */

/** The only green. Spent when, and only when, a live verification passed. */
export const proofVerified =
  "text-proof-verified bg-proof-verified-surface border-proof-verified-line";

/** Red. A check ran and what it checked does not hold. */
export const proofFailed =
  "text-proof-failed bg-proof-failed-surface border-proof-failed-line";

/**
 * Violet. ADR-0047's fourth state: the commit object was rewritten and its
 * signature is gone, and the change it makes is one a signed run recorded.
 *
 * Not the green, which doc 06 §5.3 spends on a live verification passing and
 * nothing else — this is a weaker claim, and saying so in colour is the point.
 * Not the red, which would accuse a genuine signature. Not the amber, which
 * means the check could not run when this one ran and held.
 */
export const proofContent =
  "text-proof-content bg-proof-content-surface border-proof-content-line";

/** Amber. A check could not run — never either of the other two (P2). */
export const proofUnavailable =
  "text-proof-unavailable bg-proof-unavailable-surface border-proof-unavailable-line";

/**
 * Neutral, for two states that are not verdicts about cryptography:
 *
 *   - a commit that claims nothing (VER-006), which is not a failure;
 *   - a check that reported verified inside a panel that did not verify, where
 *     the word and the icon still say what the check said and the colour that
 *     means "this commit is proven" is withheld.
 */
export const proofNeutral = "text-ink-secondary bg-sunken border-line";

/** The panel's own shell. Calm: doc 06 P3 says success is quiet.
 *
 * The verdict band and the check row are flush to its edges, so the shell
 * carries the rounding and clips them (doc 06 §5.4: hairline borders and
 * background steps for structure, no shadows, no gradients). */
export const panelShell = `${rule} flex flex-col overflow-hidden rounded-md bg-surface border-line`;

/* ── the verdict band ──────────────────────────────────────────────────────
 *
 * The first thing on the panel, tinted by the verdict, carrying one word and
 * the reason for it. doc 06 P3 — "design the alarm first" — and §6.4's "never
 * color alone": the tone classes below set the ground, the ProofIcon sets the
 * glyph and the headline sets the word, and all three are present in every
 * state including the calm one. */
export const verdictBand = `${rule} flex flex-wrap items-start gap-4 border-0 border-b p-panel`;
/** The verdict in one word. doc 06 §5.2's display serif: a heading, and the
 * largest thing on the page a reader screenshots into an audit report. */
export const verdictHeadline =
  "font-serif text-heading font-semibold leading-tight tracking-display";
/** The sentence under it: what ran and what it established. Never the serif —
 * this is copy (doc 06 §5.2). */
export const verdictMeaning = "leading-default";
/** The facts at the trailing edge of the band: which commit this verdict is
 * about.
 *
 * NO INK TOKEN, deliberately, and this is the lesson tailwind-theme.css
 * already wrote down for the filled alert: the page's ink scale is defined
 * against the PAGE's ground, and a tinted band is its own ground. Measured on
 * the verified band in dark mode, --innsegl-color-text-muted came out at
 * 4.43:1 against the surface behind it, under doc 06 §6.4's 4.5:1 floor —
 * caught by FE-100, which measures rendered pairs rather than declared ones.
 * Inheriting the band's own text colour makes the contrast here the same
 * assertion contrast-pairs.txt already makes for the band's copy, in every
 * verdict, including ones added later. */
export const verdictAside =
  "flex min-w-0 flex-col items-start gap-1 text-micro sm:ml-auto sm:items-end";

/* ── the three checks ──────────────────────────────────────────────────────
 *
 * Side by side, each its own card. doc 06 §4.1 forbids collapsing them into
 * one icon and the row is the shape that makes the three legible at a glance
 * without any of them being the summary of the others.
 *
 * One column on a narrow viewport, and inside a table cell, which is where
 * VerificationSummary puts this panel — a three-across row in a cell would
 * push the second and third off the side. */
export const checkGrid = "grid list-none grid-cols-1 gap-0 p-0 md:grid-cols-3";
/** One check, one card. The hairline is on the leading edge so the three read
 * as divisions of one row rather than as three separate panels. */
// `min-w-0`: a grid item's min-width is `auto`, which means "no smaller than
// your content". An unbreakable identifier inside then widens the track
// rather than wrapping, whatever the text is told to do. Both halves are
// needed — see identifierText.
export const checkRow = `${rule} flex min-w-0 flex-col gap-2 border-0 border-t p-4 md:border-t-0 md:border-l md:first:border-l-0`;
/** What the check is called. Weight before size (doc 06 §5.2). */
export const checkName = "font-medium leading-tight";
/** The result word above it: small, uppercase, tracked open — the same
 * treatment a metric card's label and a table column header get, because it is
 * the same thing. The TONE comes from the check's own group. */
export const checkResultLabel =
  "inline-flex items-center gap-2 text-micro font-semibold uppercase tracking-label";

/* ── who the commit is attributed to ───────────────────────────────────────
 *
 * The last block, on the sunken ground: the identity the certificate proves,
 * in mono because it is verbatim material a reader compares (doc 06 P4), with
 * the run's own facts beside it and a link into the run. */
export const attributionBlock = `${rule} flex flex-col gap-2 border-0 border-t bg-sunken p-panel`;
export const attributionLabel =
  "text-micro font-semibold uppercase tracking-label text-ink-muted";
export const attributionFacts = "flex flex-wrap gap-x-6 gap-y-2";
export const attributionFactName = "text-ink-muted";

/** Everything under the band: the checks, the comparison, the material. */
export const panelBody = "flex flex-col gap-4 p-panel";

/** The block the two identities sit in, side by side. */
export const comparisonRow = "flex flex-col gap-1";

/**
 * The differing segment (doc 06 §4.1, §6.4).
 *
 * Colour AND a text decoration, because §6.4 requires the mismatch highlight
 * to "also underline/mark the differing text": the underline is a wavy rule
 * from the sheet, so a reader who cannot separate the hues still sees a mark,
 * and the element carrying it is a <mark> so the cue exists in the markup and
 * not only in a stylesheet. The panel additionally names the differing segment
 * in visible prose, which is the one cue no rendering mode can remove.
 */
export const mismatchMark =
  "rounded-sm bg-mismatch-surface px-1 text-mismatch [text-decoration:var(--innsegl-text-decoration-mismatch)]";

/** Amber, unfilled: the reason a set of passing checks is not a verdict. */
export const degradedNotice =
  "text-degraded bg-degraded-surface border-degraded-line";
