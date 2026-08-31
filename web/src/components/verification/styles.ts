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

/** The panel's own shell. Calm: doc 06 P3 says success is quiet. */
export const panelShell = "flex flex-col gap-4 rounded-md bg-surface p-panel";

/** One check, one block. */
export const checkRow = "flex flex-col gap-1 rounded-md bg-sunken p-3";

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
