// SPDX-License-Identifier: Apache-2.0

/*
 * Class strings for the run page — doc 06 §5, mirroring run-detail/styles.ts
 * and components/common/styles.ts's own discipline: nothing here is a raw
 * value, every entry is a Tailwind utility that resolves through
 * tailwind-theme.css into a token, or an arbitrary property naming one
 * outright. Layout widths that have no token (the 300px aside, the 1440px
 * artboard this page was built against) are arbitrary Tailwind values, which
 * is not a colour and so is not what "no raw hex outside the token files"
 * governs.
 */

import {
  badgeBase,
  focusRing,
  hairline,
  identifierText,
  integrityAlert,
  labelText,
  link,
  mutedText,
  neutralSurface,
  noticeBase,
  secondaryText,
  srOnly,
  stateTransition,
} from "../../components/common/styles";

export {
  badgeBase,
  focusRing,
  hairline,
  identifierText,
  integrityAlert,
  labelText,
  link,
  mutedText,
  neutralSurface,
  noticeBase,
  secondaryText,
  srOnly,
  stateTransition,
};

/* ── page shell ─────────────────────────────────────────────────────────── */

export const viewShell = "flex flex-col gap-3";
export const breadcrumb = `flex flex-wrap items-center gap-1 text-micro ${mutedText}`;

export const headerRow = "flex flex-wrap items-end gap-4";
export const pageHeading = "font-serif text-display font-semibold leading-tight tracking-display text-ink";

/** The status pill: word, icon and the run's age, all three (§6.4). */
export const statusPill = `${badgeBase} ${hairline} gap-2 px-3 py-1 text-micro ${neutralSurface}`;

export const bodyNote = `text-micro ${mutedText}`;

/* ── fact cards ─────────────────────────────────────────────────────────── */

export const factGrid = "grid grid-cols-2 gap-3 md:grid-cols-4";
export const factCard = `${hairline} flex flex-col gap-1 rounded-md bg-surface border-line p-3`;
export const factLabel = labelText;
export const factValue = "mt-1 text-body text-ink";
export const factRowIcon = "flex items-center gap-2";

/* ── two-column layout ─────────────────────────────────────────────────── */

export const columns = "flex min-h-0 flex-grow gap-6";
export const aside = "flex w-[300px] shrink-0 flex-col gap-4";
export const mainColumn = "flex min-w-0 flex-grow flex-col gap-4";

/* ── panels, shared by aside and main ──────────────────────────────────── */

export const panel = `${hairline} flex flex-col rounded-md bg-surface border-line`;
export const panelHeadingRow = `${hairline} flex items-center gap-2 border-0 border-b border-line px-3 py-2`;
export const panelHeading = "flex-grow text-prose font-semibold text-ink";
export const panelBody = "flex flex-col gap-0.5 p-2";
export const panelFooter = `${hairline} flex flex-wrap gap-3 border-0 border-t border-line px-3 py-2 text-micro ${secondaryText}`;
export const panelPad = "flex flex-col gap-1 p-3";

/* ── agent tree ─────────────────────────────────────────────────────────── */

export const treeRow = `flex items-center gap-2 rounded-sm px-2 py-1.5 text-body text-ink ${focusRing} ${stateTransition}`;
export const treeRowSelected = "bg-accent-surface";
export const treeRowChild = "pl-[26px]";
export const treeRowIcon = "shrink-0";
export const treeRowName = "truncate";
export const treeRowId = `ml-auto shrink-0 text-micro ${mutedText}`;

/* ── files changed ─────────────────────────────────────────────────────── */

export const filesFolderRow = `flex items-center gap-1.5 px-2 py-1 text-micro ${secondaryText}`;
export const fileRow = `flex items-center gap-2 rounded-sm px-2 py-1 pl-6 text-body text-ink ${focusRing} ${stateTransition}`;
export const fileStatusLetter = `${hairline} flex w-4 shrink-0 items-center justify-center rounded-sm text-[10px] font-medium leading-none ${secondaryText}`;
export const fileName = "truncate";
export const fileCount = `ml-auto shrink-0 text-micro ${mutedText}`;
export const fileSubNote = `pl-8 text-micro ${mutedText}`;
export const legendRow = `flex flex-wrap gap-3 text-micro ${secondaryText}`;

/* ── commits aside ─────────────────────────────────────────────────────── */

export const commitLink = `${identifierText} ${link}`;

/* ── brief / reply ─────────────────────────────────────────────────────── */

export const briefHeadRow = "flex flex-wrap items-baseline gap-3";
export const briefCaption = `text-micro ${mutedText}`;
export const briefBody = "mt-2 text-prose leading-prose text-ink";
export const replyRow = `${panel} flex gap-3 p-3`;
export const replyGutter = `w-5 shrink-0 text-micro ${mutedText}`;

/* ── timeline heading + toggle ─────────────────────────────────────────── */

export const timelineHeadRow = "flex items-center gap-3";
export const timelineHeading = "flex-grow text-prose font-semibold text-ink";
export const toggleGroup = `${hairline} inline-flex overflow-hidden rounded-md text-micro border-line`;
export const toggleButton = `px-3 py-1.5 font-inherit ${stateTransition} ${focusRing}`;
export const toggleButtonIdle = `bg-surface ${secondaryText} hover:bg-hover`;
export const toggleButtonSelected = "bg-accent-surface font-semibold text-accent";

/* ── step card ─────────────────────────────────────────────────────────── */

export const stepHeaderRow = "flex flex-wrap items-center gap-3 px-4 py-3";
export const stepNumber = `w-5 shrink-0 text-micro ${mutedText} ${identifierText}`;
export const stepTool = "w-16 shrink-0 font-medium text-ink";
export const stepSummary = `min-w-0 flex-grow truncate ${identifierText} text-micro text-ink-secondary`;
export const stepOutcomeOk = "flex shrink-0 items-center gap-1 text-micro text-ink-secondary";
export const stepOutcomeFailed = `${hairline} flex shrink-0 items-center gap-1 rounded-sm px-2 py-0.5 text-micro ${secondaryText}`;
export const stepTime = `w-[70px] shrink-0 text-right text-micro ${mutedText}`;
export const stepWitnessText = `w-[160px] shrink-0 text-right text-micro ${mutedText}`;
export const stepWitnessBadge = `${badgeBase} ${hairline} ml-auto shrink-0 gap-1 px-2 py-0.5 font-semibold ${integrityAlert}`;

export const stepOutputBlock = `${hairline} mx-4 mb-3 whitespace-pre-wrap break-words rounded-md border-line bg-sunken p-2.5 ${identifierText} text-ink`;
export const stepRefusedNote = `mx-4 -mt-1.5 mb-3 text-micro ${mutedText}`;
export const stepAgentLine = "px-4 pb-1 text-body text-ink";
export const stepAgentNote = `px-4 pb-3 text-micro ${secondaryText}`;

export const witnessGrid = "mx-4 mb-3 grid grid-cols-1 gap-2 text-micro sm:grid-cols-3";
export const witnessCell = `${hairline} flex flex-col gap-1 rounded-md border-line p-2`;
export const witnessCellFailed = `border-integrity-alert-line bg-integrity-alert-surface`;
export const witnessCellLabel = mutedText;
export const witnessCellLabelFailed = "text-integrity-alert";
export const witnessCellResult = "flex items-center gap-1.5";

/* ── diff renderer ─────────────────────────────────────────────────────── */

export const diffShell = `${hairline} mx-4 mb-3 overflow-hidden rounded-md border-line ${identifierText} text-micro`;
export const diffFileHeader = `${hairline} flex flex-wrap items-center gap-2 border-0 border-b border-line bg-sunken px-2.5 py-1.5 text-ink-secondary`;
export const diffAdditions = "text-diff-added-marker";
export const diffDeletions = "text-diff-removed-marker";

export const diffRowUnified = "flex";
export const diffLineNoBase = "w-11 shrink-0 py-0.5 px-2 text-right text-ink-muted";
export const diffMarkerBase = "w-5 shrink-0 py-0.5 text-center";
export const diffTextBase = "min-w-0 flex-grow whitespace-pre px-2 py-0.5 text-ink";

export const diffAddedRow = "bg-diff-added-surface";
export const diffRemovedRow = "bg-diff-removed-surface";
export const diffAddedGutter = "bg-diff-added-gutter";
export const diffRemovedGutter = "bg-diff-removed-gutter";
export const diffAddedMarker = "text-diff-added-marker";
export const diffRemovedMarker = "text-diff-removed-marker";

export const sideBySideGrid = "grid grid-cols-1 sm:grid-cols-2";
export const sideBySideCol = `${hairline} border-0 sm:border-l sm:first:border-l-0 border-line`;

/* ── commit card ───────────────────────────────────────────────────────── */

export const commitCard = `${hairline} mx-4 mb-4 rounded-md border-line`;
export const commitCardHeadRow = `${hairline} flex flex-wrap items-center gap-3 border-0 border-b border-line p-3`;
export const commitCardTitle = "font-semibold text-ink";
export const commitCardSha = `${identifierText} ${link}`;
export const commitCardSubject = secondaryText;
export const notLandedNote = `ml-2 text-micro ${secondaryText}`;

export const checkGrid = "grid grid-cols-1 gap-3 p-3 sm:grid-cols-3";
export const checkLabel = `text-micro ${mutedText}`;
export const checkResult = "mt-1 flex items-center gap-1.5 font-medium";
/* The three check tones. `text-proof-*` is a Tailwind utility resolving
 * through tailwind-theme.css to the governed token — the same class name
 * components/verification/styles.ts declares, spent here for the same
 * reason: this card renders an ACTUAL live verification result, which is
 * exactly what doc 06 §5.3 reserves the green for. check-tokens.sh governs
 * the token SHEET, not which component may reference an existing utility. */
export const checkResultOk = "text-proof-verified";
export const checkResultFailed = "text-proof-failed";
export const checkResultUnavailable = "text-proof-unavailable";

export const commitCardFooter = `${hairline} flex flex-wrap items-center gap-4 border-0 border-t border-line px-3 py-2 text-micro ${secondaryText}`;

/* ── never-committed / not-landed callouts (States board) ─────────────── */

export const calloutGrid = "grid grid-cols-1 gap-4 md:grid-cols-2";
export const calloutCard = `${panel} p-3`;
export const calloutHeading = "mb-2 text-prose font-semibold text-ink";
export const calloutRow = "flex flex-wrap items-center gap-2";
export const calloutCaption = `mt-2 text-micro ${secondaryText}`;
