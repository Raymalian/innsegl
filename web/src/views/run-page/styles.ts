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
  statusActive,
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
  statusActive,
};

/** A 1px rule one shade stronger than `hairline` — the mockup's own `c8d0d5`
 * on a search box, a toggle group, and the "Reported back" card's own
 * border. */
export const hairlineStrong = "border-[length:var(--innsegl-border-width-hairline)] border-solid border-line-strong";

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
/* Sentence case, not the shared `labelText`'s uppercase/tracked treatment —
 * the mockup's own fact-card labels ("Identity", "Repository · branch") are
 * plain sentence case, which this page follows over the rest of the
 * product's table/column-header convention (doc06 §5.4 says sentence case
 * "everywhere", and the approved mockup is the one place that reading and
 * `labelText`'s established uppercase disagree). */
export const factLabel = `text-micro ${mutedText}`;
export const factValue = "mt-1 text-body text-ink";
/* The identity card's chip at the mockup's 12px, so the SPIFFE ID sits on
 * one line in a fact card; the chip itself sets the body size everywhere
 * else. */
export const factIdentity =
  "[&_[data-identifier-display]]:text-micro [&_[data-identifier-display]]:min-w-0 [&_[data-identifier-display]]:truncate [&_[data-identifier-display]]:break-normal";
/* A witness disagreement is an alarm (doc 06 P3): the failure tone. */
export const factValueFailed = "text-proof-failed font-medium";
export const factRowIcon = "flex items-center gap-2";

/* ── two-column layout ─────────────────────────────────────────────────── */

export const columns = "flex min-h-0 flex-grow gap-6";
/* #443: the agent page puts the aside on the right at 320px (Agent.dc.html /
 * Session.dc.html), not the left at 300px the old Main.dc.html used. */
export const aside = "flex w-[320px] shrink-0 flex-col gap-4";
export const mainColumn = "flex min-w-0 flex-grow flex-col gap-4";

/* ── panels, shared by aside and main ──────────────────────────────────── */

export const panel = `${hairline} flex flex-col rounded-md bg-surface border-line`;
/** A step card the browser may skip laying out and painting while it is off
 * screen (#442); the reserved height keeps the scrollbar steady. */
export const stepCardDeferred = "[content-visibility:auto] [contain-intrinsic-size:auto_160px]";
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
/* `min-w-0` is load-bearing, not decoration — see identifierText's own
 * comment in components/common/styles.ts for the measured failure this
 * exact omission causes: a flex item's min-width is `auto` by default, so
 * without it "truncate" never actually shrinks the name and the id chip
 * beside it gets squeezed instead. MEASURED here: "general-purpose" rendered
 * as "general-purp…" in the 300px aside before this was added. */
/* An agent's name is never cut; its run id, which the chip already
 * shortens and can copy whole, gives way first. */
export const treeRowName = "shrink-0";
export const treeRowId = `ml-auto min-w-0 truncate text-micro ${mutedText}`;

/* ── files changed ─────────────────────────────────────────────────────── */

export const filesFolderRow = `flex items-center gap-1.5 px-2 py-1 text-micro ${secondaryText}`;
export const fileRow = `flex items-center gap-2 rounded-sm px-2 py-1 pl-6 text-body text-ink ${focusRing} ${stateTransition}`;
const fileStatusLetterBase = "flex w-4 shrink-0 items-center justify-center rounded-sm border text-[10px] font-medium leading-none";
/* The changed-files list shares the diff's two hues (doc 06 §5.3's named
 * exception): an added file's A and a deleted file's D; M and R stay neutral. */
export const fileStatusLetter = {
  added: `${fileStatusLetterBase} border-diff-added-gutter text-diff-added-marker`,
  removed: `${fileStatusLetterBase} border-diff-removed-gutter text-diff-removed-marker`,
  neutral: `${hairline} ${fileStatusLetterBase} ${secondaryText}`,
} as const;
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

/** A quiet secondary button: "Show more steps", "Show full output" (#440). */
export const showMoreButton = `${hairline} self-start rounded-md border-line px-3 py-1.5 text-micro ${toggleButtonIdle} ${stateTransition} ${focusRing}`;
export const stepShowFull = `${hairline} mx-4 mb-3 self-start rounded-md border-line px-2.5 py-1 text-micro ${toggleButtonIdle} ${stateTransition} ${focusRing}`;

/* ── step card ─────────────────────────────────────────────────────────── */

/* One row, as the approved mockup shows it: the summary truncates, the
 * outcome, time and witnesses never wrap under it. */
export const stepHeaderRow = "flex items-center gap-3 px-4 py-3 [&>*:not([data-summary])]:shrink-0";
export const stepNumber = `w-5 shrink-0 text-micro ${mutedText} ${identifierText}`;
export const stepTool = "w-16 shrink-0 font-medium text-ink";
export const stepSummary = `min-w-0 flex-grow truncate ${identifierText} text-micro text-ink-secondary`;
export const stepOutcomeOk = "flex shrink-0 items-center gap-1 text-micro text-ink-secondary";
export const stepOutcomeFailed = `${hairline} flex shrink-0 items-center gap-1 rounded-sm px-2 py-0.5 text-micro ${secondaryText}`;
export const stepTime = `w-[70px] shrink-0 text-right text-micro ${mutedText}`;
export const stepWitnessText = `w-[160px] shrink-0 text-right text-micro ${mutedText}`;
export const stepWitnessBadge = `${badgeBase} ${hairline} ml-auto shrink-0 gap-1 px-2 py-0.5 font-semibold ${integrityAlert}`;

export const stepOutputBlock = `${hairline} mx-4 mb-3 max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-md border-line bg-sunken p-2.5 ${identifierText} text-ink`;
export const stepRefusedNote = `mx-4 -mt-1.5 mb-3 text-micro ${mutedText}`;
export const stepAgentSummary = "min-w-0 flex-grow truncate text-body text-ink-secondary";
export const stepAgentNote = `px-4 pb-3 text-micro ${secondaryText}`;

export const witnessGrid = "mx-4 mb-3 grid grid-cols-1 gap-2 text-micro sm:grid-cols-3";
export const witnessCell = `${hairline} flex flex-col gap-1 rounded-md border-line p-2`;
/* The missing witness, as the approved mockup draws it: a soft red cell
 * with red text, beside the solid "2 of 3 witnesses" badge that carries the
 * alarm. */
export const witnessCellFailed = `border-proof-failed-line bg-proof-failed-surface`;
export const witnessCellLabel = mutedText;
export const witnessCellLabelFailed = "text-proof-failed";
export const witnessCellResultFailed = "text-proof-failed font-medium";
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

/* ── #443: the agent page — lineage nav, fact cards, asked/reported,
 * agents-started table, and the compact step table ──────────────────────── */

/* lineage nav */
export const lineageNav = `flex flex-wrap items-center gap-2 text-micro ${secondaryText}`;
export const lineagePill = `${hairline} inline-flex items-center gap-1.5 rounded-pill border-line bg-surface px-2.5 py-1 text-ink ${focusRing} ${stateTransition}`;
export const lineagePillCurrent = "inline-flex items-center gap-1.5 whitespace-nowrap rounded-pill bg-accent-surface px-2.5 py-1 font-semibold text-accent-emphasis";
export const lineageSeparator = `shrink-0 ${mutedText}`;
export const lineageLink = `${secondaryText} ${focusRing} rounded-sm`;

/* kicker + heading + status pill */
export const kicker = `text-micro tracking-label ${mutedText}`;
export const statusPillActive = `${badgeBase} ${hairline} gap-1.5 px-3 py-1 text-micro ${statusActive}`;

/* fact cards reuse factGrid/factCard/factLabel/factValue, declared above */

/* asked / reported */
export const askedCard = `${panel} p-4`;
export const reportedCard = `${hairlineStrong} flex flex-col rounded-md bg-surface p-4`;
export const cardHeadRow = "flex flex-wrap items-baseline gap-3";
export const cardKicker = `text-micro ${mutedText}`;
export const cardShowAll = `ml-auto shrink-0 text-micro ${link}`;
export const askedBody = "mt-2 whitespace-pre-wrap text-body leading-prose text-ink";
export const reportedBody = "mt-2 whitespace-pre-wrap text-body leading-prose text-ink";

/* "What it ran" section head, shared by both roles */
export const sectionHeadRow = "flex flex-wrap items-center gap-3";
export const sectionHeading = "flex-grow text-prose font-semibold text-ink";
export const sectionSub = `text-micro ${mutedText}`;

/* the step table */
export const stepTable = panel;
export const stepTableHeadRow = `${hairline} flex items-center gap-3 border-0 border-b border-line px-4 py-2 text-micro ${mutedText}`;
export const rowCellN = "w-6 shrink-0 text-micro text-ink-muted";
export const rowCellTool = "w-[72px] shrink-0 font-semibold text-ink";
export const rowCellMain = `min-w-0 flex-grow truncate text-left ${identifierText} text-micro text-ink-secondary`;
export const rowCellProse = "min-w-0 flex-grow truncate text-left text-body text-ink-secondary";
export const rowCellResult = "w-[60px] shrink-0 text-micro text-ink-secondary";
export const rowCellTime = `w-[70px] shrink-0 text-right text-micro ${mutedText}`;
export const stepRowButton = `${hairline} flex w-full items-center gap-3 border-0 border-b border-line bg-surface px-4 py-2.5 text-left font-inherit text-body text-ink ${focusRing} ${stateTransition} hover:bg-hover`;
export const stepRowStatic = `${hairline} flex items-center gap-3 border-0 border-b border-line px-4 py-2.5 text-body text-ink`;
export const stepRowOpen = "flex-col items-stretch bg-sunken";
export const stepGroupRow = `${hairline} border-0 border-b border-line px-4 py-1.5 text-micro ${mutedText}`;
export const stepGroupShow = `ml-1 ${link}`;
export const stepRowBody = "px-0 pt-1";
export const stepRowCommitNote = `px-4 pb-2.5 text-micro ${secondaryText}`;
/** The small chip a row with a commit carries beside its summary (#443) —
 * Session.dc.html's own step 2799: an icon and the short sha, inline. */
export const rowCommitChip = `${hairlineStrong} inline-flex shrink-0 items-center gap-1 rounded-sm px-1.5 ${identifierText} text-micro text-ink-secondary`;

/* agents-it-started table */
export const agentsSearchBox = `${hairlineStrong} flex items-center gap-1.5 rounded-md bg-surface px-2.5 py-1.5 text-micro ${mutedText}`;
export const agentsSearchInput = `w-[180px] border-0 bg-transparent font-inherit text-micro text-ink placeholder:text-ink-muted ${focusRing}`;
export const agentsTable = panel;
export const agentsTableHeadRow = `${hairline} flex items-center gap-3 border-0 border-b border-line px-4 py-2 text-micro ${mutedText}`;
export const agentRow = `${hairline} flex items-center gap-3 border-0 border-b border-line px-4 py-2.5 text-ink ${focusRing} ${stateTransition} hover:bg-hover`;
export const agentCellTask = "min-w-0 flex-grow";
export const agentCellTitle = "block truncate font-medium text-ink";
export const agentCellSpawned = `block text-micro ${mutedText}`;
export const agentCellKind = `w-[150px] shrink-0 text-micro ${secondaryText}`;
export const agentCellNum = `w-[70px] shrink-0 text-right ${identifierText} text-micro`;
export const agentCellEnded = `w-[120px] shrink-0 text-right text-micro ${mutedText}`;
export const agentsFooter = `flex items-center gap-3 px-4 py-2.5 text-micro ${mutedText}`;

/* "Where it sits" aside */
export const sitsRow = `flex items-center gap-2 rounded-sm px-2 py-1.5 text-body ${focusRing} ${stateTransition}`;
export const sitsRowLink = `${sitsRow} text-ink`;
export const sitsRowCurrent = `${sitsRow} bg-accent-surface font-semibold text-accent-emphasis`;
export const sitsRowChild = "pl-[26px] text-micro text-ink-secondary";
export const sitsNone = `pl-[26px] text-micro ${mutedText}`;
export const sitsCaption = `px-3.5 pb-3 text-micro ${mutedText}`;

/* "Files it wrote" aside */
export const writtenRow = `flex items-center gap-2 rounded-sm px-1.5 py-1 ${identifierText} text-micro text-ink ${focusRing} ${stateTransition} hover:bg-hover`;
export const writtenPath = "min-w-0 flex-grow truncate";
export const writtenStep = `shrink-0 ${mutedText}`;

/* "Commits" aside (role-aware) */
export const commitsNote = `text-micro ${secondaryText}`;
export const commitsList = "flex flex-col gap-1.5";
export const commitsShowAll = `text-micro ${link}`;

/* "Witnesses" aside */
export const witnessesNote = `text-micro ${secondaryText}`;
