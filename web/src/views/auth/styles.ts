// SPDX-License-Identifier: Apache-2.0

/*
 * Every class string the sign-in and enrolment pages use — public-verify's
 * own styles.ts pattern: import the shared geometry, name only what is new.
 */

import {
  badgeBase,
  cell,
  columnHeader,
  degraded,
  focusRing,
  hairline,
  identifierText,
  labelText,
  link,
  mutedText,
  neutralSurface,
  noticeBase,
  noticeBody,
  rowHeader,
  secondaryText,
  srOnly,
  stateTransition,
  statusActive,
  statusRetired,
  statusWithdrawn,
  table,
  tablePanel,
  tablePanelHeader,
  tableScroll,
} from "../../components/common/styles";

export {
  badgeBase,
  cell,
  columnHeader,
  degraded,
  focusRing,
  hairline,
  identifierText,
  labelText,
  link,
  mutedText,
  neutralSurface,
  noticeBase,
  noticeBody,
  rowHeader,
  secondaryText,
  srOnly,
  stateTransition,
  table,
  tablePanel,
  tablePanelHeader,
  tableScroll,
};

/** A page with nothing else on it: centred, narrow, calm — doc 06 §5's
 * "calm audit console", read literally for the one screen that is nothing
 * but a decision. */
export const pageShell =
  "mx-auto flex min-h-[60vh] max-w-prose flex-col justify-center gap-6";

export const pageHeading =
  "font-serif text-display font-semibold leading-tight tracking-display text-balance";

export const proseText = "leading-prose text-ink-secondary";

export const fieldStack = "flex flex-col gap-1";
export const fieldLabel = "font-medium";
export const fieldInput =
  "w-full rounded-sm border-[length:var(--innsegl-border-width-hairline)] border-solid border-line-strong bg-raised px-3 py-2 text-body text-ink";

/** The one prominent action on either page — doc 06's own accent token, at
 * the emphasis strength a page-level decision earns (public-verify's own
 * submitButton is the lighter, in-flow version of this same shape). */
export const primaryButton =
  "self-start rounded-sm border-[length:var(--innsegl-border-width-hairline)] border-solid border-accent-line bg-accent-emphasis px-4 py-2 font-medium text-ink-on-emphasis whitespace-nowrap disabled:opacity-60";

/** The header's sign-out control, and the account-name link beside it —
 * small, quiet, chrome rather than a page-level decision. */
export const chromeButton =
  "rounded-sm px-2 py-1 text-micro text-ink-secondary hover:bg-hover disabled:opacity-60";

/* ── #445: the account page — wider than pageShell's single centred
 * decision, with room for a table, but still the product's one content
 * width (run-page's own `max-w-content` ceiling, not a second one). ───── */

/* No width constraint of its own: App.tsx's main region already holds every
 * view, this one included, to the product's one content width. */
export const accountShell = "flex flex-col gap-8 py-6";

export const section = "flex flex-col gap-3";
export const sectionHeading =
  "font-serif text-heading font-semibold leading-tight tracking-display";

/** One settings block: Profile, Add a passkey, Recovery codes. The
 * passkeys table sits in `tablePanel` instead, doc 06 §5.4's one table
 * treatment rather than a table dressed as a card. */
export const card = `${hairline} flex flex-col gap-4 rounded-md border-line bg-surface p-4`;

/** A quiet, secondary action beside the page's one primary button —
 * rename, cancel, "use a recovery code". */
export const secondaryButton = `${hairline} self-start rounded-sm border-line bg-surface px-3 py-1.5 text-micro text-ink ${stateTransition} ${focusRing} hover:bg-hover disabled:opacity-60`;

/** A link-styled button — "Rename", "Use a recovery code" — where the
 * action is a secondary word among others rather than its own control. */
export const inlineLinkButton = `${link} bg-transparent p-0 font-inherit`;

/** The "this device" badge beside the passkey this session signed in
 * with — neutral, never a verdict (doc 06 §5.3). */
export const currentBadge = `${badgeBase} ${hairline} border-line bg-sunken px-2 py-0 text-micro text-ink-secondary`;

/** The one-time recovery-codes grid, shared by the setup page's own save
 * step and the account page's regeneration. */
export const codesGrid =
  "grid grid-cols-2 gap-2 rounded-md border-[length:var(--innsegl-border-width-hairline)] border-solid border-line bg-sunken p-4 sm:grid-cols-3";
export const codeCell = "font-mono text-body text-ink";

export const checkboxRow = "flex items-center gap-2";
export const confirmRow = "flex flex-wrap items-center gap-2";

/* ── RM-333 (#511): the organisation, its machines and the sign-ins. ───── */

/** The page's opening: the serif heading and one sentence under it, the
 * same pairing Overview and Repositories open with. */
export const pageIntro = "flex flex-col gap-1";
export const introText = "max-w-prose leading-prose text-ink-secondary";

/** A section heading with its one action on the trailing edge. */
export const sectionHeader = "flex flex-wrap items-center justify-between gap-2";
export const sectionIntro = "max-w-prose text-micro leading-prose text-ink-secondary";

/** The identity block: who, and in which organisation. Two columns from
 * `md`, one below. */
export const identityGrid = "grid gap-4 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]";
export const identityName = `${sectionHeading} break-words`;
export const factList = "grid grid-cols-[auto_minmax(0,1fr)] items-baseline gap-x-4 gap-y-2";
export const factTerm = labelText;
export const factValue = "min-w-0 text-ink";
export const idValue = `${identifierText} text-micro text-ink-secondary`;
export const orgList = "flex flex-col gap-2";
export const orgRow = "flex flex-wrap items-baseline gap-2";

/** A small quiet control: copy, add a passkey, cancel. */
export const smallButton = `${hairline} self-start inline-flex items-center gap-1 rounded-sm border-line bg-surface px-2 py-0.5 text-micro text-ink ${stateTransition} ${focusRing} hover:bg-hover disabled:opacity-60`;

/** Role, kind — a neutral word on a pill, never a verdict. */
export const neutralPill = `${badgeBase} ${hairline} border-line bg-sunken text-ink-secondary`;

/** Machine status: the word carries it; the run states' own neutral tones
 * only repeat it (doc 06 §5.3). */
const pillBase = `${badgeBase} border-[length:var(--innsegl-border-width-hairline)] border-solid`;
export const machineStatusPill: Record<string, string> = {
  active: `${pillBase} ${statusActive}`,
  suspended: `${pillBase} ${statusWithdrawn}`,
  revoked: `${pillBase} ${statusRetired}`,
};
export const machineStatusFallback = neutralPill;

/** What the role allows: two plain lists, side by side from `sm`. */
export const privilegeColumns = "grid gap-4 sm:grid-cols-2";
export const privilegeList = "flex flex-col gap-2";
export const privilegeItem = "flex flex-col gap-0.5";
export const privilegeMark = "mr-2 inline-block w-4 text-center font-semibold";
export const privilegeNote = "pl-6 text-micro leading-prose text-ink-muted";

/** The minted token and its command: shown once, so set apart. */
export const secretBlock = `${hairline} flex flex-col gap-3 rounded-md border-line bg-sunken p-4`;
export const secretRow = "flex flex-wrap items-start gap-2";
export const secretValue = `${identifierText} min-w-0 flex-1 text-ink`;
export const commandValue = `${identifierText} min-w-0 flex-1 rounded-sm bg-raised px-2 py-1 text-micro text-ink`;

/** Agent types: one chip per type, the count beside the name. */
export const chipList = "flex flex-wrap gap-2";
export const chip = `${hairline} inline-flex items-baseline gap-2 rounded-md border-line bg-surface px-3 py-1.5`;
export const chipCount = "font-semibold tabular-nums text-ink";
export const numericCell = "tabular-nums";
export const subHeading = "font-semibold text-ink";
export const inlineSelect = `${hairline} rounded-sm border-line-strong bg-raised px-2 py-1 text-micro text-ink ${focusRing}`;

/** The account page's tables: one panel, scrolling sideways inside itself
 * on a narrow screen. `relative` keeps a visually hidden header label
 * positioned inside the panel, so it cannot widen the page. */
export const scrollingTablePanel = `${tablePanel} ${tableScroll} relative`;
