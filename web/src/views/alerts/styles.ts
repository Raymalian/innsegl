// SPDX-License-Identifier: Apache-2.0

/*
 * Class strings for the notification menu and the alert detail view —
 * ADR-0038, ADR-0054, doc 06 §5.
 *
 * Every surface and border colour this directory uses is here and nowhere
 * else; FE-139 holds that. The two tones are the shared groups, not new ones:
 * red for an open integrity alert (doc 06 §5.3), amber for a count nobody
 * could read (P2). There is no green, because an alert is not a verification.
 */

import {
  degraded,
  focusRing,
  hairline,
  integrityAlert,
  link,
  mutedText,
  popover,
  secondaryText,
  stateTransition,
} from "../../components/common/styles";

export { focusRing, link, mutedText, secondaryText };

/** The bell: a real button, quiet at rest, in the header's own type size. */
export const bellButton = `inline-flex items-center gap-1 rounded-sm px-2 py-1 text-prose text-ink-secondary hover:bg-hover ${focusRing} ${stateTransition}`;

const badgeBase = `${hairline} inline-flex items-center justify-center rounded-pill px-2 py-0 text-body font-semibold leading-tight [font-variant-numeric:var(--innsegl-font-variant-numeric-tabular)]`;

/** P3: the alarm is filled red and cannot be mistaken for chrome. */
export const badgeOpen = `${badgeBase} ${integrityAlert}`;
/** P2: an unknown count is amber, never a red it has not earned, never zero. */
export const badgeUnknown = `${badgeBase} ${degraded}`;

/** Anchored to the bell's trailing edge, so it never leaves the viewport on
 * the right; capped to the viewport on a phone. */
export const menuShell = "relative";
export const menuPanel = `${popover} ${hairline} right-0 flex w-[22rem] max-w-[calc(100vw-2rem)] flex-col gap-1 border-line text-body`;
export const menuHeader = "flex items-baseline gap-2 px-2 py-1";
export const menuHeading = "font-semibold text-ink";
export const menuNote = `px-2 py-1 text-micro ${mutedText}`;

/** One alert in the list: a link, a block, keyboard-focusable. */
export const menuItem = `flex flex-col gap-1 rounded-sm px-2 py-2 text-ink hover:bg-hover focus:bg-hover ${focusRing}`;
export const menuItemHead = "flex items-baseline justify-between gap-2";
export const menuItemTitle = "inline-flex items-center gap-1 font-semibold";
export const menuItemSummary = `text-micro leading-default ${secondaryText}`;
export const menuItemTime = `shrink-0 text-micro ${mutedText}`;
/** The alarm triangle beside each title: a shape, so the list never relies on colour (doc 06 §6.4). */
export const alarmIcon = "shrink-0";

/* ── the detail view ────────────────────────────────────────────────────── */

export const page = "flex w-full flex-col gap-5";
export const heading = "inline-flex items-center gap-2 text-heading font-semibold leading-tight text-ink";
export const summary = `leading-prose ${secondaryText}`;
export const facts = `${hairline} flex flex-col rounded-md border-line bg-surface`;
export const factRow = `${hairline} flex flex-col gap-1 border-0 border-t border-line px-4 py-3 first:border-t-0 sm:flex-row sm:gap-4`;
export const factTerm = "w-full shrink-0 text-micro font-semibold uppercase tracking-label text-ink-muted sm:w-[10rem]";
export const factValue = "min-w-0 text-body text-ink [overflow-wrap:anywhere]";
export const evidence = "flex flex-col gap-2";
export const evidenceHeading = "text-prose font-semibold text-ink";

/* ── resolving (RM-330) ─────────────────────────────────────────────────── */

export const resolveForm = "flex flex-col gap-3";
/** The resolve section on the detail page: the form, then the command. */
export const resolveSection = "flex flex-col gap-4";
export const fieldStack = "flex flex-col gap-1";
export const fieldLabel = "font-medium text-ink";
export const fieldHelp = `text-micro leading-default ${secondaryText}`;
export const reasonInput = `${hairline} min-h-[5rem] w-full rounded-sm border-line-strong bg-raised px-3 py-2 text-body text-ink ${focusRing}`;
export const formActions = "flex flex-wrap items-center gap-3";
/** The one action that writes: the accent at emphasis strength, as the
 * account page's own passkey actions are. */
export const primaryButton = `${hairline} rounded-sm border-accent-line bg-accent-emphasis px-4 py-2 font-medium text-ink-on-emphasis whitespace-nowrap disabled:opacity-60 ${focusRing}`;
/** A quiet control beside it: open or close a form. */
export const secondaryButton = `${hairline} rounded-sm border-line bg-surface px-3 py-1 font-medium text-ink hover:bg-hover whitespace-nowrap ${focusRing} ${stateTransition}`;
export const formError = `${hairline} rounded-sm px-3 py-2 text-body ${degraded}`;
export const formDone = `${hairline} rounded-sm border-line bg-sunken px-3 py-2 text-body text-ink`;

/* ── the alerts page (RM-330) ───────────────────────────────────────────── */

export const filterBar = "flex flex-wrap items-end gap-4";
export const segmented = "inline-flex flex-wrap gap-1";
export const segment = `${hairline} rounded-sm border-line bg-surface px-3 py-1 text-body text-ink-secondary hover:bg-hover aria-pressed:border-accent-line aria-pressed:bg-accent-surface aria-pressed:text-accent ${focusRing} ${stateTransition}`;
export const runSelect = `${hairline} rounded-sm border-line-strong bg-raised px-3 py-1 text-body text-ink ${focusRing}`;
export const groupCard = `${hairline} flex flex-col rounded-md border-line bg-surface`;
export const groupHeader = `${hairline} flex flex-col gap-2 border-0 border-b border-line px-4 py-3`;
export const groupTitleRow = "flex flex-wrap items-baseline justify-between gap-2";
export const groupTitle = "inline-flex items-center gap-2 text-prose font-semibold text-ink";
export const groupCounts = `inline-flex flex-wrap gap-2 text-micro ${mutedText}`;
export const openCountBadge = `${badgeOpen}`;
export const groupBody = "flex flex-col gap-3";
/** A heading inside a group: one step below the group's own title. */
export const groupSubheading = "text-body font-semibold text-ink";
export const alertList = "flex flex-col";
export const alertRow = `${hairline} flex flex-col gap-1 border-0 border-t border-line px-4 py-2 first:border-t-0 text-ink hover:bg-hover focus:bg-hover sm:flex-row sm:items-baseline sm:gap-4 ${focusRing}`;
export const alertRowTime = `shrink-0 text-micro ${mutedText} sm:w-[12rem]`;
export const alertRowRun = "min-w-0 flex-1 text-micro [overflow-wrap:anywhere]";
export const alertRowRunId = "font-mono";
export const alertRowStatus = `shrink-0 text-micro ${secondaryText}`;
export const recordPre = `${hairline} overflow-x-auto rounded-md border-line bg-sunken p-3 font-mono text-micro text-ink`;
export const recordToggle = `cursor-pointer text-accent underline underline-offset-2 ${focusRing}`;

/** The alerts page's title: the shell's page heading, as Overview and Runs set it. */
export const pageHeading =
  "font-serif text-display font-semibold leading-tight tracking-display text-ink";
