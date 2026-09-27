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

export const page = "flex max-w-prose flex-col gap-5";
export const heading = "inline-flex items-center gap-2 text-heading font-semibold leading-tight text-ink";
export const summary = `leading-prose ${secondaryText}`;
export const facts = `${hairline} flex flex-col rounded-md border-line bg-surface`;
export const factRow = `${hairline} flex flex-col gap-1 border-0 border-t border-line px-4 py-3 first:border-t-0 sm:flex-row sm:gap-4`;
export const factTerm = "w-full shrink-0 text-micro font-semibold uppercase tracking-label text-ink-muted sm:w-[10rem]";
export const factValue = "min-w-0 text-body text-ink [overflow-wrap:anywhere]";
export const evidence = "flex flex-col gap-2";
export const evidenceHeading = "text-prose font-semibold text-ink";

/** The resolve command: a sunken well, so it reads as something to copy. */
export const commandBox = `${hairline} rounded-md border-line bg-sunken px-3 py-2 [overflow-wrap:anywhere]`;
