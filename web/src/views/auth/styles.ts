// SPDX-License-Identifier: Apache-2.0

/*
 * Every class string the sign-in and enrolment pages use — public-verify's
 * own styles.ts pattern: import the shared geometry, name only what is new.
 */

export {
  degraded,
  focusRing,
  hairline,
  mutedText,
  noticeBase,
  noticeBody,
  secondaryText,
} from "../../components/common/styles";

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

/** The header's sign-out control — small, quiet, chrome rather than a
 * page-level decision. */
export const chromeButton =
  "rounded-sm px-2 py-1 text-micro text-ink-secondary hover:bg-hover disabled:opacity-60";
