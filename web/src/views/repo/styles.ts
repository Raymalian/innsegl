// SPDX-License-Identifier: Apache-2.0

/*
 * The class strings the repo view uses, and the only file in this directory
 * that names a surface or a border.
 *
 * Same discipline as components/common/styles.ts and for the same reason: one
 * file to audit for doc 06 §5.3. FE-047 asserts that no other file in this
 * directory or in views/agent-type names a `bg-` or `border-` utility, so a
 * reviewer asking "where could a colour get in" reads two files and is done.
 *
 * Nothing here is a value. Every entry is a Tailwind utility that resolves
 * through tailwind-theme.css into `var(--innsegl-…)`; ADR-0038 deleted
 * Tailwind's default palette, spacing and type scales, so a utility that is
 * not backed by a token does not compile.
 *
 * There is no green here and no route to one. ADR-0038 decision 4 keeps
 * `--innsegl-color-proof-verified-*` reachable from components/verification
 * alone, and this view holds no proof: doc 06 §5.3's green means "cryptographic
 * verification passed", and nothing on this page has been verified.
 *
 * There are no `dark:` variants and nothing for one to do — every token is a
 * `light-dark()` pair inside the sheet (ADR-0038 decision 3).
 */

export {
  identifierText,
  link,
  mutedText,
  secondaryText,
} from "../../components/common/styles";

/** The stack a whole view sits in. Air between blocks, density inside them
 * (doc 06 §5.4). */
export const viewShell = "flex flex-col gap-6";

/** One block of the view. A background step for structure; doc 06 §5.4 allows
 * no shadow outside a popover and no gradient anywhere. */
export const sectionShell = "flex flex-col gap-3 rounded-md bg-surface p-panel";

/** The identifier this whole page is about. Mono, because it is verbatim
 * technical material a reader will compare (doc 06 §5.2, P4). */
export const viewHeading = "font-mono text-heading font-semibold break-all";

/** A block heading. Weight carries the hierarchy before size does (§5.2). */
export const sectionHeading =
  "flex items-center gap-2 text-prose font-semibold leading-tight";

/** A caption is a heading a table already owns; same treatment. */
export const tableCaption = "text-left text-prose font-semibold leading-tight";

/** Label-and-value pairs. */
export const factList = "grid gap-2 sm:grid-cols-2";
export const factRow = "flex flex-col gap-0";
export const factTerm = "text-ink-muted text-micro";

/** One identity's block, a background step below the section it sits in. */
export const identityGroup = "flex flex-col gap-2 rounded-md bg-sunken p-3";

/** Compact rows: density belongs to data (doc 06 §5.4). */
export const table = "w-full border-collapse text-body";
export const tableHeader =
  "border-b border-line px-cell-x py-cell-y text-left font-medium text-ink-secondary";
export const tableCell = "border-b border-line px-cell-x py-cell-y align-top";

/** Things that sit beside each other and wrap together. */
export const inlineRow = "flex flex-wrap items-center gap-2";

/** Prose inside a section: generous line height, bounded measure (§5.4). */
export const explanation = "max-w-prose leading-prose text-ink-secondary";
