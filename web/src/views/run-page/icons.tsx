// SPDX-License-Identifier: Apache-2.0

/*
 * Run-page-local glyphs — issue #395 (E19).
 *
 * `components/common/Icon.tsx` is the shared set, and this view does not
 * extend it: the shared set is owned elsewhere (not a path this issue owns),
 * and — the load-bearing reason, not just the ownership one — two of the
 * marks this page needs are semantically specific to it. `ProofIcon.tsx`
 * already establishes the pattern of drawing a component-local glyph rather
 * than widening the shared set for one meaning: "the shared set deliberately
 * contains no mark of approval — nothing in that directory is a cryptographic
 * verification". The same is true here in reverse: a step's "done"/"exit 0"
 * outcome is not a verification either, and a tick drawn for it must never be
 * mistaken for the one `ProofIcon` draws. It is drawn in neutral ink only
 * (never green — doc 06 §5.3) and nowhere does this page import `ProofIcon`
 * for anything but an actual commit's verification checks.
 *
 * Every shape here follows the shared set's own conventions: inline,
 * `currentColor`, `aria-hidden`, 16x16 viewBox.
 */

import type { ReactNode } from "react";

function Svg({ children, className }: { readonly children: ReactNode; readonly className?: string }) {
  return (
    <svg
      aria-hidden="true"
      focusable="false"
      viewBox="0 0 24 24"
      width="1em"
      height="1em"
      fill="none"
      stroke="currentColor"
      className={className}
    >
      {children}
    </svg>
  );
}

/** A step outcome that completed — neutral ink, never the verification tick. */
export function OutcomeOkIcon({ className }: { readonly className?: string }) {
  return (
    <Svg className={className}>
      <path d="M4 12l5 5L20 6" strokeWidth={2.2} strokeLinecap="round" strokeLinejoin="round" />
    </Svg>
  );
}

/** A step that failed — grey, not red: "a tool that failed is grey, not
 * red: it is history, not an alarm" (doc 06 §5.3's run-page exception). */
export function OutcomeFailedIcon({ className }: { readonly className?: string }) {
  return (
    <Svg className={className}>
      <path d="M6 6l12 12M18 6L6 18" strokeWidth={2.2} strokeLinecap="round" strokeLinejoin="round" />
    </Svg>
  );
}

/** The root of the agent tree: a filled-corner square, distinct from the
 * branch glyph below by silhouette, not only by the accent colour it takes
 * only on the selected row. */
export function AgentRootIcon({ className }: { readonly className?: string }) {
  return (
    <Svg className={className}>
      <rect x="4" y="4" width="16" height="16" rx="3" strokeWidth={2} />
    </Svg>
  );
}

/** A spawned subagent: a branch dropping from its parent's line. */
export function AgentBranchIcon({ className }: { readonly className?: string }) {
  return (
    <Svg className={className}>
      <path d="M6 3v12a3 3 0 0 0 3 3h9" strokeWidth={2} strokeLinecap="round" />
    </Svg>
  );
}

/** The commit card's own mark: a node on a line, not a verdict. */
export function CommitIcon({ className }: { readonly className?: string }) {
  return (
    <Svg className={className}>
      <circle cx="12" cy="12" r="3.5" strokeWidth={1.8} />
      <path d="M3 12h5.5M15.5 12H21" strokeWidth={1.8} strokeLinecap="round" />
    </Svg>
  );
}

/** A right-pointing chevron, for the lineage nav's own separators between
 * pills (#443) — the same silhouette as a disclosure chevron, pointed at
 * what comes next rather than claiming anything about it. */
export function ChevronIcon({ className }: { readonly className?: string }) {
  return (
    <Svg className={className}>
      <path d="M9 6l6 6-6 6" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
    </Svg>
  );
}

/** The agents-table search box's own glyph (#443). */
export function SearchIcon({ className }: { readonly className?: string }) {
  return (
    <Svg className={className}>
      <circle cx="11" cy="11" r="7" strokeWidth={2} />
      <path d="M20 20l-3.5-3.5" strokeWidth={2} strokeLinecap="round" />
    </Svg>
  );
}
