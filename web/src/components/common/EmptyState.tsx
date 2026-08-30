// SPDX-License-Identifier: Apache-2.0

/*
 * Empty state — doc 06 §4.6, P2. Driven by FE-032.
 *
 *   §4.6: "Every view specifies its empty state ('No runs match these
 *   filters') ... No blank panels."
 *
 * Separate from ErrorState on purpose. An empty result is not a fault: the
 * query ran, the answer was none, and the reader can act on that by changing a
 * filter. doc 06 P2 is about not collapsing distinct states into one, and
 * "nothing matched" collapsed into "we could not check" is the same error in
 * miniature. So this renders neutral, carries no alert role, and says nothing
 * about a dependency.
 *
 * The title belongs to the calling view (§4.6 says "every view specifies its
 * empty state"); the fallback exists so a view that names none still cannot
 * render a blank panel.
 */

import { Icon } from "./Icon";
import { strings } from "./strings";
import { mutedText, noticeBase, noticeBody } from "./styles";

export interface EmptyStateProps {
  readonly title?: string;
  readonly detail?: string;
}

export function EmptyState({ title, detail }: EmptyStateProps) {
  return (
    <div className={`${noticeBase} ${mutedText}`}>
      <Icon name="empty" className="mt-[0.3em] shrink-0" />
      <span className={noticeBody}>
        <span>{title ?? strings.empty.title}</span>
        <span>{detail ?? strings.empty.detail}</span>
      </span>
    </div>
  );
}
