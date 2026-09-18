// SPDX-License-Identifier: Apache-2.0

/*
 * The timeline's rail gutter — doc 06 §3.3.
 *
 * One marker per row and the connector down to the next one. It lives in its
 * own module because both `Timeline` (which draws the folded tool-call rows)
 * and `TimelineNode` (which draws every other row) need it, and a component
 * imported in a cycle between those two would work only by accident of
 * hoisting. There is one rail on this page; this is it.
 *
 * ── THE RAIL IS NEVER A VERDICT ────────────────────────────────────────────
 *
 * doc 06 §5.3 makes colour a claim in this product, and a node is a statement
 * that the ledger holds an event — not a verification of it, not a judgement
 * about it. So the marker is neutral in every case, and what carries the
 * exception is the SHAPE: a bare ring for an ordinary event, the dashed ring
 * for a degradation, the triangle for an integrity alert, a chevron for a fold.
 * Those read apart at 16px with no colour at all, which is what doc 06 §6.4
 * asks of every cue that means something.
 *
 * The connector stops at the last marker. A line continuing past it would be a
 * stroke asserting the chain runs on beyond what this response holds, which is
 * a claim about events that are not on the page (P1).
 */

import { Icon } from "../../components/common/Icon";
import { railGutter, railLine, railMarker } from "./styles";

/** The four shapes the rail can take. Named rather than open to any `IconName`
 * so that a caller cannot quietly introduce a fifth marker whose meaning nobody
 * decided. */
export type RailMarker = "node" | "fold" | "status-lapsed" | "integrity-alert";

export function RailGutter({
  icon,
  last,
}: {
  readonly icon: RailMarker;
  /** Whether this is the last row of its rail. Decided by the list, because a
   * row cannot see whether anything follows it. */
  readonly last: boolean;
}) {
  return (
    <div className={railGutter} data-rail-gutter>
      <span className={railMarker}>
        <Icon name={icon} />
      </span>
      {last ? null : <span className={railLine} data-rail-line />}
    </div>
  );
}
