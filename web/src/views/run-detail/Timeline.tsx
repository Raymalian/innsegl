// SPDX-License-Identifier: Apache-2.0

/*
 * The run's ordered event chain — doc 06 §3.3.
 *
 * An `<ol>`, not a stack of divs: the order IS the evidence, and doc 06 §6.4
 * asks for real semantics so that a screen-reader user hears "list, 9 items,
 * item 4" rather than a wall of paragraphs. The order is the ledger's own —
 * `timelineSQL` returns `ORDER BY chain_position` — and this component does
 * not re-sort it. A view that sorted the chain by timestamp would be quietly
 * asserting that the two orders agree, which is one of the things a reader
 * comes here to check.
 *
 * ── IT IS A RAIL, AND THE RAIL IS THE ORDER DRAWN ──────────────────────────
 *
 * A stack of panels shows a SET. The reader has to infer the sequence from the
 * chain positions printed inside each one, which is exactly the work doc 06 P1
 * says a dashboard should be doing on their behalf. The rail draws it: a marker
 * per event, a connector between markers, content beside both.
 *
 * The connector is a property of the ROW ABOVE it, so this component decides
 * it rather than the node: a node cannot see whether it is the last, and a line
 * running past the last marker would be a stroke asserting the chain continues
 * beyond what this response holds. `last` is therefore computed over the ROWS —
 * a fold of two hundred tool calls is one row and takes one connector — and
 * never over the events.
 *
 * The chain-link state of each node is computed here for the same reason: it is
 * a fact about a PAIR of events and a node cannot see its neighbour. See
 * events.ts for why three of the four states exist.
 */

import type { ReactElement } from "react";

import { EmptyState } from "../../components/common/EmptyState";
import { Icon } from "../../components/common/Icon";
import type { VerifyCommit } from "./CommitVerification";
import { RailGutter } from "./Rail";
import { TimelineNode } from "./TimelineNode";
import { strings } from "./strings";
import {
  chainMarker,
  foldCount,
  foldPill,
  nodeBody,
  railRow,
  timelineList,
} from "./styles";
import { chainLinkAt, groupTimeline } from "./events";
import type { TimelineEvent } from "./types";

export interface TimelineProps {
  /** In the ledger's order. Never re-sorted here. */
  readonly events: readonly TimelineEvent[];
  /** Injected so a render is deterministic (doc 06 §6.2's relative times). */
  readonly now: Date;
  readonly verifyCommit?: VerifyCommit;
  readonly freshnessMs?: number;
}

export function Timeline({ events, now, verifyCommit, freshnessMs }: TimelineProps) {
  if (events.length === 0) {
    return (
      <EmptyState title={strings.timeline.empty} detail={strings.timeline.emptyDetail} />
    );
  }

  const rows = groupTimeline(events);

  const node = (event: TimelineEvent, index: number, last: boolean) => (
    <TimelineNode
      key={`${event.chain_position}-${event.event_id}`}
      event={event}
      link={chainLinkAt(events, index)}
      now={now}
      last={last}
      {...(verifyCommit === undefined ? {} : { verifyCommit })}
      {...(freshnessMs === undefined ? {} : { freshnessMs })}
    />
  );

  return (
    <ol className={timelineList}>
      {rows.map((row, position) => {
        const last = position === rows.length - 1;
        return row.kind === "event" ? (
          node(row.event, row.index, last)
        ) : (
          <ToolCallRun
            key={`run-${row.index}`}
            events={row.events}
            last={last}
            renderNode={(event, offset, innerLast) =>
              node(event, row.index + offset, innerLast)
            }
          />
        );
      })}
    </ol>
  );
}

/** A run of consecutive tool calls, as one row that opens.
 *
 * doc 06 §3.3 asks for "tool-call events (count, expandable to digests)", and a
 * card per call was never that: a real run held 1220 of them, so the events the
 * timeline exists to show — the registration, the intents, the recorded
 * commits, the retirement — were hundreds of screens apart and unreachable in
 * practice.
 *
 * Closed by default, so a reader arrives at the evidence chain rather than at
 * the noise. The summary is a pill rather than a line of text because it is the
 * one thing on the rail a reader can open and it has to look like it; it
 * carries the exact count and the exact span of chain positions behind it, so
 * the fold states what it is folding rather than merely that it folded
 * something (doc 06 §6.2).
 *
 * Every call is still here, in the ledger's order, one click away, and each is
 * the same node with the same chain link it had before: this changes what is on
 * screen first, never what the timeline says. */
function ToolCallRun({
  events,
  last,
  renderNode,
}: {
  readonly events: readonly TimelineEvent[];
  readonly last: boolean;
  readonly renderNode: (
    event: TimelineEvent,
    offset: number,
    last: boolean,
  ) => ReactElement;
}) {
  const first = events[0];
  const final = events[events.length - 1];
  if (first === undefined || final === undefined) return <></>;
  return (
    <li className={railRow}>
      <RailGutter icon="fold" last={last} />
      <div className={nodeBody} data-node-body>
        <details>
          <summary className={foldPill}>
            <Icon name="fold" className="shrink-0" />
            <span className={foldCount}>
              {strings.toolCall.count(events.length)}
            </span>
            <span className={chainMarker}>
              {strings.timeline.toolCallRange(
                first.chain_position,
                final.chain_position,
              )}
            </span>
          </summary>
          <ol className={`${timelineList} mt-2`}>
            {events.map((event, offset) =>
              renderNode(event, offset, offset === events.length - 1),
            )}
          </ol>
        </details>
      </div>
    </li>
  );
}
