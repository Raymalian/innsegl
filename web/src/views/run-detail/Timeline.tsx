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
 * The chain-link state of each node is computed here rather than in the node,
 * because it is a fact about a PAIR of events and a node cannot see its
 * neighbour. See timeline.ts for why three of the four states exist.
 */

import type { ReactElement } from "react";

import { EmptyState } from "../../components/common/EmptyState";
import type { VerifyCommit } from "./CommitVerification";
import { TimelineNode } from "./TimelineNode";
import { strings } from "./strings";
import { disclosure, focusRing, timelineList } from "./styles";
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

  const node = (event: TimelineEvent, index: number) => (
    <TimelineNode
      key={`${event.chain_position}-${event.event_id}`}
      event={event}
      link={chainLinkAt(events, index)}
      now={now}
      {...(verifyCommit === undefined ? {} : { verifyCommit })}
      {...(freshnessMs === undefined ? {} : { freshnessMs })}
    />
  );

  return (
    <ol className={timelineList}>
      {groupTimeline(events).map((row) =>
        row.kind === "event" ? (
          node(row.event, row.index)
        ) : (
          <ToolCallRun
            key={`run-${row.index}`}
            events={row.events}
            renderNode={(event, offset) => node(event, row.index + offset)}
          />
        ),
      )}
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
 * the noise. Every call is still here, in the ledger's order, one click away,
 * and each is the same node with the same chain link it had before: this
 * changes what is on screen first, never what the timeline says. */
function ToolCallRun({
  events,
  renderNode,
}: {
  readonly events: readonly TimelineEvent[];
  readonly renderNode: (event: TimelineEvent, offset: number) => ReactElement;
}) {
  const first = events[0];
  const last = events[events.length - 1];
  if (first === undefined || last === undefined) return <></>;
  return (
    <li>
      <details>
        <summary
          className={`${disclosure} ${focusRing} flex flex-wrap items-baseline gap-x-3 rounded-md p-3`}
        >
          <span className="font-medium text-ink">
            {strings.timeline.toolCallRun(
              events.length,
              first.chain_position,
              last.chain_position,
            )}
          </span>
        </summary>
        <ol className={`${timelineList} mt-2`}>
          {events.map((event, offset) => renderNode(event, offset))}
        </ol>
      </details>
    </li>
  );
}
