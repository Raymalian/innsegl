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

import { EmptyState } from "../../components/common/EmptyState";
import type { VerifyCommit } from "./CommitVerification";
import { TimelineNode } from "./TimelineNode";
import { strings } from "./strings";
import { timelineList } from "./styles";
import { chainLinkAt } from "./events";
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

  return (
    <ol className={timelineList}>
      {events.map((event, index) => (
        <TimelineNode
          key={`${event.chain_position}-${event.event_id}`}
          event={event}
          link={chainLinkAt(events, index)}
          now={now}
          {...(verifyCommit === undefined ? {} : { verifyCommit })}
          {...(freshnessMs === undefined ? {} : { freshnessMs })}
        />
      ))}
    </ol>
  );
}
