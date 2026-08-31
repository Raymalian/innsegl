// SPDX-License-Identifier: Apache-2.0

/*
 * The overview, wired to the query API — doc 06 §3.1, §4.6, §7.
 *
 * Two components, and the second is the one the shell needs.
 *
 * `OverviewView` is what `App`'s view registry renders at "/". It reads,
 * renders the loading state that times out into an explicit error (doc 06
 * §4.6, FE-011), and hands the data to the presentational `Overview`.
 *
 * `OverviewHeartbeat` is doc 06 §3.1's "persistent header (all views)". The
 * header is the shell's — `App` takes the content as a `heartbeat` prop
 * precisely so a view can fill the slot without reaching into the chrome —
 * and this is what fills it. It reads the same endpoint and renders nothing
 * but the pulse, in every state including the two the read itself can be in.
 *
 * The wiring the supervisor has to do, in `web/src/app/main.tsx`, is two
 * lines and no edit to `App`:
 *
 *   import { OverviewHeartbeat, OverviewView } from "../views/overview";
 *   <App views={{ overview: OverviewView }} heartbeat={<OverviewHeartbeat />} />
 *
 * doc 06 P6: everything here is a GET. There is no request in this file that
 * could write, and `internal/api` refuses every method but GET, HEAD and
 * OPTIONS on every path anyway — a client is a suggestion, and the database
 * role is what actually stops a write.
 */

import { ErrorState, LoadingState } from "../../components/common";
import { AnchoringPulse, DEFAULT_LAG_BOUND_MS } from "./AnchoringPulse";
import { DEFAULT_API_BASE, useOverview } from "./data";
import { Overview } from "./Overview";
import { strings } from "./strings";

export interface OverviewViewProps {
  /** Where the query API lives. Same-origin by default. */
  readonly apiBase?: string;
  /** The configured anchoring-lag bound. Not served by the query API — see
   * AnchoringPulse's DEFAULT_LAG_BOUND_MS. */
  readonly lagBoundMs?: number;
  /** Injected for determinism; defaults to the wall clock. */
  readonly now?: Date;
}

export function OverviewView({
  apiBase = DEFAULT_API_BASE,
  lagBoundMs = DEFAULT_LAG_BOUND_MS,
  now,
}: OverviewViewProps = {}) {
  const resource = useOverview({ base: apiBase, now });

  if (resource.status === "loading") {
    return <LoadingState what={strings.loading.what} onRetry={resource.reload} />;
  }

  /* The ledger did not answer. doc 06 §4.6: "showing nothing rather than
   * guessing" — but the heartbeat is still rendered, because §3.1 says it is
   * never hidden and a failed read is a state it has words for. */
  if (resource.overview === null) {
    return (
      <div className="flex flex-col gap-4">
        <AnchoringPulse anchor={null} lagBoundMs={lagBoundMs} now={now} />
        <ErrorState
          detail={strings.error.withReason(resource.error)}
          onRetry={resource.reload}
        />
      </div>
    );
  }

  return (
    <Overview
      data={resource.overview}
      runsToday={resource.runsToday}
      recentRuns={resource.recentRuns}
      lagBoundMs={lagBoundMs}
      apiBase={apiBase}
      now={now}
    />
  );
}

/** doc 06 §3.1's heartbeat, for the shell's header slot. */
export function OverviewHeartbeat({
  apiBase = DEFAULT_API_BASE,
  lagBoundMs = DEFAULT_LAG_BOUND_MS,
  now,
}: OverviewViewProps = {}) {
  const resource = useOverview({ base: apiBase, now });
  return (
    <AnchoringPulse
      anchor={resource.status === "loading" ? undefined : (resource.overview?.anchor ?? null)}
      lagBoundMs={lagBoundMs}
      now={now}
    />
  );
}
