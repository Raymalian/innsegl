// SPDX-License-Identifier: Apache-2.0

/*
 * Staleness indicator — doc 06 §4.4, P2, §8 anti-pattern 7. Driven by FE-006.
 *
 *   §4.4: "Whenever the dashboard serves data while the ledger read path is
 *   degraded, every affected view carries a visible 'data as of {timestamp}'
 *   marker. Silent staleness violates P2."
 *
 * The requirement doc 07 states as FE-006 is "on every affected view", and
 * that phrase is the design constraint rather than a testing detail. A marker
 * each view decides to render is a marker some view forgets to render, and the
 * forgetting is invisible — the view looks fine, it is simply lying by
 * omission. doc 06 §8 calls that a defect.
 *
 * So the read-path state is provided once, above the views, and the marker
 * derives from it. A view renders <StalenessIndicator /> unconditionally and
 * never decides anything; when the read path is healthy the component renders
 * nothing at all (P3: "the healthy state is calm"). The failure mode this
 * shape removes is a view that has the marker and forgets to show it; the one
 * it leaves is a view that never places the marker, which is visible in that
 * view's own tests and in RM-050's anti-pattern pass.
 *
 * Colour: degraded/amber, per doc 06 §5.3 — "Amber = degraded/unavailable:
 * verification unavailable, anchoring lag, staleness." Staleness is not a
 * verdict and is never red, and it is emphatically never green.
 */

import { createContext, useContext } from "react";
import type { ReactNode } from "react";
import { Icon } from "./Icon";
import { strings } from "./strings";
import { degraded, hairline, noticeBase } from "./styles";
import { elapsedSince, formatAbsoluteUtc, toDateTimeAttribute } from "./time";

export interface ReadPathState {
  /** True while the dashboard is serving data it could not read freshly. */
  readonly degraded: boolean;
  /** The instant the served data was known good. */
  readonly asOf: Date | null;
  /** Injected so a render is deterministic; defaults to the wall clock. */
  readonly now: Date;
}

const HEALTHY: ReadPathState = { degraded: false, asOf: null, now: new Date() };

const ReadPathContext = createContext<ReadPathState>(HEALTHY);

/**
 * Publishes the ledger read path to every view beneath it. The shell (RM-041,
 * #49) or the query layer (RM-040, #48) owns the value; this is where views
 * read it from.
 */
export function StalenessProvider({
  degraded: isDegraded,
  asOf = null,
  now,
  children,
}: {
  readonly degraded: boolean;
  readonly asOf?: Date | null;
  readonly now?: Date;
  readonly children: ReactNode;
}) {
  return (
    <ReadPathContext.Provider
      value={{ degraded: isDegraded, asOf, now: now ?? new Date() }}
    >
      {children}
    </ReadPathContext.Provider>
  );
}

/** For a view that must change more than its marker when reads are degraded. */
export function useReadPath(): ReadPathState {
  return useContext(ReadPathContext);
}

/**
 * The "data as of {timestamp}" marker. Renders nothing when the read path is
 * healthy, and nothing when it is degraded but no timestamp is known — a
 * marker without a timestamp would be an alarm the reader cannot act on, and
 * doc 06 §4.4 specifies the timestamp as the content of the marker.
 */
export function StalenessIndicator() {
  const { degraded: isDegraded, asOf, now } = useReadPath();
  if (!isDegraded || asOf === null) return null;

  return (
    <p role="status" className={`${noticeBase} ${hairline} ${degraded}`}>
      <Icon name="staleness" className="mt-[0.15em] shrink-0" />
      <span>
        {`${strings.staleness.prefix} `}
        <time
          dateTime={toDateTimeAttribute(asOf)}
          title={formatAbsoluteUtc(asOf)}
          className="font-mono"
        >
          {formatAbsoluteUtc(asOf)}
        </time>
        {` ${strings.staleness.ago(elapsedSince(asOf, now))}. ${strings.staleness.reason}`}
      </span>
    </p>
  );
}
