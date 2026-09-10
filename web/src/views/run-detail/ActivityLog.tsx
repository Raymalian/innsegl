// SPDX-License-Identifier: Apache-2.0

/*
 * What the agent actually did, and whether the chain still vouches for it.
 *
 * The timeline above this says a tool was called. It cannot say more: doc 02
 * §3 gives a `tool_call` event no member for its body and IP E4 makes that
 * mechanical, so the ledger records `"tool_name": "Edit"` and a digest and
 * nothing else. The chain is append-only as well, so anything written there
 * could never be deleted — and this detail has a 90-day life by the operator's
 * decision.
 *
 * The two halves therefore live apart, and the split is what makes this panel
 * worth reading: the digest in the chain is evidence about a file the chain
 * does not contain. Every line carries the verdict of that comparison.
 *
 *   verified   the bytes on disk hash to the digest the ledger recorded
 *   altered    a body is there and is NOT what was recorded
 *   expired    no body: it aged out, or this deployment keeps none
 *
 * `altered` is the reason this is not just a log viewer, and the body of an
 * altered line is deliberately not shown — its bytes are not what was vouched
 * for, and rendering them next to verified ones is how a forgery comes to be
 * read as evidence. doc 06 §5.3 gives red to a failed verification, which is
 * exactly what an altered body is.
 *
 * Identity is not affected by any of this and never expires: it lives in the
 * chain. This panel going empty after ninety days is the system working.
 */

import { useEffect, useState } from "react";

import { EmptyState } from "../../components/common/EmptyState";
import { strings } from "./strings";
import { block, secondaryText, sectionHeading, srOnly } from "./styles";

export interface LogEntry {
  chain_position: number;
  tool_name: string;
  ts: string;
  payload_digest: string;
  integrity: "verified" | "altered" | "expired";
  body?: unknown;
}

export interface RunLog {
  run_id: string;
  retention_days: number;
  entries: LogEntry[];
  verified: number;
  altered: number;
  expired: number;
}

export async function fetchRunLog(runId: string, signal?: AbortSignal): Promise<RunLog> {
  const response = await fetch(`/api/v1/runs/${encodeURIComponent(runId)}/log`, { signal });
  if (!response.ok) {
    throw new Error(`the activity log answered ${response.status}`);
  }
  return (await response.json()) as RunLog;
}

/* One line's mark. Colour is not the only carrier — doc 06 requires the word
 * to stand alone, because a reader who cannot separate the hues must still be
 * able to tell an altered body from an expired one. */
const markStyle: Record<LogEntry["integrity"], string> = {
  verified: "text-ok",
  altered: "text-alarm font-semibold",
  expired: "text-ink-muted",
};

/** The integrity of one entry: said once loudly, or shown once quietly.
 *
 * Repeating "matches the ledger" on every one of a hundred and forty-one rows is
 * what made this section a wall. The eye cannot find the row that does NOT match
 * when every row shouts that it does, and the count above already states it
 * exactly — "141 checked against the ledger, 0 altered". So the per-row job is
 * to mark the EXCEPTIONS: doc 06 P3's strongest claim first, and §5.3's rule
 * that green is never decoration.
 *
 * A match is a tick. Anything that is not a match keeps its words, at full
 * weight, where they can be seen.
 *
 * The words survive for assistive technology either way — the tick carries the
 * same sentence in `title` and in visually hidden text — so a row is never
 * distinguished by colour or by glyph alone (doc 06 §6.4). */
function IntegrityMark({ integrity }: { readonly integrity: LogEntry["integrity"] }) {
  const label = strings.activity.integrity[integrity];
  if (integrity !== "verified") {
    return <span className={markStyle[integrity]}>{label}</span>;
  }
  return (
    <span className={markStyle.verified} title={label}>
      <svg
        viewBox="0 0 16 16" width="12" height="12" fill="none" aria-hidden="true"
        stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
      >
        <path d="M3.5 8.5l3 3 6-7" />
      </svg>
      <span className={srOnly}>{label}</span>
    </span>
  );
}

function summarise(body: unknown): string {
  if (typeof body !== "object" || body === null) return "";
  const input = (body as { tool_input?: Record<string, unknown> }).tool_input;
  if (!input) return "";
  /* The fields a reader recognises, in the order they answer "what did it do":
   * which file, or which command. Everything else stays in the raw body. */
  for (const key of ["file_path", "command", "pattern", "url", "path"]) {
    const value = input[key];
    if (typeof value === "string" && value !== "") return value;
  }
  return "";
}

export function ActivityLog({ runId }: { runId: string }): React.JSX.Element {
  const [log, setLog] = useState<RunLog | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    fetchRunLog(runId, controller.signal)
      .then(setLog)
      .catch(() => {
        if (!controller.signal.aborted) setFailed(true);
      });
    return () => controller.abort();
  }, [runId]);

  if (failed) {
    return (
      <section className={block}>
        <h2 className={sectionHeading}>{strings.activity.heading}</h2>
        <p className={secondaryText}>{strings.activity.failed}</p>
      </section>
    );
  }
  if (!log) return <></>;

  return (
    <section className={block}>
      <h2 className={sectionHeading}>{strings.activity.heading}</h2>
      <p className={secondaryText}>
        {strings.activity.retention(log.retention_days)}
      </p>
      {log.entries.length === 0 ? (
        <EmptyState title={strings.activity.empty} detail={strings.activity.emptyDetail} />
      ) : (
        <>
          <p className={secondaryText}>
            {strings.activity.counts(log.verified, log.altered, log.expired)}
          </p>
          {/* A GRID, not a wrapping flex row.
            *
            * Every row is (position, tool, command, integrity) and the command
            * is the only unbounded one. As a wrapping flex row a long command
            * WRAPPED rather than truncating — `truncate` cannot take effect on a
            * flex item that is allowed to wrap — which pushed the integrity mark
            * onto its own line and destroyed the alignment of every column.
            * Fixed tracks put the four back in columns and give the command
            * exactly the room that is left.
            *
            * `minmax(0,1fr)` is what lets the command track shrink below its
            * content, which is what makes the ellipsis happen at all. */}
          <ul className="m-0 list-none divide-y divide-line p-0">
            {log.entries.map((entry) => (
              <li
                key={entry.chain_position}
                className="grid grid-cols-[auto_auto_minmax(0,1fr)_auto] items-baseline gap-x-3 py-1 text-micro"
              >
                <span className="text-ink-muted tabular-nums">{entry.chain_position}</span>
                <span className="font-medium text-ink">{entry.tool_name}</span>
                {/* What was run, set as code and held to one line. The full text
                  * is on the element: a truncated command nobody can read in
                  * full is evidence nobody can check. */}
                <span
                  className="min-w-0 overflow-hidden font-mono text-ellipsis whitespace-nowrap text-ink-muted"
                  title={summarise(entry.body)}
                >
                  {summarise(entry.body)}
                </span>
                <IntegrityMark integrity={entry.integrity} />
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
