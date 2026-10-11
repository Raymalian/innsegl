// SPDX-License-Identifier: Apache-2.0

/*
 * RM-319 (#579): the sessions enrolled machines reported as sending model
 * traffic that bypassed innsegl. A machine's client service finds them by
 * comparing the harness's own transcripts with the traffic it forwarded; the
 * core keeps one row per session. They come with the overview
 * (`unrouted_sessions`), already scoped to the viewer's machines. Nothing
 * renders when there are none. Nothing here is refused anywhere: these
 * sessions ran, unrecorded, and this says so.
 */

import { strings } from "./strings";
import { degraded, hairline } from "./styles";
import type { UnroutedSession } from "./types";

export interface UnroutedNoticeProps {
  readonly sessions: readonly UnroutedSession[] | undefined;
}

/** "2026-10-11T05:01:00Z" as "2026-10-11 05:01 UTC". */
function minuteUTC(iso: string): string {
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
}

export function UnroutedNotice({ sessions }: UnroutedNoticeProps) {
  if (!sessions || sessions.length === 0) return null;
  return (
    <section
      aria-label={strings.unrouted.regionLabel}
      className={`${hairline} ${degraded} flex flex-col gap-1 rounded-md p-3`}
    >
      {sessions.map((s) => (
        <p key={`${s.installation_id}/${s.session_id}`}>
          {strings.unrouted.line(s.session_id, s.installation_id, minuteUTC(s.last_activity_at))}
        </p>
      ))}
    </section>
  );
}
