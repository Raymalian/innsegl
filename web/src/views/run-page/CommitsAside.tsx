// SPDX-License-Identifier: Apache-2.0

/*
 * The aside's "Commits" panel (#443, RM-278) — Agent.dc.html / Session.dc.html.
 *
 * Three shapes, chosen by what the record itself says:
 *
 *   - no commits at all: "None." (Agent.dc.html).
 *   - every commit signed by this very run: sha + subject, listed plainly —
 *     the ordinary case for a subagent, and for a session whose own commits
 *     were never delegated to a one-commit identity.
 *   - at least one commit signed by a run this one started rather than by
 *     itself: the session board's own sentence about one-commit identities
 *     (RM-278's reason those exist at all — a run that only ever signed one
 *     commit is a commit, not an agent, and does not belong in "Agents it
 *     started"), the first three shown, then a link to the rest.
 *
 * The old aside's "made by step N · landed on <branch>" caption is gone: the
 * new board shows neither, and a step that made a commit now carries a
 * commit chip of its own in "What it ran".
 */

import { strings } from "./strings";
import { commitLink, commitsList, commitsNote, commitsShowAll, panel, panelHeading, panelHeadingRow, panelPad } from "./styles";
import type { RecordCommit } from "./types";

export interface CommitsAsideProps {
  readonly commits: readonly RecordCommit[];
  readonly runId: string;
  readonly role: "session" | "subagent";
}

export function CommitsAside({ commits, runId, role }: CommitsAsideProps) {
  const identities = role === "session" && commits.some((c) => c.signed_by !== runId);
  return (
    <section className={panel} aria-labelledby="commits-aside-heading">
      <div className={panelHeadingRow}>
        <h2 id="commits-aside-heading" className={panelHeading}>
          {strings.commits.heading}
        </h2>
      </div>
      <div className={`${panelPad} gap-2`}>
        {commits.length === 0 ? (
          <span className={commitsNote}>{strings.commits.none}</span>
        ) : identities ? (
          <IdentitiesList commits={commits} />
        ) : (
          <PlainList commits={commits} />
        )}
      </div>
    </section>
  );
}

function PlainList({ commits }: { readonly commits: readonly RecordCommit[] }) {
  return (
    <div className={commitsList}>
      {commits.map((commit) => (
        <div key={commit.sha} className="flex items-baseline gap-2">
          <a href={`#commit-${commit.sha}`} className={commitLink}>
            {commit.sha.slice(0, 7)}
          </a>
          <span className="min-w-0 truncate text-micro text-ink-secondary">{commit.subject}</span>
        </div>
      ))}
    </div>
  );
}

function IdentitiesList({ commits }: { readonly commits: readonly RecordCommit[] }) {
  const shown = commits.slice(0, 3);
  return (
    <>
      <span className={commitsNote}>{strings.commits.oneCommitIdentities(commits.length)}</span>
      <div className={commitsList}>
        {shown.map((commit) => (
          <a key={commit.sha} href={`#commit-${commit.sha}`} className={commitLink}>
            {commit.sha.slice(0, 7)}
          </a>
        ))}
      </div>
      {commits.length > 0 ? (
        <a href="#commits" className={commitsShowAll}>
          {strings.commits.allCommits(commits.length)}
        </a>
      ) : null}
    </>
  );
}
