// SPDX-License-Identifier: Apache-2.0

/*
 * The left aside's "Commits" panel — Main.dc.html: one row per commit, the
 * SHA linking to the step that made it, and "made by step N · landed on
 * <branch>" beneath — or, for a commit the repository never landed (States
 * board), "on no branch" instead.
 *
 * ── THE ONE THING THIS CANNOT SAY ──────────────────────────────────────────
 *
 * The mockup's not-landed card names a REASON — "lost git's ref lock to a
 * parallel commit". `RecordCommit` (types.ts, the contract) carries no field
 * for it: `landed` is the closed `Landed` enum and nothing else. This view
 * cannot invent a reason the contract does not supply, so it says only what
 * the contract says — reported as a contract gap rather than guessed at.
 */

import { strings } from "./strings";
import { commitLink, panel, panelHeadingRow, panelHeading, panelPad } from "./styles";
import type { RecordCommit } from "./types";

export interface CommitsAsideProps {
  readonly commits: readonly RecordCommit[];
  readonly branch: string;
}

export function CommitsAside({ commits, branch }: CommitsAsideProps) {
  return (
    <section className={panel} aria-labelledby="commits-aside-heading">
      <div className={panelHeadingRow}>
        <h2 id="commits-aside-heading" className={panelHeading}>
          {strings.commits.heading}
        </h2>
      </div>
      <div className={`${panelPad} gap-3`}>
        {commits.map((commit) => (
          <div key={commit.sha} className="flex flex-col gap-0.5">
            <a href={`#commit-${commit.sha}`} className={commitLink}>
              {commit.sha.slice(0, 7)}
            </a>
            <span className="text-micro text-ink-secondary">
              {strings.commits.madeByStep(commit.step)}
              {strings.punctuation.middot}
              {commit.landed === "landed"
                ? strings.commits.landedOn(branch)
                : commit.landed === "not_landed"
                  ? strings.commits.notLanded
                  : commit.landed === "rewritten"
                    ? strings.commits.rewritten
                    : strings.commits.landedOn(branch)}
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}
