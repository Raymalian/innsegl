// SPDX-License-Identifier: Apache-2.0

/*
 * The session page's own "Agents it started" table (#443, RM-278) —
 * Session.dc.html: direct children only, by task, with their steps,
 * commits and status — never the whole family, and never a run that only
 * ever signed a commit (those are listed as commits, in the aside, not
 * here). A search box filters by title; the first 8 show, then "Show more
 * agents".
 */

import { useState } from "react";

import { Link } from "../../app/router";
import { endedColumnText, headingTextFor } from "./derive";
import { SearchIcon } from "./icons";
import { strings } from "./strings";
import {
  agentCellEnded,
  agentCellKind,
  agentCellNum,
  agentCellSpawned,
  agentCellTask,
  agentCellTitle,
  agentRow,
  agentsFooter,
  agentsSearchBox,
  agentsSearchInput,
  agentsTable,
  agentsTableHeadRow,
  link,
  sectionHeadRow,
  sectionHeading,
  sectionSub,
} from "./styles";
import type { RecordChild } from "./types";

const PAGE = 8;

export interface AgentsStartedProps {
  readonly children: readonly RecordChild[];
}

export function AgentsStarted({ children }: AgentsStartedProps) {
  const [query, setQuery] = useState("");
  const [shown, setShown] = useState(PAGE);

  const filtered = query.trim() === "" ? children : children.filter((c) => c.title.toLowerCase().includes(query.trim().toLowerCase()));
  const visible = filtered.slice(0, shown);
  const left = filtered.length - visible.length;

  return (
    <>
      <div className={sectionHeadRow}>
        <h2 className={sectionHeading}>{strings.agentPage.agentsStartedHeading}</h2>
        <span className={sectionSub}>{strings.agentPage.agentsStartedSub}</span>
        <span className="flex-grow" />
        <label className={agentsSearchBox}>
          <SearchIcon className="shrink-0" />
          <input
            type="search"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setShown(PAGE);
            }}
            placeholder={strings.agentPage.findAnAgent}
            aria-label={strings.agentPage.findAnAgent}
            className={agentsSearchInput}
          />
        </label>
      </div>

      <section className={agentsTable} aria-label={strings.agentPage.agentsStartedHeading}>
        <div className={agentsTableHeadRow}>
          <span className="flex-grow">{strings.agentPage.colTask}</span>
          <span className="w-[150px]">{strings.agentPage.colKind}</span>
          <span className="w-[70px] text-right">{strings.agentPage.colSteps}</span>
          <span className="w-[70px] text-right">{strings.agentPage.colCommits}</span>
          <span className="w-[120px] text-right">{strings.agentPage.colEnded}</span>
        </div>

        {visible.map((child) => (
          <Link key={child.run_id} to={{ view: "run", runId: child.run_id }} className={agentRow}>
            <span className={agentCellTask}>
              <span className={agentCellTitle}>{headingTextFor(child.title, child.agent_type)}</span>
              <span className={agentCellSpawned}>{strings.agentPage.spawnedAtStep(child.spawned_at_step)}</span>
            </span>
            <span className={agentCellKind}>{child.model === "" ? child.agent_type : `${child.agent_type} · ${child.model}`}</span>
            <span className={agentCellNum}>{child.steps}</span>
            <span className={agentCellNum}>{child.commits}</span>
            <span className={agentCellEnded}>{endedColumnText(child.status, child.ended_at)}</span>
          </Link>
        ))}

        <div className={agentsFooter}>
          <span>{strings.agentPage.showingOf(visible.length, filtered.length)}</span>
          <span className="flex-grow" />
          {left > 0 ? (
            <button type="button" className={link} onClick={() => setShown(shown + PAGE)}>
              {strings.agentPage.showMoreAgents}
            </button>
          ) : null}
        </div>
      </section>
    </>
  );
}
