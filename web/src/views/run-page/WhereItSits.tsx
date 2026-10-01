// SPDX-License-Identifier: Apache-2.0

/*
 * The aside's "Where it sits" panel (#443, RM-278) — Agent.dc.html /
 * Session.dc.html: for a subagent, its one parent, itself highlighted, and
 * its own children (by title, or the "started no subagents" fallback), plus
 * the sentence naming how its parent's spawn was matched to a step; for a
 * session, itself highlighted with a breakdown of what it started by agent
 * type. Replaces the old flat "Agent tree" panel, which showed the whole
 * family rather than this agent's own place in it.
 */

import { Link } from "../../app/router";
import { headingTextFor } from "./derive";
import { AgentBranchIcon, AgentRootIcon } from "./icons";
import { strings } from "./strings";
import { panel, panelHeading, panelHeadingRow, sitsCaption, sitsNone, sitsRowCurrent, sitsRowLink } from "./styles";
import type { RecordAgent, RecordChild, RunRecord } from "./types";

export interface WhereItSitsProps {
  readonly record: RunRecord;
}

export function WhereItSits({ record }: WhereItSitsProps) {
  const { agent } = record;
  return (
    <section className={panel} aria-labelledby="where-it-sits-heading">
      <div className={panelHeadingRow}>
        <h2 id="where-it-sits-heading" className={panelHeading}>
          {strings.agentPage.whereItSits}
        </h2>
      </div>
      <div className="flex flex-col gap-0.5 p-3">
        {agent.role === "session" ? <SessionSits record={record} /> : <SubagentSits record={record} />}
      </div>
      {agent.role === "subagent" ? <p className={sitsCaption}>{linkedBySentence(agent)}</p> : null}
    </section>
  );
}

function SubagentSits({ record }: { readonly record: RunRecord }) {
  const { agent } = record;
  const parent = agent.lineage[agent.lineage.length - 1];
  return (
    <>
      {parent === undefined ? null : (
        <Link to={{ view: "run", runId: parent.run_id }} className={sitsRowLink}>
          {parent.role === "session" ? <AgentRootIcon className="shrink-0 text-accent" /> : <AgentBranchIcon className="shrink-0" />}
          <span>{parent.role === "session" ? strings.agentPage.sessionLabel : headingTextFor(parent.title, parent.agent_type)}</span>
          <span className="flex-grow" />
          <span className="text-micro text-ink-muted">{strings.agentPage.otherAgents(Math.max(0, parent.agents - 1))}</span>
        </Link>
      )}
      <div className={`${sitsRowCurrent} pl-[28px]`}>
        <AgentBranchIcon className="shrink-0" />
        <span>{headingTextFor(agent.title, record.run.agent_type)}</span>
      </div>
      {record.children.length === 0 ? (
        <p className={sitsNone}>{strings.agentPage.startedNoSubagents}</p>
      ) : (
        record.children.map((child) => (
          <Link key={child.run_id} to={{ view: "run", runId: child.run_id }} className={`${sitsRowLink} pl-[28px]`}>
            <AgentBranchIcon className="shrink-0" />
            <span>{headingTextFor(child.title, child.agent_type)}</span>
          </Link>
        ))
      )}
    </>
  );
}

function SessionSits({ record }: { readonly record: RunRecord }) {
  const groups = groupByAgentType(record.children);
  return (
    <>
      <div className={sitsRowCurrent}>
        <AgentRootIcon className="shrink-0 text-accent" />
        <span>{strings.agentPage.thisSessionAside}</span>
      </div>
      <div className="flex flex-col gap-1 py-1 pl-[28px] text-micro text-ink-secondary">
        {groups.map((g) => (
          <span key={g.agentType}>{`${g.n} ${g.agentType}`}</span>
        ))}
      </div>
    </>
  );
}

function groupByAgentType(children: readonly RecordChild[]): Array<{ readonly agentType: string; readonly n: number }> {
  const counts = new Map<string, number>();
  for (const child of children) {
    counts.set(child.agent_type, (counts.get(child.agent_type) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([agentType, n]) => ({ agentType, n }))
    .sort((a, b) => b.n - a.n);
}

function linkedBySentence(agent: RecordAgent): string {
  if (agent.linked_by === "agent_id") return strings.agentPage.linkedByAgentId(agent.spawned_at_step);
  if (agent.linked_by === "brief") return strings.agentPage.linkedByBrief(agent.spawned_at_step);
  return strings.agentPage.linkedByNone;
}
