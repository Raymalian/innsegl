// SPDX-License-Identifier: Apache-2.0

/*
 * The agent page's own header (#443, RM-278) — Agent.dc.html / Session.dc.html:
 * the lineage nav, the kicker + heading + status pill, and the four fact
 * cards, role-conditional throughout (`record.agent.role`).
 */

import { Fragment } from "react";

import { Icon } from "../../components/common/Icon";
import type { IconName } from "../../components/common/Icon";
import { IdentifierChip } from "../../components/common/IdentifierChip";
import type { RunStatus } from "../../components/common/StatusBadge";
import { Link } from "../../app/router";
import {
  dayMonthTimeUtc,
  headingTextFor,
  sessionCommittedText,
  sessionDidText,
  sessionStartedText,
  shortRepo,
  shortRunId,
  statusRangeText,
  subagentDidText,
} from "./derive";
import { AgentBranchIcon, AgentRootIcon, ChevronIcon } from "./icons";
import { strings } from "./strings";
import {
  factCard,
  factGrid,
  factIdentity,
  factLabel,
  factValue,
  headerRow,
  kicker,
  lineageLink,
  lineageNav,
  lineagePill,
  lineagePillCurrent,
  lineageSeparator,
  pageHeading,
  statusPill,
  statusPillActive,
} from "./styles";
import type { RecordAncestor, RecordRun, RunRecord } from "./types";

export interface HeaderProps {
  readonly record: RunRecord;
  readonly now: Date;
}

const KNOWN_STATUSES: readonly RunStatus[] = ["active", "lapsed", "abandoned", "retired"];

export function Header({ record, now }: HeaderProps) {
  const { run, agent } = record;
  const isSession = agent.role === "session";

  return (
    <div className="flex flex-col gap-3.5">
      <LineageNav record={record} />

      <div className={headerRow}>
        <div className="flex flex-col gap-1">
          <div className={kicker}>
            {isSession ? strings.agentPage.kickerSession : strings.agentPage.kickerSubagent(run.agent_type)}
          </div>
          <h1 className={pageHeading}>{headingText(record)}</h1>
        </div>
        <StatusPill run={run} lastStepAt={record.steps[record.steps.length - 1]?.at} />
      </div>

      <dl className={factGrid}>
        {isSession ? <SessionFacts record={record} now={now} /> : <SubagentFacts record={record} />}
      </dl>
    </div>
  );
}

function headingText(record: RunRecord): string {
  const { run, agent } = record;
  if (agent.title !== "") return agent.title;
  return agent.role === "session"
    ? strings.agentPage.sessionHeading(shortRepo(run.repo))
    : strings.header.heading(run.agent_type);
}

function ancestorLabel(ancestor: RecordAncestor): string {
  if (ancestor.role === "session") return strings.agentPage.sessionLabel;
  return headingTextFor(ancestor.title, ancestor.agent_type);
}

function LineageNav({ record }: { readonly record: RunRecord }) {
  const { agent } = record;

  if (agent.role === "session") {
    return (
      <nav aria-label={strings.agentPage.lineageAria} className={lineageNav}>
        <span className={lineagePillCurrent}>
          <AgentRootIcon className="shrink-0" />
          {strings.agentPage.thisSession}
        </span>
        <span>{strings.agentPage.startedByYou}</span>
      </nav>
    );
  }

  const parent = agent.lineage[agent.lineage.length - 1];

  return (
    <nav aria-label={strings.agentPage.lineageAria} className={lineageNav}>
      {agent.lineage.map((ancestor) => (
        <Fragment key={ancestor.run_id}>
          <Link to={{ view: "run", runId: ancestor.run_id }} className={lineagePill}>
            {ancestor.role === "session" ? (
              <AgentRootIcon className="shrink-0 text-accent" />
            ) : (
              <AgentBranchIcon className="shrink-0" />
            )}
            {ancestorLabel(ancestor)}
          </Link>
          <ChevronIcon className={lineageSeparator} />
        </Fragment>
      ))}
      {agent.spawned_at_step > 0 && parent !== undefined ? (
        <>
          <Link to={`/runs/${parent.run_id}#step-${agent.spawned_at_step}`} className={lineageLink}>
            {strings.agentPage.spawnedAtStep(agent.spawned_at_step)}
          </Link>
          <ChevronIcon className={lineageSeparator} />
        </>
      ) : null}
      <span className={lineagePillCurrent}>{strings.agentPage.thisAgent}</span>
    </nav>
  );
}

function StatusPill({ run, lastStepAt }: { readonly run: RecordRun; readonly lastStepAt?: string }) {
  const status = KNOWN_STATUSES.find((s) => s === run.status);
  if (status === undefined) return null;
  const range = statusRangeText(status, run.registered_at, run.status_at, lastStepAt);
  return (
    <span className={status === "active" ? statusPillActive : statusPill} data-run-status={status}>
      <Icon name={STATUS_ICON[status]} className="shrink-0" />
      <span className="font-medium">{statusLabel(status)}</span>
      <span aria-hidden="true">{strings.punctuation.middot}</span>
      <span>{range}</span>
    </span>
  );
}

function SubagentFacts({ record }: { readonly record: RunRecord }) {
  const { run, agent } = record;
  const parent = agent.lineage[agent.lineage.length - 1];
  return (
    <>
      <div className={factCard}>
        <dt className={factLabel}>{strings.facts.startedBy}</dt>
        <dd className={factValue}>
          {parent === undefined ? null : (
            <Link to={{ view: "run", runId: parent.run_id }}>{ancestorLabel(parent)}</Link>
          )}{" "}
          {strings.facts.startedByAt(agent.spawned_at_step, dayMonthTimeUtc(run.registered_at))}
        </dd>
      </div>
      <div className={factCard}>
        <dt className={factLabel}>{strings.facts.workedIn}</dt>
        <dd className={`${factValue} font-mono text-micro`}>{strings.facts.workedInValue(shortRepo(run.repo))}</dd>
      </div>
      <div className={factCard}>
        <dt className={factLabel}>{strings.facts.did}</dt>
        <dd className={factValue}>{subagentDidText(record)}</dd>
      </div>
      <div className={factCard}>
        <dt className={factLabel}>{strings.facts.identity}</dt>
        <dd className={`${factValue} ${factIdentity}`}>
          <IdentifierChip value={run.run_id} kind="run" display={shortRunId(run.run_id)} />
        </dd>
      </div>
    </>
  );
}

function SessionFacts({ record, now }: { readonly record: RunRecord; readonly now: Date }) {
  const { run } = record;
  return (
    <>
      <div className={factCard}>
        <dt className={factLabel}>{strings.facts.did}</dt>
        <dd className={factValue}>{sessionDidText(record, now)}</dd>
      </div>
      <div className={factCard}>
        <dt className={factLabel}>{strings.facts.started}</dt>
        <dd className={factValue}>{sessionStartedText(record)}</dd>
      </div>
      <div className={factCard}>
        <dt className={factLabel}>{strings.facts.committed}</dt>
        <dd className={factValue}>{sessionCommittedText(record)}</dd>
      </div>
      <div className={factCard}>
        <dt className={factLabel}>{strings.facts.repository}</dt>
        <dd className={`${factValue} font-mono text-micro`}>{shortRepo(run.repo)}</dd>
      </div>
    </>
  );
}

const STATUS_ICON: Record<RunStatus, IconName> = {
  active: "status-active",
  lapsed: "status-lapsed",
  abandoned: "status-abandoned",
  retired: "status-retired",
};

function statusLabel(status: RunStatus): string {
  const labels: Record<RunStatus, string> = {
    active: "Active",
    lapsed: "Lapsed",
    abandoned: "Abandoned",
    retired: "Retired",
  };
  return labels[status];
}
