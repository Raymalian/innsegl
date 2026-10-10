// SPDX-License-Identifier: Apache-2.0

/*
 * RM-333 (#511), ADR-0062's 2026-10-03 amendment — the account page's
 * organisation half: what the role allows, the machines that record for the
 * organisation (and connecting a new one), the repositories it holds, and
 * the agents that ran on its machines.
 *
 * Every write here — revoking a machine, minting an enrolment token — is
 * confirmed with a fresh passkey, and the server refuses either from a
 * member. The page hides what a role cannot do, but the server is what
 * enforces it; the privileges list says the same thing the handlers check.
 */

import { useId, useState } from "react";

import { chosenOrganisation } from "../../app/OrganisationSwitcher";
import { Link } from "../../app/router";
import {
  AccountSection,
  CopyButton,
  SectionStatus,
  latest,
  noteFor,
  useSectionLoad,
  wordFor,
} from "./accountShared";
import {
  AuthRequestError,
  fetchAccountAgents,
  fetchAccountRepositories,
  fetchMachines,
  mintEnrolmentToken,
  revokeMachine,
  type WebAuthnBrowser,
} from "./client";
import { lastSeenAgo } from "../runs/lastseen";
import { formatDate, formatDateTime } from "./format";
import { strings } from "./strings";
import type {
  AccountMachine,
  AccountOrganisation,
  EnrolmentToken,
} from "./types";
import {
  card,
  cell,
  chip,
  chipCount,
  chipList,
  columnHeader,
  commandValue,
  degraded,
  fieldLabel,
  inlineSelect,
  link,
  machineStatusFallback,
  machineStatusPill,
  mutedText,
  neutralPill,
  noticeBase,
  noticeBody,
  numericCell,
  primaryButton,
  privilegeColumns,
  privilegeItem,
  privilegeList,
  privilegeMark,
  privilegeNote,
  rowHeader,
  secondaryButton,
  secondaryText,
  secretBlock,
  secretRow,
  secretValue,
  srOnly,
  subHeading,
  table,
  scrollingTablePanel,
  focusRing,
  kindChoice,
} from "./styles";

const a = strings.account;

/** The port the core's gateway answers on, which is where `innsegl
 * connect` enrols (install.sh, deploy/compose's gateway publish). */
const CORE_PORT = 28095;

function managesMachines(org: AccountOrganisation): boolean {
  return org.privileges.some((p) => p.action === "connect_machine" && p.allowed);
}

// ---------------------------------------------------------------------------
// What you can do
// ---------------------------------------------------------------------------

export function PrivilegesSection({
  organisations,
}: {
  readonly organisations: readonly AccountOrganisation[];
}) {
  if (organisations.length === 0) return null;
  return (
    <AccountSection heading={a.privilegesHeading} intro={a.privilegesIntro}>
      {organisations.map((org) => (
        <PrivilegeLists key={org.id} org={org} named={organisations.length > 1} />
      ))}
    </AccountSection>
  );
}

function PrivilegeLists({
  org,
  named,
}: {
  readonly org: AccountOrganisation;
  readonly named: boolean;
}) {
  const allowedId = useId();
  const deniedId = useId();
  const allowed = org.privileges.filter((p) => p.allowed);
  const denied = org.privileges.filter((p) => !p.allowed);
  const label = (action: string) => wordFor(a.privileges, action);

  return (
    <div className={`${card} gap-3`}>
      {named && (
        <p className={subHeading}>
          {org.name} <span className={neutralPill}>{wordFor(a.roles, org.role)}</span>
        </p>
      )}
      <div className={privilegeColumns}>
        <div className="flex flex-col gap-2">
          <h3 id={allowedId} className={subHeading}>
            {a.privilegesAllowed}
          </h3>
          <ul aria-labelledby={allowedId} className={privilegeList}>
            {allowed.map((p) => (
              <li key={p.action} className={privilegeItem}>
                <span>
                  <span aria-hidden="true" className={`${privilegeMark} text-ink`}>
                    {a.privilegeAllowedMark}
                  </span>
                  {label(p.action)}
                </span>
              </li>
            ))}
          </ul>
        </div>
        <div className="flex flex-col gap-2">
          <h3 id={deniedId} className={subHeading}>
            {a.privilegesDenied}
          </h3>
          <ul aria-labelledby={deniedId} className={privilegeList}>
            {denied.map((p) => (
              <li key={p.action} className={privilegeItem}>
                <span className={secondaryText}>
                  <span aria-hidden="true" className={`${privilegeMark} ${mutedText}`}>
                    {a.privilegeDeniedMark}
                  </span>
                  {label(p.action)}
                </span>
                {noteFor(p.action) !== undefined && (
                  <span className={privilegeNote}>{noteFor(p.action)}</span>
                )}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Machines, and connecting a new one
// ---------------------------------------------------------------------------

type RowPhase =
  | { readonly status: "idle" }
  | { readonly status: "confirming" }
  | { readonly status: "working" }
  | { readonly status: "failed"; readonly message: string };

type ConnectPhase =
  | { readonly status: "idle" }
  | { readonly status: "working" }
  | { readonly status: "minted"; readonly token: EnrolmentToken }
  | { readonly status: "failed"; readonly message: string };

function ceremonyMessage(err: unknown, fallback: string): string {
  if (err instanceof AuthRequestError) return err.message;
  if (err instanceof Error && err.message.includes("passkey support")) return a.addUnsupported;
  if (err instanceof Error && /abort|cancel|not allowed/i.test(err.message)) return a.addCancelled;
  return fallback;
}

export function MachinesSection({
  organisations,
  browser,
}: {
  readonly organisations: readonly AccountOrganisation[];
  readonly browser: WebAuthnBrowser;
}) {
  const [load, reload] = useSectionLoad(fetchMachines);
  const [rows, setRows] = useState<Record<string, RowPhase>>({});
  const [connect, setConnect] = useState<ConnectPhase>({ status: "idle" });
  const manageable = organisations.filter(managesMachines);
  // FE-141: the organisation the header's switcher chose, when they may
  // connect a machine to it.
  const [orgId, setOrgId] = useState(
    () => manageable.find((o) => o.id === chosenOrganisation())?.id ?? manageable[0]?.id ?? "",
  );
  const [kind, setKind] = useState("workstation");
  const orgSelectId = useId();
  const kindSelectId = useId();
  const multiOrg = organisations.length > 1;

  const rowOf = (id: string): RowPhase => rows[id] ?? { status: "idle" };
  const setRow = (id: string, phase: RowPhase) => setRows((prev) => ({ ...prev, [id]: phase }));

  const revoke = async (machine: AccountMachine) => {
    setRow(machine.id, { status: "working" });
    try {
      await revokeMachine(machine.id, browser);
      setRow(machine.id, { status: "idle" });
      reload();
    } catch (err) {
      setRow(machine.id, { status: "failed", message: ceremonyMessage(err, a.revokeFailed) });
    }
  };

  const mint = async () => {
    setConnect({ status: "working" });
    try {
      const token = await mintEnrolmentToken(orgId, kind, browser);
      setConnect({ status: "minted", token });
    } catch (err) {
      setConnect({ status: "failed", message: ceremonyMessage(err, a.connectFailed) });
    }
  };

  const machines = load.status === "loaded" ? load.data.machines : [];
  const caFingerprint = load.status === "loaded" ? load.data.ca_fingerprint : "";
  const anyManageable = machines.some((m) => m.can_manage && m.status !== "revoked");
  const canConnect = manageable.length > 0 && load.status !== "unavailable";

  return (
    <AccountSection heading={a.machinesHeading} intro={a.machinesIntro}>
      <SectionStatus load={load} />

      {load.status === "loaded" && (
        <div className={scrollingTablePanel}>
          {machines.length === 0 ? (
            <p className={`p-4 ${secondaryText}`}>{a.noMachines}</p>
          ) : (
            <table className={table}>
              <caption className={srOnly}>{a.machinesHeading}</caption>
              <thead>
                <tr>
                  <th scope="col" className={columnHeader}>
                    {a.machineNameHeader}
                  </th>
                  <th scope="col" className={columnHeader}>
                    {a.machineKindHeader}
                  </th>
                  <th scope="col" className={columnHeader}>
                    {a.machineStatusHeader}
                  </th>
                  <th scope="col" className={columnHeader}>
                    {a.machineReposHeader}
                  </th>
                  <th scope="col" className={columnHeader}>
                    {a.machineEnrolledHeader}
                  </th>
                  <th scope="col" className={columnHeader}>
                    {a.machineLastActiveHeader}
                  </th>
                  {anyManageable && (
                    <th scope="col" className={columnHeader}>
                      <span className={srOnly}>{a.machineActionsHeader}</span>
                    </th>
                  )}
                </tr>
              </thead>
              <tbody>
                {machines.map((machine) => {
                  const phase = rowOf(machine.id);
                  const active = latest(machine.last_renewed_at, machine.last_run_at);
                  return (
                    <tr key={machine.id}>
                      <th scope="row" className={rowHeader}>
                        <span className="block whitespace-nowrap">{machine.name}</span>
                        {multiOrg && (
                          <span className={`block text-micro ${mutedText}`}>
                            {machine.organisation}
                          </span>
                        )}
                      </th>
                      <td className={cell}>{wordFor(a.machineKind, machine.kind)}</td>
                      <td className={cell}>
                        <span className={machineStatusPill[machine.status] ?? machineStatusFallback}>
                          {wordFor(a.machineStatus, machine.status)}
                        </span>
                      </td>
                      <td className={cell}>
                        <ul className="flex flex-col gap-0.5">
                          {machine.repos.map((repo) => (
                            <li key={repo} className="whitespace-nowrap">
                              {repo === "*" ? a.allRepositories : repo}
                            </li>
                          ))}
                        </ul>
                      </td>
                      <td className={`${cell} whitespace-nowrap`}>{formatDate(machine.enrolled_at)}</td>
                      <td className={`${cell} whitespace-nowrap`}>
                        {active === null ? (
                          <span className={mutedText}>{a.notYet}</span>
                        ) : (
                          <span title={formatDateTime(active)}>{lastSeenAgo(active, new Date())}</span>
                        )}
                      </td>
                      {anyManageable && (
                        <td className={cell}>
                          {machine.can_manage && machine.status !== "revoked" && (
                            <MachineAction
                              phase={phase}
                              onAsk={() => setRow(machine.id, { status: "confirming" })}
                              onCancel={() => setRow(machine.id, { status: "idle" })}
                              onConfirm={() => void revoke(machine)}
                            />
                          )}
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {canConnect ? (
        <div className={card}>
          <div className="flex flex-col gap-1">
            <h3 className={subHeading}>{a.connectHeading}</h3>
            <p className={`text-micro leading-prose ${secondaryText}`}>{a.connectIntro}</p>
          </div>
          {connect.status === "minted" ? (
            <MintedToken token={connect.token} caFingerprint={caFingerprint} onDone={() => {
              setConnect({ status: "idle" });
              reload();
            }} />
          ) : (
            <div className="flex flex-col gap-4">
              {manageable.length > 1 && (
                <div className="flex flex-col gap-1">
                  <label htmlFor={orgSelectId} className={`text-micro ${fieldLabel}`}>
                    {a.connectOrganisationLabel}
                  </label>
                  <select
                    id={orgSelectId}
                    value={orgId}
                    onChange={(e) => setOrgId(e.target.value)}
                    className={inlineSelect}
                  >
                    {manageable.map((org) => (
                      <option key={org.id} value={org.id}>
                        {org.name}
                      </option>
                    ))}
                  </select>
                </div>
              )}
              <fieldset className="flex w-full flex-col gap-2">
                <legend id={kindSelectId} className={`mb-2 text-micro ${fieldLabel}`}>
                  {a.connectKindLabel}
                </legend>
                <div
                  role="radiogroup"
                  aria-labelledby={kindSelectId}
                  className="grid w-full gap-3 sm:grid-cols-2"
                >
                  {(["workstation", "service"] as const).map((k) => (
                    <label key={k} className={kindChoice}>
                      <input
                        type="radio"
                        name="machine-kind"
                        value={k}
                        checked={kind === k}
                        onChange={() => setKind(k)}
                        className={`mt-1 accent-[var(--innsegl-color-accent-emphasis)] ${focusRing}`}
                      />
                      <span className="flex flex-col gap-0.5">
                        <span className="font-medium text-ink">{a.machineKind[k]}</span>
                        <span className={`text-micro leading-prose ${secondaryText}`}>
                          {a.connectKindHelp[k]}
                        </span>
                      </span>
                    </label>
                  ))}
                </div>
              </fieldset>
              <button
                type="button"
                disabled={connect.status === "working"}
                onClick={() => void mint()}
                className={`${primaryButton} ${focusRing}`}
              >
                {connect.status === "working" ? a.connectWorking : a.connectButton}
              </button>
            </div>
          )}
          {connect.status === "failed" && (
            <p role="alert" className={`${noticeBase} ${degraded}`}>
              <span className={noticeBody}>{connect.message}</span>
            </p>
          )}
        </div>
      ) : (
        load.status !== "unavailable" &&
        organisations.length > 0 && (
          <p className={`text-micro ${secondaryText}`}>{a.connectNeedsRole}</p>
        )
      )}
    </AccountSection>
  );
}

function MachineAction({
  phase,
  onAsk,
  onCancel,
  onConfirm,
}: {
  readonly phase: RowPhase;
  readonly onAsk: () => void;
  readonly onCancel: () => void;
  readonly onConfirm: () => void;
}) {
  if (phase.status === "confirming" || phase.status === "working") {
    return (
      <div className="flex min-w-[14rem] flex-col gap-2">
        <span className={`text-micro ${secondaryText}`}>{a.revokeConfirmPrompt}</span>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            disabled={phase.status === "working"}
            onClick={onConfirm}
            className={`${secondaryButton} ${focusRing}`}
          >
            {phase.status === "working" ? a.revokeWorking : a.revokeConfirmButton}
          </button>
          <button type="button" onClick={onCancel} className={`${secondaryButton} ${focusRing}`}>
            {a.revokeCancelButton}
          </button>
        </div>
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-2">
      <button type="button" onClick={onAsk} className={`${secondaryButton} ${focusRing}`}>
        {a.revokeButton}
      </button>
      {phase.status === "failed" && (
        <p role="alert" className={`text-micro ${mutedText}`}>
          {phase.message}
        </p>
      )}
    </div>
  );
}

function MintedToken({
  token,
  caFingerprint,
  onDone,
}: {
  readonly token: EnrolmentToken;
  /** The core's CA fingerprint; empty when the API could not read it. */
  readonly caFingerprint: string;
  readonly onDone: () => void;
}) {
  const tokenLabelId = useId();
  const commandLabelId = useId();
  const pin = caFingerprint ? `--ca-fingerprint ${caFingerprint}` : `--ca ${a.connectCaPlaceholder}`;
  const command = `innsegl connect https://${window.location.hostname}:${CORE_PORT} --token ${token.token} ${pin}`;
  return (
    <div className={secretBlock}>
      <div className="flex flex-col gap-1">
        <span id={tokenLabelId} className={`text-micro ${fieldLabel}`}>
          {a.tokenLabel}
        </span>
        <div className={secretRow}>
          <code aria-labelledby={tokenLabelId} className={secretValue}>
            {token.token}
          </code>
          <CopyButton value={token.token} label={a.copyToken} />
        </div>
        <span className={`text-micro ${secondaryText}`}>{a.tokenOnce}</span>
      </div>
      <div className="flex flex-col gap-1">
        <span id={commandLabelId} className={`text-micro ${fieldLabel}`}>
          {a.commandLabel}
        </span>
        <div className={secretRow}>
          <code aria-labelledby={commandLabelId} className={commandValue}>
            {command}
          </code>
          <CopyButton value={command} label={a.copyCommand} />
        </div>
        <span className={`text-micro ${secondaryText}`}>{a.connectCaNote}</span>
      </div>
      <p className="text-micro">
        <span className={fieldLabel}>{a.expiresLabel}</span>{" "}
        <span className={secondaryText}>{formatDateTime(token.expires_at)}</span>
      </p>
      <button type="button" onClick={onDone} className={`${secondaryButton} ${focusRing}`}>
        {a.connectDone}
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Repositories
// ---------------------------------------------------------------------------

export function RepositoriesSection({ multiOrg }: { readonly multiOrg: boolean }) {
  const [load] = useSectionLoad(fetchAccountRepositories);
  return (
    <AccountSection heading={a.repositoriesHeading} intro={a.repositoriesIntro}>
      <SectionStatus load={load} />
      {load.status === "loaded" && (
        <div className={scrollingTablePanel}>
          {load.data.length === 0 ? (
            <p className={`p-4 ${secondaryText}`}>{a.noRepositories}</p>
          ) : (
            <table className={table}>
              <caption className={srOnly}>{a.repositoriesHeading}</caption>
              <thead>
                <tr>
                  <th scope="col" className={columnHeader}>
                    {a.repoHeader}
                  </th>
                  <th scope="col" className={`${columnHeader} text-right`}>
                    {a.repoRunsHeader}
                  </th>
                  <th scope="col" className={`${columnHeader} text-right`}>
                    {a.repoCommitsHeader}
                  </th>
                  <th scope="col" className={columnHeader}>
                    {a.repoLastHeader}
                  </th>
                  <th scope="col" className={columnHeader}>
                    {a.repoSinceHeader}
                  </th>
                </tr>
              </thead>
              <tbody>
                {load.data.map((repo) => (
                  <tr key={`${repo.organisation_id}/${repo.repo}`}>
                    <th scope="row" className={rowHeader}>
                      <Link
                        to={{ view: "repo", repo: repo.repo, from: "", to: "" }}
                        className={`${link} whitespace-nowrap`}
                      >
                        {repo.repo}
                      </Link>
                      {multiOrg && (
                        <span className={`block text-micro ${mutedText}`}>{repo.organisation}</span>
                      )}
                    </th>
                    <td className={`${cell} ${numericCell} text-right`}>{repo.runs}</td>
                    <td className={`${cell} ${numericCell} text-right`}>{repo.commits}</td>
                    <td className={`${cell} whitespace-nowrap`}>
                      {repo.last_event_at === null ? (
                        <span className={mutedText}>{a.nothingRecorded}</span>
                      ) : (
                        formatDate(repo.last_event_at)
                      )}
                    </td>
                    <td className={`${cell} whitespace-nowrap`}>{formatDate(repo.since)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </AccountSection>
  );
}

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------

export function AgentsSection() {
  const [load] = useSectionLoad(fetchAccountAgents);
  const typesId = useId();
  const runsId = useId();
  return (
    <AccountSection heading={a.agentsHeading} intro={a.agentsIntro}>
      <SectionStatus load={load} />
      {load.status === "loaded" &&
        (load.data.agent_types.length === 0 && load.data.recent_runs.length === 0 ? (
          <p className={`${card} ${secondaryText}`}>{a.noAgents}</p>
        ) : (
          <>
            <div className="flex flex-col gap-2">
              <h3 id={typesId} className={subHeading}>
                {a.agentTypesHeading}
              </h3>
              <ul aria-labelledby={typesId} className={chipList}>
                {load.data.agent_types.map((t) => (
                  <li key={t.agent_type} className={chip}>
                    <Link
                      to={{ view: "agentType", agentType: t.agent_type, from: "", to: "" }}
                      className={link}
                    >
                      {t.agent_type}
                    </Link>
                    <span className="text-micro">
                      <span className={chipCount}>{t.runs}</span>{" "}
                      <span className={secondaryText}>{a.agentTypeRuns}</span>
                    </span>
                  </li>
                ))}
              </ul>
            </div>
            <div className="flex flex-col gap-2">
              <h3 id={runsId} className={subHeading}>
                {a.recentRunsHeading}
              </h3>
              <div className={scrollingTablePanel}>
                <table aria-labelledby={runsId} className={table}>
                  <thead>
                    <tr>
                      <th scope="col" className={columnHeader}>
                        {a.runHeader}
                      </th>
                      <th scope="col" className={columnHeader}>
                        {a.runAgentHeader}
                      </th>
                      <th scope="col" className={columnHeader}>
                        {a.runTaskHeader}
                      </th>
                      <th scope="col" className={columnHeader}>
                        {a.runMachineHeader}
                      </th>
                      <th scope="col" className={columnHeader}>
                        {a.runStartedHeader}
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {load.data.recent_runs.map((run) => (
                      <tr key={run.run_id}>
                        <th scope="row" className={rowHeader}>
                          <Link
                            to={{ view: "run", runId: run.run_id }}
                            className={`${link} whitespace-nowrap font-mono text-micro`}
                          >
                            {run.run_id}
                          </Link>
                        </th>
                        <td className={`${cell} whitespace-nowrap`}>{run.agent_type}</td>
                        <td className={`${cell} min-w-[10rem] max-w-[18rem]`}>{run.task_ref}</td>
                        <td className={`${cell} whitespace-nowrap`}>{run.machine_name}</td>
                        <td className={`${cell} whitespace-nowrap`}>{formatDate(run.registered_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        ))}
    </AccountSection>
  );
}

export { managesMachines };
