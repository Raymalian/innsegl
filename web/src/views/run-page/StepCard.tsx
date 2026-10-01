// SPDX-License-Identifier: Apache-2.0

/*
 * One step in the Timeline — Main.dc.html's ordinary step, States.dc.html's
 * disagreeing one. Number, tool, summary, outcome, time, the witness rollup,
 * the output block, the inline diff for a step whose snapshot changed, the
 * commit card for the step that made one, the failed-step note, and the
 * Agent-step spawn line.
 *
 * doc 06 §5.3's run-page exception: "A failed step is GREY with its exit
 * code, never red" — `OutcomeFailedIcon`/`stepOutcomeFailed` carry no red
 * anywhere; only the witness-disagreement badge and grid are red, because
 * disagreement is an integrity alert (§4.5) and a failed tool call is simply
 * history.
 */

import { useEffect, useState } from "react";

import { truncateIdentifier } from "../../components/common/identifier";
import { Link } from "../../app/router";
import { CommitCard } from "./CommitCard";
import type { FetchProof, FetchStep, FetchStepDiff } from "./api";
import { Diff } from "./Diff";
import type { DiffMode } from "./Diff";
import { stepWitnessesAgree, witnessActiveCount, witnessAgreeCount } from "./derive";
import { AlertMarkIcon, OutcomeFailedIcon, OutcomeOkIcon } from "./icons";
import { strings } from "./strings";
import {
  panel,
  stepAgentSummary,
  stepAgentNote,
  stepHeaderRow,
  stepNumber,
  stepOutcomeFailed,
  stepOutcomeOk,
  stepOutputBlock,
  stepRefusedNote,
  stepShowFull,
  stepSummary,
  stepTime,
  stepTool,
  stepWitnessBadge,
  stepWitnessText,
  witnessCell,
  witnessCellFailed,
  witnessCellLabel,
  witnessCellLabelFailed,
  witnessCellResultFailed,
  witnessCellResult,
  witnessGrid,
} from "./styles";
import type { RecordCommit, RecordStep, RecordTree } from "./types";

export interface StepCardProps {
  readonly step: RecordStep;
  readonly runId: string;
  readonly branch: string;
  readonly tree: RecordTree;
  readonly commits: readonly RecordCommit[];
  readonly diffMode: DiffMode;
  readonly fetchStepDiff: FetchStepDiff;
  readonly fetchProof: FetchProof;
  readonly fetchStep: FetchStep;
}

export function StepCard({
  step,
  runId,
  branch,
  tree,
  commits,
  diffMode,
  fetchStepDiff,
  fetchProof,
  fetchStep,
}: StepCardProps) {
  // A clipped step's full text, once asked for (#440).
  const [full, setFull] = useState<{ readonly output: string; readonly loading: boolean } | null>(null);
  const output = full !== null && !full.loading ? full.output : step.output;
  const showFull = () => {
    setFull({ output: step.output, loading: true });
    fetchStep(runId, step.n, new AbortController().signal).then(
      (s) => setFull({ output: s.output, loading: false }),
      () => setFull(null),
    );
  };
  const agrees = stepWitnessesAgree(step.witnesses);
  const failed = step.outcome.kind !== "ok";
  const commit = commits.find((c) => c.step === step.n);
  const showDiff = step.tool !== "Agent" && step.witnesses.snapshot === "changed";
  const spawnedNode = tree.nodes.find((n) => n.run_id === step.spawned_run_id);

  return (
    <section id={`step-${step.n}`} className={panel} data-step={step.n} data-witnesses-agree={agrees}>
      <div className={stepHeaderRow} data-step-header>
        <span className={stepNumber}>{step.n}</span>
        <span className={stepTool}>{step.tool}</span>
        {step.tool === "Agent" ? (
          <AgentSpawnSummary step={step} agentType={spawnedNode?.agent_type} />
        ) : (
          <span className={stepSummary} data-summary>{step.summary}</span>
        )}
        <Outcome step={step} />
        <span className={stepTime}>{utcTime(step.at)}</span>
        {agrees ? (
          <span className={stepWitnessText}>{strings.timeline.witnessesAgreeAll(witnessActiveCount(step.witnesses))}</span>
        ) : (
          <span className={stepWitnessBadge} data-witness-badge>
            <AlertMarkIcon />
            {strings.timeline.witnessesPartial(witnessAgreeCount(step.witnesses), witnessActiveCount(step.witnesses))}
          </span>
        )}
      </div>

      {!agrees ? <WitnessGrid step={step} /> : null}

      {step.tool === "Agent" ? (
        <SubagentCommitNote step={step} />
      ) : (
        <>
          {output !== "" && !(showDiff && FILE_EDIT_TOOLS.has(step.tool) && !failed) ? (
            <pre className={stepOutputBlock}>{output}</pre>
          ) : null}
          {step.clipped && (full === null || full.loading) ? (
            <button type="button" className={stepShowFull} onClick={showFull} disabled={full?.loading === true}>
              {full?.loading === true ? strings.timeline.loadingFullOutput : strings.timeline.showFullOutput}
            </button>
          ) : null}
          {failed ? (
            <p className={stepRefusedNote}>
              {step.outcome.kind === "refused" ? `${strings.timeline.refusedBySandbox} ` : ""}
              {strings.timeline.failedIsRecord}
            </p>
          ) : null}
        </>
      )}

      {showDiff ? (
        <StepDiffBlock
          runId={runId}
          step={step.n}
          mode={diffMode}
          fetchStepDiff={fetchStepDiff}
          treeBefore={step.tree_before}
          treeAfter={step.tree_after}
        />
      ) : null}

      {commit === undefined ? null : (
        <CommitCard commit={commit} branch={branch} fetchProof={fetchProof} />
      )}
    </section>
  );
}

function utcTime(iso: string): string {
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return iso;
  return at.toISOString().slice(11, 19);
}

function Outcome({ step }: { readonly step: RecordStep }) {
  const { kind, exit_code: exitCode } = step.outcome;
  if (step.tool === "Agent") {
    return (
      <span className={stepOutcomeOk}>
        <OutcomeOkIcon />
        {strings.timeline.returned}
      </span>
    );
  }
  if (kind === "ok") {
    return (
      <span className={stepOutcomeOk}>
        <OutcomeOkIcon />
        {exitCode === null ? strings.timeline.done : strings.timeline.exitCode(exitCode)}
      </span>
    );
  }
  return (
    <span className={stepOutcomeFailed}>
      <OutcomeFailedIcon />
      {exitCode === null ? strings.timeline.failedNoExitCode : strings.timeline.failedExitCode(exitCode)}
    </span>
  );
}

function WitnessGrid({ step }: { readonly step: RecordStep }) {
  const { gateway, snapshot, telemetry } = step.witnesses;
  const gatewayOk = gateway === "present";
  // An inactive witness is not a failure (#438): it shows as not failed,
  // with its own wording.
  const snapshotOk = snapshot === "changed" || snapshot === "unchanged" || snapshot === "inactive";
  const telemetryOk = telemetry === "matched" || telemetry === "inactive";
  return (
    <dl className={witnessGrid} data-witness-grid>
      <WitnessCell
        label={strings.timeline.witnessGateway}
        ok={gatewayOk}
        text={gatewayOk ? strings.timeline.witnessGatewayPresent : strings.timeline.witnessGatewayMissing}
      />
      <WitnessCell
        label={strings.timeline.witnessSnapshot}
        ok={snapshotOk}
        text={
          snapshot === "changed"
            ? strings.timeline.witnessSnapshotChanged
            : snapshot === "unchanged"
              ? strings.timeline.witnessSnapshotUnchanged
              : snapshot === "inactive"
                ? strings.timeline.witnessSnapshotInactive
                : strings.timeline.witnessSnapshotNone
        }
      />
      <WitnessCell
        label={strings.timeline.witnessTelemetry}
        ok={telemetryOk}
        text={
          telemetry === "matched"
            ? strings.timeline.witnessTelemetryMatched
            : telemetry === "missing"
              ? strings.timeline.witnessTelemetryMissing
              : telemetry === "pending"
                ? strings.timeline.witnessTelemetryPending
                : strings.timeline.witnessTelemetryInactive
        }
      />
    </dl>
  );
}

function WitnessCell({ label, ok, text }: { readonly label: string; readonly ok: boolean; readonly text: string }) {
  return (
    <div className={`${witnessCell} ${ok ? "" : witnessCellFailed}`} data-witness-ok={ok}>
      <dt className={ok ? witnessCellLabel : witnessCellLabelFailed}>{label}</dt>
      <dd className={`${witnessCellResult} ${ok ? "" : witnessCellResultFailed}`}>
        {ok ? <OutcomeOkIcon /> : <OutcomeFailedIcon />}
        {text}
      </dd>
    </div>
  );
}

/** A file-editing tool whose change the diff shows: its own reply ("File
 * created successfully at …") adds nothing the diff does not, and the
 * approved mockup shows the diff alone. A failed edit keeps its reply. */
const FILE_EDIT_TOOLS: ReadonlySet<string> = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit"]);

/** An Agent step's row summary, as the approved mockup shows it: the agent it
 * started, linked, and the prompt it was given. */
function AgentSpawnSummary({ step, agentType }: { readonly step: RecordStep; readonly agentType: string | undefined }) {
  const label = strings.timeline.spawnedLink(
    agentType ?? strings.timeline.subagentFallback,
    truncateIdentifier(step.spawned_run_id, { kind: "run", maxLength: 14 }),
  );
  return (
    <span className={stepAgentSummary} data-summary>
      {`${strings.timeline.spawned} `}
      {step.spawned_run_id === "" ? null : (
        <Link to={{ view: "run", runId: step.spawned_run_id }}>{label}</Link>
      )}
      {strings.timeline.spawnedBrief(step.summary)}
    </span>
  );
}

function SubagentCommitNote({ step }: { readonly step: RecordStep }) {
  return step.spawned_commits.length === 0 ? null : (
    <p className={stepAgentNote}>{strings.timeline.subagentCommitNote(step.spawned_commits[0]?.slice(0, 7) ?? "")}</p>
  );
}

function StepDiffBlock({
  runId,
  step,
  mode,
  fetchStepDiff,
  treeBefore,
  treeAfter,
}: {
  readonly runId: string;
  readonly step: number;
  readonly mode: DiffMode;
  readonly fetchStepDiff: FetchStepDiff;
  readonly treeBefore: string;
  readonly treeAfter: string;
}) {
  const [state, setState] = useState<
    | { readonly status: "loading" }
    | { readonly status: "loaded"; readonly diff: Awaited<ReturnType<FetchStepDiff>> }
    | { readonly status: "failed"; readonly error: string }
  >({ status: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    let live = true;
    setState({ status: "loading" });
    fetchStepDiff(runId, step, controller.signal).then(
      (diff) => {
        if (live) setState({ status: "loaded", diff });
      },
      (cause: unknown) => {
        if (!live) return;
        setState({ status: "failed", error: cause instanceof Error ? cause.message : String(cause) });
      },
    );
    return () => {
      live = false;
      controller.abort();
    };
  }, [runId, step, fetchStepDiff]);

  if (state.status === "loading") {
    return (
      <p role="status" aria-busy="true" className="mx-4 mb-3 text-micro text-ink-muted">
        {strings.loading.diff}
      </p>
    );
  }
  if (state.status === "failed") {
    return (
      <p role="alert" className="mx-4 mb-3 text-micro text-ink-secondary">
        {strings.error.title}
        {strings.punctuation.dash}
        {state.error}
      </p>
    );
  }
  return <Diff diff={state.diff} mode={mode} treeBefore={treeBefore} treeAfter={treeAfter} />;
}
