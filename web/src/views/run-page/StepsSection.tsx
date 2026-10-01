// SPDX-License-Identifier: Apache-2.0

/*
 * "What it ran" (#443, RM-278) — Agent.dc.html / Session.dc.html: the compact
 * step table shared by a subagent's and a session's own page.
 *
 * A row opens on click to show the same body the old per-step StepCard
 * rendered — output, an inline diff, a commit card, the witness grid for a
 * disagreement — reused here rather than reimplemented (the task's own
 * instruction: Main.dc.html is what StepCard already renders). A failed
 * step, a file write, a commit, or a witness disagreement opens by default;
 * a run of three or more ordinary tool rows collapses into one disclosure.
 *
 * The subagent's own "Commands / With output" toggle forces every row open
 * and disables collapsing; the session's own "All / Agents started /
 * Commits / Failed" filter narrows which steps show, newest first. Both
 * keep the existing paging (100 steps at a time, #440) and the existing
 * Unified/Side-by-side diff toggle (doc 06 §7: its own choice lives in the
 * URL), reused inside whichever row currently shows a diff.
 */

import { useEffect, useState } from "react";

import { truncateIdentifier } from "../../components/common/identifier";
import { Link } from "../../app/router";
import { CommitCard } from "./CommitCard";
import type { FetchProof, FetchStep, FetchStepDiff } from "./api";
import { Diff } from "./Diff";
import type { DiffMode } from "./Diff";
import { DiffToggle } from "./DiffToggle";
import {
  childFor,
  filterSteps,
  groupRange,
  headingTextFor,
  newestFirst,
  planStepRows,
  stepFailed,
  stepWitnessesAgree, toolDisplayName } from "./derive";
import type { SessionStepFilter as Filter } from "./derive";
import { CommitIcon, OutcomeFailedIcon, OutcomeOkIcon } from "./icons";
import { strings } from "./strings";
import {
  link,
  rowCellMain,
  rowCellN,
  rowCellProse,
  rowCellResult,
  rowCellTime,
  rowCellTool,
  rowCommitChip,
  sectionHeadRow,
  sectionHeading,
  showMoreButton,
  stepCardDeferred,
  stepGroupRow,
  stepGroupShow,
  stepOutputBlock,
  diffTextBase,
  diffAddedMarker,
  diffMarkerBase,
  diffAddedGutter,
  diffLineNoBase,
  diffAddedRow,
  diffRowUnified,
  diffFileHeader,
  diffShell,
  stepRefusedNote,
  stepRowBody,
  stepRowButton,
  stepRowStatic,
  stepShowFull,
  stepTable,
  stepTableHeadRow,
  toggleButton,
  toggleButtonIdle,
  toggleButtonSelected,
  toggleGroup,
  witnessCell,
  witnessCellFailed,
  witnessCellLabel,
  witnessCellLabelFailed,
  witnessCellResult,
  witnessCellResultFailed,
  witnessGrid,
} from "./styles";
import type { RecordStep, RunRecord } from "./types";

const STEP_PAGE = 100;

export interface StepsSectionProps {
  readonly record: RunRecord;
  readonly role: "session" | "subagent";
  readonly runId: string;
  readonly branch: string;
  readonly diffMode: DiffMode;
  readonly onDiffModeChange: (mode: DiffMode) => void;
  readonly fetchStepDiff: FetchStepDiff;
  readonly fetchProof: FetchProof;
  readonly fetchStep: FetchStep;
}

export function StepsSection({
  record,
  role,
  runId,
  branch,
  diffMode,
  onDiffModeChange,
  fetchStepDiff,
  fetchProof,
  fetchStep,
}: StepsSectionProps) {
  const [withOutput, setWithOutput] = useState(false);
  const [filter, setFilter] = useState<Filter>("all");
  const [flipped, setFlipped] = useState<ReadonlySet<number>>(new Set());
  const [expandedGroups, setExpandedGroups] = useState<ReadonlySet<number>>(new Set());
  const [shown, setShown] = useState(STEP_PAGE);

  const ordered = role === "session" ? newestFirst(filterSteps(record.steps, filter)) : [...record.steps];
  const page = ordered.slice(0, shown);
  const left = ordered.length - page.length;
  const allOpen = role === "subagent" && withOutput;
  const plan = planStepRows(record, page, allOpen);

  const toggleRow = (n: number) =>
    setFlipped((prev) => {
      const next = new Set(prev);
      if (next.has(n)) next.delete(n);
      else next.add(n);
      return next;
    });
  const isOpen = (step: RecordStep, planOpen: boolean) => (allOpen ? true : flipped.has(step.n) ? !planOpen : planOpen);
  const expandGroup = (key: number) => setExpandedGroups((prev) => new Set(prev).add(key));

  return (
    <>
      <div className={sectionHeadRow}>
        <h2 className={sectionHeading}>
          {role === "session" ? strings.agentPage.whatItRanSession(ordered.length) : strings.agentPage.whatItRanSubagent(ordered.length)}
        </h2>
        {role === "subagent" ? (
          <div role="group" aria-label={strings.agentPage.commandsToggle} className={toggleGroup}>
            <button
              type="button"
              aria-pressed={!withOutput}
              onClick={() => setWithOutput(false)}
              className={`${toggleButton} ${!withOutput ? toggleButtonSelected : toggleButtonIdle}`}
            >
              {strings.agentPage.commandsToggle}
            </button>
            <button
              type="button"
              aria-pressed={withOutput}
              onClick={() => setWithOutput(true)}
              className={`${toggleButton} ${withOutput ? toggleButtonSelected : toggleButtonIdle}`}
            >
              {strings.agentPage.withOutputToggle}
            </button>
          </div>
        ) : (
          <div role="group" aria-label={strings.agentPage.filterAll} className={toggleGroup}>
            {(["all", "spawned", "commits", "failed"] as const).map((f) => (
              <button
                key={f}
                type="button"
                aria-pressed={filter === f}
                onClick={() => setFilter(f)}
                className={`${toggleButton} ${filter === f ? toggleButtonSelected : toggleButtonIdle}`}
              >
                {filterLabel(f)}
              </button>
            ))}
          </div>
        )}
        {record.steps.some((st) => st.witnesses.snapshot === "changed") ? (
          <DiffToggle mode={diffMode} onChange={onDiffModeChange} />
        ) : null}
      </div>

      {record.steps.length === 0 ? <p className="text-micro text-ink-secondary">{strings.timeline.noSteps}</p> : null}

      <section className={stepTable}>
        {role === "subagent" ? (
          <div className={stepTableHeadRow}>
            <span className={rowCellN}>{strings.agentPage.colN}</span>
            <span className={rowCellTool}>{strings.agentPage.colTool}</span>
            <span className="flex-grow">{strings.agentPage.colCommand}</span>
            <span className={rowCellResult}>{strings.agentPage.colResult}</span>
            <span className={rowCellTime}>{strings.agentPage.colTime}</span>
          </div>
        ) : null}

        {plan.map((item) => {
          if (item.kind === "group") {
            const key = Math.min(...item.steps.map((s) => s.n));
            if (expandedGroups.has(key)) {
              return item.steps.map((step) => (
                <StepRow
                  key={step.n}
                  record={record}
                  step={step}
                  open={isOpen(step, false)}
                  onToggle={() => toggleRow(step.n)}
                  runId={runId}
                  branch={branch}
                  diffMode={diffMode}
                  fetchStepDiff={fetchStepDiff}
                  fetchProof={fetchProof}
                  fetchStep={fetchStep}
                />
              ));
            }
            const { a, b, atA, atB } = groupRange(item.steps);
            return (
              <div key={key} className={stepGroupRow}>
                {strings.agentPage.groupRange(a, b, item.steps.length, utcTime(atA), utcTime(atB))}
                {strings.punctuation.middot}
                <button type="button" className={stepGroupShow} onClick={() => expandGroup(key)}>
                  {strings.agentPage.show}
                </button>
              </div>
            );
          }
          return (
            <StepRow
              key={item.step.n}
              record={record}
              step={item.step}
              open={isOpen(item.step, item.open)}
              onToggle={() => toggleRow(item.step.n)}
              runId={runId}
              branch={branch}
              diffMode={diffMode}
              fetchStepDiff={fetchStepDiff}
              fetchProof={fetchProof}
              fetchStep={fetchStep}
            />
          );
        })}
      </section>

      {left > 0 ? (
        <button type="button" className={showMoreButton} onClick={() => setShown(shown + STEP_PAGE)}>
          {strings.timeline.showMore(Math.min(STEP_PAGE, left), left)}
        </button>
      ) : null}
    </>
  );
}

function filterLabel(f: Filter): string {
  if (f === "spawned") return strings.agentPage.filterSpawned;
  if (f === "commits") return strings.agentPage.filterCommits;
  if (f === "failed") return strings.agentPage.filterFailed;
  return strings.agentPage.filterAll;
}

function utcTime(iso: string): string {
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return iso;
  return at.toISOString().slice(11, 19);
}

function resultText(step: RecordStep): string {
  if (step.kind === "spawn") return strings.timeline.returned;
  const { kind, exit_code: exitCode } = step.outcome;
  if (kind === "ok") return exitCode === null ? strings.timeline.done : strings.timeline.exitCode(exitCode);
  return exitCode === null ? strings.timeline.failedNoExitCode : strings.timeline.failedExitCode(exitCode);
}

function StepRow({
  record,
  step,
  open,
  onToggle,
  runId,
  branch,
  diffMode,
  fetchStepDiff,
  fetchProof,
  fetchStep,
}: {
  readonly record: RunRecord;
  readonly step: RecordStep;
  readonly open: boolean;
  readonly onToggle: () => void;
  readonly runId: string;
  readonly branch: string;
  readonly diffMode: DiffMode;
  readonly fetchStepDiff: FetchStepDiff;
  readonly fetchProof: FetchProof;
  readonly fetchStep: FetchStep;
}) {
  const toolLabel = step.kind === "report" ? strings.agentPage.reportTool : toolDisplayName(step.tool);

  if (step.kind === "spawn") {
    const child = childFor(record, step.spawned_run_id);
    return (
      <div id={`step-${step.n}`} className={`${stepRowStatic} ${stepCardDeferred}`} data-step={step.n}>
        <span className={rowCellN}>{step.n}</span>
        <span className={rowCellTool}>{toolLabel}</span>
        <span className={rowCellProse}>
          {`${strings.agentPage.started} `}
          {child === undefined ? (
            truncateIdentifier(step.spawned_run_id, { kind: "run", maxLength: 14 })
          ) : (
            <Link to={{ view: "run", runId: child.run_id }} className={link}>
              {headingTextFor(child.title, child.agent_type)}
            </Link>
          )}
        </span>
        <span className={rowCellResult}>{resultText(step)}</span>
        <span className={rowCellTime}>{utcTime(step.at)}</span>
      </div>
    );
  }

  if (step.kind === "report") {
    return (
      <div id={`step-${step.n}`} className={`${stepRowStatic} ${stepCardDeferred}`} data-step={step.n}>
        <span className={rowCellN}>{step.n}</span>
        <span className={rowCellTool}>{toolLabel}</span>
        <span className={rowCellProse}>{strings.agentPage.reportHandedBack}</span>
        <span className={rowCellResult}>{resultText(step)}</span>
        <span className={rowCellTime}>{utcTime(step.at)}</span>
      </div>
    );
  }

  return (
    <div id={`step-${step.n}`} className={`flex flex-col ${stepCardDeferred}`} data-step={step.n} data-witnesses-agree={stepWitnessesAgree(step.witnesses)}>
      <button type="button" onClick={onToggle} aria-expanded={open} className={stepRowButton}>
        <span className={rowCellN}>{step.n}</span>
        <span className={rowCellTool}>{toolLabel}</span>
        <span className="flex min-w-0 flex-grow items-center gap-2">
          <span className={rowCellMain}>{step.summary}</span>
          {step.commit_sha === "" ? null : (
            <span className={rowCommitChip}>
              <CommitIcon />
              {step.commit_sha.slice(0, 7)}
            </span>
          )}
        </span>
        <span className={rowCellResult}>{resultText(step)}</span>
        <span className={rowCellTime}>{utcTime(step.at)}</span>
      </button>
      {open ? (
        <div className={stepRowBody}>
          <StepBody
            record={record}
            step={step}
            runId={runId}
            branch={branch}
            diffMode={diffMode}
            fetchStepDiff={fetchStepDiff}
            fetchProof={fetchProof}
            fetchStep={fetchStep}
          />
        </div>
      ) : null}
    </div>
  );
}

function StepBody({
  record,
  step,
  runId,
  branch,
  diffMode,
  fetchStepDiff,
  fetchProof,
  fetchStep,
}: {
  readonly record: RunRecord;
  readonly step: RecordStep;
  readonly runId: string;
  readonly branch: string;
  readonly diffMode: DiffMode;
  readonly fetchStepDiff: FetchStepDiff;
  readonly fetchProof: FetchProof;
  readonly fetchStep: FetchStep;
}) {
  const [full, setFull] = useState<{ readonly output: string; readonly loading: boolean } | null>(null);
  const output = full !== null && !full.loading ? full.output : step.output;
  const showFull = () => {
    setFull({ output: step.output, loading: true });
    fetchStep(runId, step.n, new AbortController().signal).then(
      (s) => setFull({ output: s.output, loading: false }),
      () => setFull(null),
    );
  };
  const failed = stepFailed(step);
  const agrees = stepWitnessesAgree(step.witnesses);
  const commit = record.commits.find((c) => c.step === step.n);
  const showDiff = step.witnesses.snapshot === "changed";
  // A Write with no snapshot diff shows what it wrote, from its own input,
  // as a new-file preview (#443).
  const written = !showDiff && !failed ? writtenContentOf(record, step) : null;

  return (
    <>
      {!agrees ? <WitnessGrid step={step} /> : null}

      {written !== null ? (
        <WrittenPreview path={written.path} isNew={written.isNew} content={written.content} />
      ) : output !== "" && !(showDiff && FILE_EDIT_TOOLS.has(step.tool) && !failed) ? (
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

      {commit === undefined ? null : <CommitCard commit={commit} branch={branch} repo={record.run.repo} fetchProof={fetchProof} />}
    </>
  );
}

const FILE_EDIT_TOOLS: ReadonlySet<string> = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit"]);

function WitnessGrid({ step }: { readonly step: RecordStep }) {
  const { gateway, snapshot, telemetry } = step.witnesses;
  const gatewayOk = gateway === "present";
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

const WRITTEN_PREVIEW_LINES = 8;

/** The content a Write step wrote, from its own input: the file it named,
 * whether it was new, and the text. Null for any other step. */
function writtenContentOf(
  record: RunRecord,
  step: RecordStep,
): { readonly path: string; readonly isNew: boolean; readonly content: string } | null {
  if (step.tool !== "Write") return null;
  let content: unknown;
  try {
    content = (JSON.parse(step.input) as { content?: unknown }).content;
  } catch {
    return null;
  }
  if (typeof content !== "string") return null;
  const entry = record.written.find((w) => w.step === step.n);
  return { path: entry?.path ?? step.summary, isNew: entry?.status === "A", content };
}

function WrittenPreview({
  path,
  isNew,
  content,
}: {
  readonly path: string;
  readonly isNew: boolean;
  readonly content: string;
}) {
  const lines = content.replace(/\n$/, "").split("\n");
  const shown = lines.slice(0, WRITTEN_PREVIEW_LINES);
  return (
    <div className={diffShell} data-testid="written-preview">
      <div className={diffFileHeader}>
        <span className="text-ink">{path}</span>
        <span>{isNew ? strings.agentPage.newFile : strings.agentPage.writtenFile}</span>
        {lines.length > shown.length ? (
          <span>{strings.agentPage.moreLines(lines.length - shown.length)}</span>
        ) : null}
      </div>
      {shown.map((line, i) => (
        <div key={i} className={`${diffRowUnified} ${diffAddedRow}`}>
          <span className={`${diffLineNoBase} ${diffAddedGutter}`}>{i + 1}</span>
          <span className={`${diffMarkerBase} ${diffAddedMarker}`} aria-label={strings.agentPage.addedLine}>
            {strings.agentPage.addedMarker}
          </span>
          <span className={diffTextBase}>{line}</span>
        </div>
      ))}
    </div>
  );
}
