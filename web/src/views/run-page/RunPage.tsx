// SPDX-License-Identifier: Apache-2.0

/*
 * doc 06 §3.3's run page (E19, #395-397) — rebuilt around one agent at a time
 * for #443 (RM-278): a session or a subagent, by its own task, with its
 * lineage, rather than the whole family as a flat tree. `record.agent.role`
 * chooses between the subagent board (Agent.dc.html: Asked to / Reported
 * back, files it wrote, witnesses) and the session board (Session.dc.html:
 * the agents it started, its commits' one-commit identities).
 *
 * The four read states doc 06 §4.6/P2 require: loading with a bound, missing
 * (a run this ledger does not hold), failed (the ledger did not answer), and
 * loaded. Mirrors run-detail/RunDetailView.tsx's own shape for the same
 * reason that file states it: `LoadingState` owns the timeout so a caller
 * cannot forget one, and "not found" and "failed" are different facts (P2)
 * rather than the same blank screen.
 *
 * The diff toggle's choice lives in the URL (doc 06 §7): `?diff=unified|side`
 * on this same route, read and written through `router.ts`'s own `navigate`/
 * `usePath` rather than through a second piece of state this page could
 * disagree with the address bar about.
 */

import { useCallback, useEffect, useState } from "react";

import { AlertBanner } from "../../components/common/AlertBanner";
import type { Alert } from "../../components/common/AlertBanner";
import { EmptyState } from "../../components/common/EmptyState";
import { ErrorState } from "../../components/common/ErrorState";
import { LoadingState } from "../../components/common/LoadingState";
import { StalenessIndicator } from "../../components/common/StalenessIndicator";
import { navigate, usePath } from "../../app/router";
import type { Route } from "../../app/routes";
import { AgentsStarted } from "./AgentsStarted";
import { AskedTo, ReportedBack } from "./AskedReported";
import { CommitsAside } from "./CommitsAside";
import type { DiffMode } from "./Diff";
import { FilesWritten } from "./FilesWritten";
import { Header } from "./Header";
import { RunRecordNotFound, fetchProof, fetchRunRecord, fetchStep, fetchStepDiff } from "./api";
import type { FetchProof, FetchRunRecord, FetchStep, FetchStepDiff } from "./api";
import { disagreementReason, firstDisagreeingStep } from "./derive";
import { StepsSection } from "./StepsSection";
import { strings } from "./strings";
import { aside, columns, mainColumn, viewShell } from "./styles";
import type { RecordStep, RunRecord } from "./types";
import { WhereItSits } from "./WhereItSits";
import { WitnessesAside } from "./WitnessesAside";

export interface RunPageProps {
  readonly route: Route;
  readonly fetchRunRecord?: FetchRunRecord;
  readonly fetchStepDiff?: FetchStepDiff;
  readonly fetchProof?: FetchProof;
  readonly fetchStep?: FetchStep;
  /** Injected so a render is deterministic, exactly as the run-detail view's
   * own `now` prop is. */
  readonly now?: Date;
}

type Read =
  | { readonly state: "loading" }
  | { readonly state: "loaded"; readonly record: RunRecord }
  | { readonly state: "missing" }
  | { readonly state: "failed"; readonly error: string };

function diffModeFromPath(path: string): DiffMode {
  const query = path.split("?")[1] ?? "";
  return new URLSearchParams(query).get("diff") === "side" ? "side" : "unified";
}

export function RunPage({
  route,
  fetchRunRecord: read = fetchRunRecord,
  fetchStepDiff: readDiff = fetchStepDiff,
  fetchProof: readProof = fetchProof,
  fetchStep: readStep = fetchStep,
  now,
}: RunPageProps) {
  const runId = route.view === "run" ? route.runId : "";
  const [attempt, setAttempt] = useState(0);
  const [result, setResult] = useState<Read>({ state: "loading" });
  const clock = now ?? new Date();
  const path = usePath();
  const diffMode = diffModeFromPath(path);

  useEffect(() => {
    const controller = new AbortController();
    let live = true;
    setResult({ state: "loading" });
    read(runId, controller.signal).then(
      (record) => {
        if (live) setResult({ state: "loaded", record });
      },
      (cause: unknown) => {
        if (!live) return;
        if (cause instanceof RunRecordNotFound) {
          setResult({ state: "missing" });
          return;
        }
        setResult({ state: "failed", error: cause instanceof Error ? cause.message : String(cause) });
      },
    );
    return () => {
      live = false;
      controller.abort();
    };
  }, [read, runId, attempt]);

  const retry = useCallback(() => setAttempt((n) => n + 1), []);

  const setDiffMode = useCallback(
    (mode: DiffMode) => {
      const [base] = path.split("?");
      const params = new URLSearchParams(path.split("?")[1] ?? "");
      if (mode === "unified") {
        params.delete("diff");
      } else {
        params.set("diff", mode);
      }
      const query = params.toString();
      navigate(`${base}${query === "" ? "" : `?${query}`}`, { replace: true });
    },
    [path],
  );

  return (
    <div className={viewShell}>
      <StalenessIndicator />
      {result.state === "loading" ? (
        <LoadingState what={strings.loading.record} onRetry={retry} />
      ) : null}
      {result.state === "missing" ? (
        <EmptyState title={strings.empty.title} detail={strings.empty.detail} />
      ) : null}
      {result.state === "failed" ? (
        <ErrorState title={strings.error.title} detail={`${strings.error.detail} ${result.error}`} onRetry={retry} />
      ) : null}
      {result.state === "loaded" ? (
        <Loaded
          record={result.record}
          now={clock}
          diffMode={diffMode}
          onDiffModeChange={setDiffMode}
          fetchStepDiff={readDiff}
          fetchProof={readProof}
          fetchStep={readStep}
        />
      ) : null}
    </div>
  );
}

function Loaded({
  record,
  now,
  diffMode,
  onDiffModeChange,
  fetchStepDiff: readDiff,
  fetchProof: readProof,
  fetchStep: readStep,
}: {
  readonly record: RunRecord;
  readonly now: Date;
  readonly diffMode: DiffMode;
  readonly onDiffModeChange: (mode: DiffMode) => void;
  readonly fetchStepDiff: FetchStepDiff;
  readonly fetchProof: FetchProof;
  readonly fetchStep: FetchStep;
}) {
  const disagreeing = firstDisagreeingStep(record);
  const role = record.agent.role;

  return (
    <>
      {disagreeing === undefined ? null : <DisagreementBanner step={disagreeing} />}

      <Header record={record} now={now} />

      <div className={columns}>
        <main className={mainColumn}>
          {role === "subagent" ? (
            <>
              <AskedTo asked={record.agent.asked} />
              <ReportedBack reported={record.agent.reported} />
            </>
          ) : (
            <AgentsStarted children={record.children} />
          )}

          <StepsSection
            record={record}
            role={role}
            runId={record.run.run_id}
            branch={record.run.branch}
            diffMode={diffMode}
            onDiffModeChange={onDiffModeChange}
            fetchStepDiff={readDiff}
            fetchProof={readProof}
            fetchStep={readStep}
          />
        </main>

        <aside className={aside}>
          <WhereItSits record={record} />
          {role === "subagent" ? <FilesWritten written={record.written} /> : null}
          <CommitsAside commits={record.commits} runId={record.run.run_id} role={role} />
          {role === "subagent" ? <WitnessesAside record={record} /> : null}
        </aside>
      </div>
    </>
  );
}

function DisagreementBanner({ step }: { readonly step: RecordStep }) {
  const reason = disagreementReason(step.witnesses);
  const reasonText =
    reason === "telemetry-missing"
      ? strings.witnessDisagreement.reasonTelemetryMissing
      : reason === "gateway-missing"
        ? strings.witnessDisagreement.reasonGatewayMissing
        : reason === "snapshot"
          ? strings.witnessDisagreement.reasonSnapshot
          : strings.witnessDisagreement.reasonGeneric;

  const alert: Alert = {
    id: `witness-disagreement-step-${step.n}`,
    kind: "integrity",
    title: strings.witnessDisagreement.bannerTitle(step.n, reasonText),
    detail:
      reason === "telemetry-missing"
        ? strings.witnessDisagreement.detailTelemetryMissing(step.tool_use_id)
        : strings.witnessDisagreement.detailGeneric(step.tool_use_id),
    evidenceHref: `#step-${step.n}`,
  };
  return <AlertBanner alerts={[alert]} />;
}
