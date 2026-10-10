// SPDX-License-Identifier: Apache-2.0

/*
 * Pure functions over a RunRecord — nothing here touches the DOM or fetches
 * anything, so every one of them is exercised directly without mounting a
 * component. Kept separate from the components for the same reason
 * run-detail/events.ts is: a view this dense needs one place to audit for
 * "where does this sentence's number come from".
 *
 * Rewritten for #443 (RM-278): the page is now built around one agent — a
 * session or a subagent — rather than a flat family tree, so the functions
 * here read `record.agent`/`record.children`/`record.written` rather than
 * `record.tree`/`record.files`, which this page no longer renders.
 */

import { displayName, isPseudonym } from "../../app/pseudonym";
import { strings } from "./strings";
import type {
  RecordChild,
  RecordStep,
  RecordWitness,
  RecordWitnesses,
  RunRecord,
} from "./types";

const DAY_MS = 24 * 60 * 60 * 1000;

/** The repository's own name, stripped of a leading host segment, for the
 * fact card's "Repository" value — doc 06's mockup shows
 * "Raymalian/innsegl", not "github.com/Raymalian/innsegl". */
export function shortRepo(repo: string): string {
  if (isPseudonym(repo)) return displayName(repo);
  const slash = repo.indexOf("/");
  if (slash === -1) return repo;
  const host = repo.slice(0, slash);
  return host.includes(".") ? repo.slice(slash + 1) : repo;
}

/** How many of the three witnesses (gateway, snapshot, telemetry) agree that
 * a step happened as recorded. "Agree" reads "unchanged" as a legitimate
 * observation, same as "changed" — both are the snapshot witness having
 * something to say; "none" is the snapshot witness having nothing to say,
 * which does not agree any more than "missing" does. */
export function witnessAgreeCount(w: RecordWitnesses): number {
  let n = 0;
  if (w.gateway === "present") n++;
  if (w.snapshot === "changed" || w.snapshot === "unchanged") n++;
  if (w.telemetry === "matched") n++;
  return n;
}

/** How many witnesses were active for this step's run (#438): the gateway
 * always, a snapshot or telemetry witness unless the run never had it. An
 * inactive witness proves nothing by its absence, so it is not counted. */
export function witnessActiveCount(w: RecordWitnesses): number {
  let n = 1;
  if (w.snapshot !== "inactive") n++;
  if (w.telemetry !== "inactive") n++;
  return n;
}

export function stepWitnessesAgree(w: RecordWitnesses): boolean {
  return witnessAgreeCount(w) === witnessActiveCount(w);
}

/** The first step whose witnesses disagree, or undefined when none do — the
 * page-level alert names this step, and the step's own row renders the
 * expanded witness grid only for this one. */
export function firstDisagreeingStep(record: RunRecord): RecordStep | undefined {
  return record.steps.find((step) => !stepWitnessesAgree(step.witnesses));
}

/** The sentence clause naming why a step's witnesses disagree — the
 * mockup's "the gateway relayed a tool call the harness's telemetry never
 * reported", generalised to the other shapes a disagreement can take. */
export function disagreementReason(w: RecordWitnesses): "telemetry-missing" | "gateway-missing" | "snapshot" | "generic" {
  if (w.gateway === "present" && w.telemetry !== "matched") return "telemetry-missing";
  if (w.gateway === "missing") return "gateway-missing";
  if (w.snapshot === "none") return "snapshot";
  return "generic";
}

/** Whether every step of this run's own witnesses are simply not active for
 * it (#443's hook-recorded aside note) — not one disagreement among them,
 * every one of them silent. */
export function everyWitnessInactive(record: RunRecord): boolean {
  if (record.steps.length === 0) return false;
  return record.steps.every((s) => s.witnesses.snapshot === "inactive" && s.witnesses.telemetry === "inactive");
}

/** A bare run id, shortened the same way the mockup's Identity fact card
 * shortens one: the "run-" prefix, its next 8 hex characters, an ellipsis,
 * its last 4 — "run-26c7818c…41ef". Unlike `truncateIdentifier`'s own
 * single-token rule this is deliberately asymmetric, matching the approved
 * board; used only where a run id is shown on its own, not inside a SPIFFE
 * ID. */
export function shortRunId(runId: string): string {
  const match = /^run-([0-9a-f]+)$/.exec(runId);
  const hex = match?.[1];
  if (hex === undefined || hex.length <= 12) return runId;
  return `run-${hex.slice(0, 8)}…${hex.slice(-4)}`;
}

/* ── dates ─────────────────────────────────────────────────────────────── */

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function parse(iso: string): Date | undefined {
  const at = new Date(iso);
  return Number.isNaN(at.getTime()) ? undefined : at;
}

/** "26 Sep" — UTC day and month, no year (doc 06's short-horizon convention:
 * nothing on this page spans a year). */
export function dayMonthUtc(iso: string): string {
  const at = parse(iso);
  if (at === undefined) return "";
  return `${at.getUTCDate()} ${MONTHS[at.getUTCMonth()]}`;
}

/** "07:45" — UTC hour and minute, zero-padded. */
export function hhmmUtc(iso: string): string {
  const at = parse(iso);
  if (at === undefined) return "";
  const h = String(at.getUTCHours()).padStart(2, "0");
  const m = String(at.getUTCMinutes()).padStart(2, "0");
  return `${h}:${m}`;
}

/** "1 Oct 07:45" — the session table's own "Ended" column, for a retired
 * child. */
export function dayMonthTimeUtc(iso: string): string {
  const day = dayMonthUtc(iso);
  return day === "" ? "" : `${day} ${hhmmUtc(iso)}`;
}

/** Whole days between two instants, floored — never negative. */
export function daysBetween(start: Date, end: Date): number {
  return Math.max(0, Math.floor((end.getTime() - start.getTime()) / DAY_MS));
}

/** The status pill's own clause, after the status word: a still-active run
 * states when it started ("since 23 Sep 08:16 UTC"); anything else states
 * the span it ran ("ran 26 Sep 18:00–18:02 UTC"), spelling the end's own day
 * too when the run crossed midnight. */
export function statusRangeText(
  status: string,
  registeredAt: string,
  statusAt: string | null,
  lastStepAt?: string,
): string {
  if (status === "active") {
    return `since ${dayMonthTimeUtc(registeredAt)} UTC`;
  }
  const startDay = dayMonthUtc(registeredAt);
  const startTime = hhmmUtc(registeredAt);
  // A lapsed or abandoned agent was marked so later than it stopped
  // working: its own last step says when it worked until (#443).
  const end = status !== "retired" && lastStepAt !== undefined && lastStepAt !== "" ? lastStepAt : statusAt;
  if (end === null || end === "") return `ran ${startDay} ${startTime} UTC`;
  const endDay = dayMonthUtc(end);
  const endTime = hhmmUtc(end);
  return endDay === startDay
    ? `ran ${startDay} ${startTime}–${endTime} UTC`
    : `ran ${startDay} ${startTime} – ${endDay} ${endTime} UTC`;
}

/** The "Agents it started" table's own "Ended" column: a retired child names
 * when, in full; anything else names its status in that same cell, in
 * lowercase, since the status word already appears capitalised in that
 * child's own page. */
export function endedColumnText(status: string, endedAt: string | null): string {
  if (endedAt === null || endedAt === "") return "";
  return status === "retired" ? dayMonthTimeUtc(endedAt) : `${status} ${dayMonthUtc(endedAt)}`;
}

/** A subagent's own display name: its title when the record has one, else
 * "{agent_type} agent" — used for this agent, an ancestor, a parent and a
 * child alike, wherever the record names a run only by its task. */
export function headingTextFor(title: string, agentType: string): string {
  return title !== "" ? title : strings.header.heading(agentType);
}

/** A tool's own name: an MCP tool's `mcp__<server>__<tool>` shows as
 * `<tool>` (#443). */
export function toolDisplayName(tool: string): string {
  if (!tool.startsWith("mcp__")) return tool;
  const last = tool.lastIndexOf("__");
  return last > 3 ? tool.slice(last + 2) : tool;
}

/** A count as the page prints it everywhere: 3,103 (#443). */
export function countText(n: number): string {
  return n.toLocaleString("en-US");
}

/* ── fact cards ────────────────────────────────────────────────────────── */

function countWord(n: number, singular: string, plural: string): string {
  return `${n} ${n === 1 ? singular : plural}`;
}

/** The subagent fact card's own "Did" value: "15 steps · 2 files written ·
 * 0 commits · no subagents". */
export function subagentDidText(record: RunRecord): string {
  const steps = countWord(record.steps.length, "step", "steps");
  const files = `${countWord(record.written.length, "file", "files")} written`;
  const commits = countWord(record.commits.length, "commit", "commits");
  const subagents = record.children.length === 0 ? "no subagents" : countWord(record.children.length, "subagent", "subagents");
  return [steps, files, commits, subagents].join(" · ");
}

/** The session fact card's own "Did" value: "2,972 steps over 8 days". */
export function sessionDidText(record: RunRecord, now: Date): string {
  const steps = record.steps.length.toLocaleString("en-US");
  const days = daysBetween(new Date(record.run.registered_at), now);
  return `${steps} steps over ${countWord(days, "day", "days")}`;
}

/** "73 subagents · 0 running now". */
export function sessionStartedText(record: RunRecord): string {
  const running = record.children.filter((c) => c.status === "active").length;
  return `${countWord(record.children.length, "subagent", "subagents")} · ${running} running now`;
}

/** "40 signed commits". */
export function sessionCommittedText(record: RunRecord): string {
  return `${countWord(record.commits.length, "signed commit", "signed commits")}`;
}

/* ── asked / reported ─────────────────────────────────────────────────── */

export interface LinedText {
  readonly lines: readonly string[];
  readonly total: number;
}

/** A message's text split on literal newlines, for the "Asked to" card's own
 * "first 3 lines, Show all N lines" disclosure. */
export function linesOf(text: string): LinedText {
  const lines = text.split("\n");
  // Only lines that carry text are counted: "Show all N lines" names what
  // the reader will get, not the blank lines between paragraphs (#443).
  return { lines, total: lines.filter((line) => line.trim() !== "").length };
}

export type InlineToken =
  | { readonly kind: "text"; readonly value: string }
  | { readonly kind: "bold"; readonly value: string }
  | { readonly kind: "code"; readonly value: string };

/**
 * The only two markdown spans "Reported back" renders — `**bold**` and
 * `` `code` `` — and nothing else: no links, no italics, no lists. A regex
 * alternation over the two delimiters, left to right, non-overlapping; a lone
 * unmatched `*` or backtick is plain text.
 */
export function parseInlineMarkdown(text: string): InlineToken[] {
  const tokens: InlineToken[] = [];
  const pattern = /\*\*([^*]+)\*\*|`([^`]+)`/g;
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    if (match.index > last) tokens.push({ kind: "text", value: text.slice(last, match.index) });
    if (match[1] !== undefined) tokens.push({ kind: "bold", value: match[1] });
    else if (match[2] !== undefined) tokens.push({ kind: "code", value: match[2] });
    last = match.index + match[0].length;
  }
  if (last < text.length) tokens.push({ kind: "text", value: text.slice(last) });
  return tokens;
}

/* ── step rows: what opens by default, and what collapses ────────────────── */

export function stepFailed(step: RecordStep): boolean {
  return step.outcome.kind !== "ok";
}

/** A step this run wrote a file in: named by the run-level `written` list
 * (#443), or — for a run recorded before that field existed — by its own
 * snapshot witness having seen the tree change. */
export function stepWroteFile(record: RunRecord, step: RecordStep): boolean {
  return record.written.some((w) => w.step === step.n) || step.witnesses.snapshot === "changed";
}

export function stepHasCommit(step: RecordStep): boolean {
  return step.commit_sha !== "";
}

/** Open by default (per #443's board): a failed step, a step that wrote a
 * file, a step that made a commit, or a step whose witnesses disagree — the
 * last so the page-level disagreement banner's link actually lands on
 * visible evidence rather than a row the reader must also click open. */
export function stepOpensByDefault(record: RunRecord, step: RecordStep): boolean {
  return (
    stepFailed(step) ||
    stepWroteFile(record, step) ||
    stepHasCommit(step) ||
    !stepWitnessesAgree(step.witnesses)
  );
}

export type StepPlanItem =
  | { readonly kind: "row"; readonly step: RecordStep; readonly open: boolean }
  | { readonly kind: "group"; readonly steps: readonly RecordStep[] };

/**
 * The "What it ran" table's own row plan, in the order `steps` is already
 * given. A run of three or more consecutive ordinary tool-call rows (none of
 * them open by default) collapses into one disclosure row; everything else —
 * a spawn, a report, anything open by default — stays its own row.
 * `allOpen` (the subagent page's "With output" toggle) disables both the
 * collapsing and the default-closed state: every row shows, open.
 */
const VISIBLE_BEFORE_GROUP = 3;
const MIN_GROUP = 2;

export function planStepRows(record: RunRecord, steps: readonly RecordStep[], allOpen = false): StepPlanItem[] {
  const items: StepPlanItem[] = [];
  let buffer: RecordStep[] = [];

  // The first rows of a run of ordinary steps stay visible; the rest
  // collapse, but never fewer than two into a group (#443).
  const flush = () => {
    if (buffer.length === 0) return;
    const shown = buffer.length - VISIBLE_BEFORE_GROUP >= MIN_GROUP ? buffer.slice(0, VISIBLE_BEFORE_GROUP) : buffer;
    for (const step of shown) items.push({ kind: "row", step, open: false });
    if (shown.length < buffer.length) items.push({ kind: "group", steps: buffer.slice(shown.length) });
    buffer = [];
  };

  for (const step of steps) {
    const auto = stepOpensByDefault(record, step);
    if (!allOpen && step.kind === "tool" && !auto) {
      buffer.push(step);
      continue;
    }
    flush();
    items.push({ kind: "row", step, open: allOpen || auto });
  }
  flush();
  return items;
}

/** A collapsed group's own caption: "Steps 4–9 · 6 more commands,
 * 18:01:04–18:01:27 · show". */
export function groupRange(steps: readonly RecordStep[]): { readonly a: number; readonly b: number; readonly atA: string; readonly atB: string } {
  let a = steps[0] as RecordStep;
  let b = steps[0] as RecordStep;
  for (const step of steps) {
    if (step.n < a.n) a = step;
    if (step.n > b.n) b = step;
  }
  return { a: a.n, b: b.n, atA: a.at, atB: b.at };
}

export type SessionStepFilter = "all" | "spawned" | "commits" | "failed";

export function filterSteps(steps: readonly RecordStep[], filter: SessionStepFilter): RecordStep[] {
  switch (filter) {
    case "spawned":
      return steps.filter((s) => s.kind === "spawn");
    case "commits":
      return steps.filter((s) => stepHasCommit(s));
    case "failed":
      return steps.filter((s) => stepFailed(s));
    default:
      return [...steps];
  }
}

export function newestFirst(steps: readonly RecordStep[]): RecordStep[] {
  return [...steps].sort((a, b) => b.n - a.n);
}

/** The child record a spawn/report step's own run id names, if the parent's
 * record lists it among its children (#443: direct children only). */
export function childFor(record: RunRecord, runId: string): RecordChild | undefined {
  return record.children.find((c) => c.run_id === runId);
}

/* ── witnesses ─────────────────────────────────────────────────────────── */

export function allWitnessesAgree(witness: RecordWitness): boolean {
  return witness.disagree === 0 && witness.unchecked === 0 && witness.steps > 0;
}
