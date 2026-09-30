// SPDX-License-Identifier: Apache-2.0

/*
 * The inline diff renderer — Main.dc.html's single-file addition, and
 * States.dc.html's side-by-side modification. doc 06 §5.3's named exception:
 * soft green/red backgrounds on code lines, always with a +/− marker and line
 * numbers, never a solid fill, an icon or a badge — so a diff and a
 * verification result can never be read as each other on the same page.
 *
 * Unified and side-by-side read the SAME hunks; the toggle changes only how
 * this component lays them out, which is what keeps the two views from ever
 * disagreeing about what changed.
 */

import { strings } from "./strings";
import {
  diffAddedGutter,
  diffAddedMarker,
  diffAddedRow,
  diffFileHeader,
  diffLineNoBase,
  diffMarkerBase,
  diffRemovedGutter,
  diffRemovedMarker,
  diffRemovedRow,
  diffRowUnified,
  diffShell,
  diffTextBase,
  sideBySideCol,
  sideBySideGrid,
} from "./styles";
import type { DiffFile, DiffLine, FileStatus, StepDiff } from "./types";

export type DiffMode = "unified" | "side";

const STATUS_LABEL: Record<FileStatus, string> = {
  A: strings.timeline.newFile,
  M: strings.timeline.modifiedFile,
  D: strings.timeline.deletedFile,
  R: strings.timeline.revertedFile,
};

export interface DiffProps {
  readonly diff: StepDiff;
  readonly mode: DiffMode;
  /** The step's own tree transition (Main.dc.html's "tree dd57973 → a41f0e2"),
   * shown on a NEW file's header in place of a +/- count — a new file has
   * nothing to count deletions against, and the tree hash is what the mockup
   * shows there instead. Undefined for a caller that has none to show. */
  readonly treeBefore?: string;
  readonly treeAfter?: string;
}

export function Diff({ diff, mode, treeBefore, treeAfter }: DiffProps) {
  return (
    <>
      {diff.files.map((file) => (
        <DiffFileBlock key={file.path} file={file} mode={mode} treeBefore={treeBefore} treeAfter={treeAfter} />
      ))}
    </>
  );
}

function DiffFileBlock({
  file,
  mode,
  treeBefore,
  treeAfter,
}: {
  readonly file: DiffFile;
  readonly mode: DiffMode;
  readonly treeBefore?: string;
  readonly treeAfter?: string;
}) {
  const additions = file.hunks.flatMap((h) => h.lines).filter((l) => l.kind === "add").length;
  const deletions = file.hunks.flatMap((h) => h.lines).filter((l) => l.kind === "del").length;
  const showTree = file.status === "A" && treeBefore !== undefined && treeAfter !== undefined;

  if (file.binary) {
    return (
      <div className={diffShell}>
        <div className={diffFileHeader}>
          <span>{file.path}</span>
          <span>{strings.diff.binary}</span>
        </div>
      </div>
    );
  }

  return (
    <div className={diffShell} data-diff-file={file.path} data-diff-mode={mode}>
      <div className={diffFileHeader}>
        <span>{file.path}</span>
        <span>
          {STATUS_LABEL[file.status]}
          {mode === "side" ? `${strings.punctuation.middot}${strings.timeline.sideBySide.toLowerCase()}` : ""}
        </span>
        <span className="flex-grow" />
        {showTree ? (
          <span className="text-ink-secondary">{strings.timeline.treeChange(shortHash(treeBefore), shortHash(treeAfter))}</span>
        ) : (
          <>
            {additions > 0 ? <span className="text-diff-added-marker">{`+${additions}`}</span> : null}
            {deletions > 0 ? <span className="text-diff-removed-marker">{`−${deletions}`}</span> : null}
          </>
        )}
      </div>
      {file.hunks.map((hunk, index) =>
        mode === "unified" ? (
          <UnifiedHunk key={index} lines={hunk.lines} />
        ) : (
          <SideBySideHunk key={index} lines={hunk.lines} />
        ),
      )}
    </div>
  );
}

function UnifiedHunk({ lines }: { readonly lines: readonly DiffLine[] }) {
  return (
    <div>
      {lines.map((line, index) => (
        <UnifiedRow key={index} line={line} />
      ))}
    </div>
  );
}

function UnifiedRow({ line }: { readonly line: DiffLine }) {
  const rowTone = line.kind === "add" ? diffAddedRow : line.kind === "del" ? diffRemovedRow : "";
  const gutterTone = line.kind === "add" ? diffAddedGutter : line.kind === "del" ? diffRemovedGutter : "bg-sunken";
  const markerTone = line.kind === "add" ? diffAddedMarker : line.kind === "del" ? diffRemovedMarker : "";
  const marker = line.kind === "add" ? "+" : line.kind === "del" ? "−" : "";

  return (
    <div className={`${diffRowUnified} ${rowTone}`}>
      <span className={`${diffLineNoBase} ${gutterTone}`}>{line.kind === "add" ? "" : line.old_no || ""}</span>
      <span className={`${diffLineNoBase} ${gutterTone}`}>{line.kind === "del" ? "" : line.new_no || ""}</span>
      <span className={`${diffMarkerBase} ${markerTone}`} aria-hidden="true">
        {marker}
      </span>
      <span className={diffTextBase}>{line.text}</span>
    </div>
  );
}

interface Paired {
  readonly left?: DiffLine;
  readonly right?: DiffLine;
}

/** Group a hunk's lines into context and matched del/add runs, then pair each
 * run positionally — a context line sits in both columns at once, and a run
 * of deletions is paired against the run of additions that follows it,
 * padding whichever side is shorter with a blank row so the two columns stay
 * the same height (States.dc.html's own layout). */
function pairForSideBySide(lines: readonly DiffLine[]): readonly Paired[] {
  const pairs: Paired[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i] as DiffLine;
    if (line.kind === "context") {
      pairs.push({ left: line, right: line });
      i++;
      continue;
    }
    const dels: DiffLine[] = [];
    while (i < lines.length && (lines[i] as DiffLine).kind === "del") {
      dels.push(lines[i] as DiffLine);
      i++;
    }
    const adds: DiffLine[] = [];
    while (i < lines.length && (lines[i] as DiffLine).kind === "add") {
      adds.push(lines[i] as DiffLine);
      i++;
    }
    const height = Math.max(dels.length, adds.length);
    for (let row = 0; row < height; row++) {
      pairs.push({ left: dels[row], right: adds[row] });
    }
  }
  return pairs;
}

function SideBySideHunk({ lines }: { readonly lines: readonly DiffLine[] }) {
  const pairs = pairForSideBySide(lines);
  return (
    <div className={sideBySideGrid}>
      <div className={sideBySideCol}>
        {pairs.map((pair, index) => (
          <SideRow key={index} line={pair.left} side="old" />
        ))}
      </div>
      <div className={sideBySideCol}>
        {pairs.map((pair, index) => (
          <SideRow key={index} line={pair.right} side="new" />
        ))}
      </div>
    </div>
  );
}

function shortHash(hash: string): string {
  return hash.slice(0, 7);
}

function SideRow({ line, side }: { readonly line: DiffLine | undefined; readonly side: "old" | "new" }) {
  if (line === undefined) {
    return (
      <div className={`${diffRowUnified} bg-sunken`}>
        <span className={diffLineNoBase} />
        <span className={diffTextBase}> </span>
      </div>
    );
  }
  const rowTone = line.kind === "add" ? diffAddedRow : line.kind === "del" ? diffRemovedRow : "";
  const gutterTone = line.kind === "add" ? diffAddedGutter : line.kind === "del" ? diffRemovedGutter : "bg-sunken";
  const markerTone = line.kind === "add" ? diffAddedMarker : line.kind === "del" ? diffRemovedMarker : "";
  const marker = line.kind === "add" ? "+" : line.kind === "del" ? "−" : "";
  const lineNo = side === "old" ? line.old_no : line.new_no;

  return (
    <div className={`${diffRowUnified} ${rowTone}`}>
      <span className={`${diffLineNoBase} ${gutterTone}`}>{lineNo || ""}</span>
      <span className={`${diffMarkerBase} ${markerTone}`} aria-hidden="true">
        {marker}
      </span>
      <span className={diffTextBase}>{line.text}</span>
    </div>
  );
}
