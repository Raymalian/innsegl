// SPDX-License-Identifier: Apache-2.0

/*
 * The left aside's "Files changed" panel — Main.dc.html: a tree grouped by
 * the repository's own folder, each file with its A/M/D/R status, a
 * subagent-authorship note where one applies, and the legend beneath it.
 *
 * ── WHY THE STATUS LETTER AND THE +/- COUNT ARE NEUTRAL, NOT GREEN/RED ────
 *
 * The mockup's own hex for "A" and its "+1" is the same green
 * `--innsegl-palette-verification-700`/`-100` the three-check panel spends on
 * a live verification passing. doc 06 §5.3 reserves that green for exactly
 * one claim ("nothing else is ever green") and names one exception — "inside
 * a diff view, and only there" — for the soft added/removed backgrounds the
 * step cards' own diff renderer uses below. This panel is not a diff view; it
 * is a file list, and doc 06 §8's anti-pattern 3 ("green used for anything
 * other than cryptographic verification") is exactly what painting this
 * green would be. Rendered in neutral ink instead, and reported as a
 * deliberate difference from the artboard's colour.
 */

import { isBySubagent, isNeverCommitted, repoFolderName, writtenAndRevertedAt } from "./derive";
import { FolderIcon } from "./icons";
import { strings } from "./strings";
import {
  fileCount,
  fileName,
  fileRow,
  fileStatusLetter,
  fileSubNote,
  filesFolderRow,
  legendRow,
  panel,
  panelFooter,
  panelHeading,
  panelHeadingRow,
} from "./styles";
import type { FileStatus, RecordFile } from "./types";

export interface FilesChangedProps {
  readonly files: readonly RecordFile[];
  readonly repo: string;
}

export function FilesChanged({ files, repo }: FilesChangedProps) {
  return (
    <section className={panel} aria-labelledby="files-changed-heading">
      <div className={panelHeadingRow}>
        <h2 id="files-changed-heading" className={panelHeading}>
          {strings.files.heading}
        </h2>
        <span className="text-micro text-ink-secondary">{strings.files.scopeWholeRun}</span>
      </div>
      <div className="flex flex-col gap-0.5 p-2">
        <div className={filesFolderRow}>
          <FolderIcon />
          <span>
            {repoFolderName(repo)}
            {strings.punctuation.slash}
          </span>
        </div>
        {files.map((file) => (
          <FileRow key={file.path} file={file} />
        ))}
      </div>
      <div className={panelFooter}>
        <span className={legendRow}>
          <span>{strings.files.legend.added}</span>
          <span>{strings.files.legend.modified}</span>
          <span>{strings.files.legend.deleted}</span>
          <span>{strings.files.legend.reverted}</span>
        </span>
      </div>
    </section>
  );
}

function FileRow({ file }: { readonly file: RecordFile }) {
  const revert = writtenAndRevertedAt(file);
  return (
    <div className="flex flex-col">
      <div className={fileRow}>
        <span className={fileStatusLetter} aria-label={strings.files.statusLabel[file.status as FileStatus]}>
          {file.status}
        </span>
        <span className={fileName}>{file.path}</span>
        <span className={fileCount}>
          {file.additions > 0 ? `+${file.additions}` : null}
          {file.additions > 0 && file.deletions > 0 ? " " : null}
          {file.deletions > 0 ? `−${file.deletions}` : null}
        </span>
      </div>
      {isBySubagent(file) ? (
        <p className={fileSubNote}>{strings.files.writtenBySubagent(file.path)}</p>
      ) : null}
      {isNeverCommitted(file) && revert !== undefined ? (
        <p className={fileSubNote}>{strings.files.neverCommitted(revert.written, revert.reverted)}</p>
      ) : null}
    </div>
  );
}
