// SPDX-License-Identifier: Apache-2.0

/*
 * The aside's "Files it wrote" panel (#443, RM-278) — Agent.dc.html: every
 * file this run's own steps wrote (`record.written`), each with its A/M/W
 * badge, path, and the step that wrote it, linking to that step's row.
 * Replaces the old "Files changed" panel, which showed the whole run's tree
 * — including a subagent's own authorship note — rather than just the files
 * this one run itself touched.
 */

import { strings } from "./strings";
import { fileStatusLetter, panel, panelHeading, panelHeadingRow, writtenPath, writtenRow, writtenStep } from "./styles";
import type { RecordWrite } from "./types";

export interface FilesWrittenProps {
  readonly written: readonly RecordWrite[];
}

export function FilesWritten({ written }: FilesWrittenProps) {
  return (
    <section className={panel} aria-labelledby="files-written-heading">
      <div className={panelHeadingRow}>
        <h2 id="files-written-heading" className={panelHeading}>
          {strings.agentPage.filesItWrote}
        </h2>
      </div>
      <div className="flex flex-col gap-0.5 p-2">
        {written.map((file) => (
          <a key={`${file.path}-${file.step}`} href={`#step-${file.step}`} className={writtenRow}>
            <span className={statusTone(file.status)} aria-label={strings.files.statusLabel[file.status]}>
              {file.status}
            </span>
            <span className={writtenPath}>{file.path}</span>
            <span className={writtenStep}>{strings.agentPage.stepN(file.step)}</span>
          </a>
        ))}
      </div>
    </section>
  );
}

function statusTone(status: RecordWrite["status"]): string {
  return status === "A" ? fileStatusLetter.added : fileStatusLetter.neutral;
}
