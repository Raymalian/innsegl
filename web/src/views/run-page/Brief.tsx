// SPDX-License-Identifier: Apache-2.0

/*
 * The main column's "Brief" card — Main.dc.html: the first message this
 * agent received, with its keyed digest in the caption (doc 06 P1 — the
 * evidence sits beside the claim it backs).
 */

import { strings } from "./strings";
import { briefBody, briefCaption, briefHeadRow, panel, panelHeading } from "./styles";
import type { RecordMessage } from "./types";

export function Brief({ brief }: { readonly brief: RecordMessage }) {
  return (
    <section className={`${panel} p-4`} aria-labelledby="brief-heading">
      <div className={briefHeadRow}>
        <h2 id="brief-heading" className={panelHeading}>
          {strings.brief.heading}
        </h2>
        <span className={briefCaption}>{strings.brief.caption(brief.digest)}</span>
      </div>
      <p className={briefBody}>{brief.text}</p>
    </section>
  );
}
