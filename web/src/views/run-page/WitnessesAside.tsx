// SPDX-License-Identifier: Apache-2.0

/*
 * The aside's "Witnesses" panel (#443, RM-278) — Agent.dc.html. Shown only
 * for a subagent (the session board carries no such panel).
 *
 * A hook-recorded run — every step's snapshot and telemetry witness
 * "inactive", because it ran before the gateway existed — gets its own
 * sentence rather than a summary that would otherwise read as a disagreement
 * found and dismissed; everything else gets the same roll-up the old header
 * fact card used to state.
 */

import { allWitnessesAgree, everyWitnessInactive } from "./derive";
import { strings } from "./strings";
import { panel, panelHeading, panelHeadingRow, panelPad, witnessesNote } from "./styles";
import type { RecordWitness, RunRecord } from "./types";

export interface WitnessesAsideProps {
  readonly record: RunRecord;
}

export function WitnessesAside({ record }: WitnessesAsideProps) {
  return (
    <section className={panel} aria-labelledby="witnesses-aside-heading">
      <div className={panelHeadingRow}>
        <h2 id="witnesses-aside-heading" className={panelHeading}>
          {strings.agentPage.witnessesHeading}
        </h2>
      </div>
      <div className={panelPad}>
        <span className={witnessesNote}>{summaryText(record)}</span>
      </div>
    </section>
  );
}

function summaryText(record: RunRecord): string {
  if (everyWitnessInactive(record)) return strings.agentPage.hookRecordedWitnesses;
  return witnessSummary(record.witness);
}

function witnessSummary(witness: RecordWitness): string {
  if (witness.steps === 0) return strings.agentPage.witnessesNoSteps;
  if (witness.disagree > 0) return strings.agentPage.witnessesDisagreeSummary(witness.disagree, witness.steps);
  if (allWitnessesAgree(witness)) return strings.agentPage.witnessesAgreeAll(witness.steps);
  return strings.agentPage.witnessesPartlyChecked(witness.agree, witness.steps, witness.unchecked);
}
