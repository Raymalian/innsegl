// SPDX-License-Identifier: Apache-2.0

/*
 * The scenario registry the browser suite drives — RM-049 (#57).
 *
 * Every fixture below is imported from web/src's own fixtures
 * (components/verification/fixtures.ts), never reinvented here: a harness
 * rendering a shape the real components have never been tested against would
 * prove nothing about them. `web/src/**` is untouched by this issue; this
 * file only imports from it, the way any test in the repository does.
 *
 * `?scenario=<name>` selects what mounts. An unknown or missing scenario name
 * renders nothing recognisable on purpose — `data-harness-unknown` — so a
 * typo in a spec fails loudly (an assertion looking for the real content
 * finds this instead) rather than silently screenshotting a blank page.
 */

import type { ReactElement } from "react";

import { AlertBanner } from "../../src/components/common/AlertBanner";
import type { Alert } from "../../src/components/common/AlertBanner";
import { IdentifierChip } from "../../src/components/common/IdentifierChip";
import { VerificationPanel } from "../../src/components/verification";
import type { Liveness } from "../../src/components/verification";
import {
  failedProof,
  forgedTrailerProof,
  unavailableProof,
  verifiedProof,
} from "../../src/components/verification/fixtures";

/** Every fixture proof in this file is presented as the result of a check
 * that just ran — matching the `VerificationPanel` doc comment's point that a
 * caller with nothing to say about liveness has a live proof (internal/api's
 * Prover holds no cache). The three tri-states are a property of the CHECKS,
 * not of liveness, which is exactly what FE-001 needs held constant. */
const LIVE: Liveness = { source: "live" };

const INTEGRITY_ALERT: Alert = {
  id: "harness-integrity-alert",
  kind: "integrity",
  title: "Chain verification failed",
  detail: "Segment 46's hash chain does not link to segment 45.",
  evidenceHref: "#evidence",
  evidenceLabel: "View evidence",
};

const DEGRADED_ALERT: Alert = {
  id: "harness-degraded-alert",
  kind: "degraded",
  title: "Anchoring lag exceeds the configured bound",
  detail: "Segment 46 sealed 47 min ago and has not reached Rekor.",
  evidenceHref: "#evidence",
  evidenceLabel: "View evidence",
};

/** Long enough that DEFAULT_MAX_LENGTH (44) truncates it, and long enough
 * again that a much smaller maxLength (below) truncates it harder — the two
 * scenarios FE-091 (truncated identifiers expose their full value to AT)
 * needs: one representative width, and one aggressively narrow one. */
const LONG_SPIFFE_ID = "spiffe://innsegl.dev/agent/fix-ci/task-1481/run-7f3a2c9d8e1b4a6f";

const SCENARIOS: Record<string, () => ReactElement> = {
  "panel-verified": () => (
    <VerificationPanel id="panel" proof={verifiedProof()} liveness={LIVE} />
  ),
  "panel-failed": () => (
    <VerificationPanel id="panel" proof={failedProof()} liveness={LIVE} />
  ),
  "panel-unavailable": () => (
    <VerificationPanel id="panel" proof={unavailableProof()} liveness={LIVE} />
  ),
  "panel-mismatch": () => (
    <VerificationPanel id="panel" proof={forgedTrailerProof()} liveness={LIVE} />
  ),
  "alert-integrity": () => <AlertBanner alerts={[INTEGRITY_ALERT]} />,
  "alert-degraded": () => <AlertBanner alerts={[DEGRADED_ALERT]} />,
  "alert-both": () => <AlertBanner alerts={[INTEGRITY_ALERT, DEGRADED_ALERT]} />,
  "identifier-chip": () => <IdentifierChip value={LONG_SPIFFE_ID} kind="spiffe" />,
  "identifier-chip-narrow": () => (
    <IdentifierChip value={LONG_SPIFFE_ID} kind="spiffe" maxLength={20} />
  ),
};

function scenarioName(): string {
  return new URLSearchParams(window.location.search).get("scenario") ?? "";
}

export function Harness() {
  const name = scenarioName();
  const Render = SCENARIOS[name];
  return (
    <div
      data-harness-root
      className="min-h-screen bg-page p-6 font-sans text-body text-ink"
    >
      {Render === undefined ? (
        <p data-harness-unknown>{`innsegl test harness: unknown scenario "${name}"`}</p>
      ) : (
        <Render />
      )}
    </div>
  );
}
