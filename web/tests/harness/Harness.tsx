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
 * scenarios FE-101 (truncated identifiers expose their full value to AT)
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

/*
 * ── PROBES: the deliberately defective scenarios ────────────────────────────
 *
 * A gate nobody has watched refuse something is a gate nobody has tested. This
 * project has already shipped one assertion that could not fail — a test that
 * stripped `class` and `style` from markup while leaving a `data-*` attribute
 * in place — and it was caught by mutation, not by review.
 *
 * Each entry below plants ONE known defect and `self-check/detectors.pw.ts`
 * asserts the corresponding detector reports it. They are a separate map from
 * `SCENARIOS` on purpose: every gating spec iterates an explicit list of real
 * scenarios or the six real views, and `detectors.pw.ts` asserts the two maps
 * are disjoint, so a probe cannot drift into a gated run and turn a green
 * suite red for the wrong reason.
 *
 * Nothing here imports from web/src's colour layer. That is the point: a probe
 * that used a token would be measuring the token sheet, and every one of these
 * defects is a composition the sheet permits and cannot see.
 */
const PROBES: Record<string, () => ReactElement> = {
  /* Issue #104, reconstructed. `text-accent` is the interactive accent,
   * defined against the page ground; `bg-integrity-alert-surface` is the
   * integrity banner's red fill. Measured at the time: 1.07:1 in light mode.
   * Composed here through the same Tailwind utilities AlertBanner used, so
   * this is the real cascade and the real tokens, not a hand-picked hex. */
  "probe-issue-104": () => (
    <div data-probe="issue-104" className="bg-integrity-alert-surface p-4">
      <a data-probe-target="evidence-link" href="#evidence" className="text-accent underline">
        View evidence
      </a>
    </div>
  ),

  /* ADR-0038's Consequences name the hole this probe stands in for: Tailwind's
   * arbitrary-value syntax still compiles a literal hex into a colour utility,
   * "because it is greppable ... doc 07's FE-013 ... [is] where it gets
   * hunted."
   *
   * The greens below are INLINE STYLES rather than that arbitrary utility, and
   * the reason is worth stating because it is not fastidiousness: Tailwind v4's
   * automatic source detection reaches `web/tests`, and its candidate extractor
   * is textual — it does not know a comment from markup, or an attribute value
   * from a class. Measured on this file: the scenario above was first named for
   * the issue with a `contrast-` prefix, and that `data-probe` ATTRIBUTE VALUE
   * alone put a `--tw-contrast` filter utility into `dist/assets/index-*.css`;
   * renaming it removed the rule again. A colour utility written here would
   * land in the product's shipped stylesheet by the same route, and a green is
   * the one thing this suite must not put there. (The same mechanism, reached
   * from web/src's own files, is #58's finding.)
   *
   * Nothing is lost: `scanGreenLeaks` reads the painted pixel and cannot tell
   * which mechanism produced it, so an inline style exercises exactly the same
   * detection path. Neither element has a verification marker anywhere in its
   * ancestry, which is what makes both illegal rather than merely green. */
  "probe-green-leak": () => (
    <div data-probe="green-leak">
      <p data-probe-target="saturated" style={{ backgroundColor: "#00ff00" }} className="p-2">
        A green with no verification anywhere near it
      </p>
      <p data-probe-target="palette-adjacent" style={{ backgroundColor: "#12b76a" }} className="p-2">
        A second green, in the band the shipped palette occupies
      </p>
    </div>
  ),

  /* Two WCAG 2.0 A failures axe names by id: `image-alt` (an image with no
   * text alternative) and `label` (a form control with no label). Chosen
   * because both are unambiguous, both are in the tag set views.pw.ts asks
   * for, and neither depends on colour — so this probe still bites if the
   * token sheet changes underneath it. */
  "probe-axe-violation": () => (
    <div data-probe="axe-violation">
      {/* eslint-disable-next-line jsx-a11y/alt-text -- the missing alt IS the probe */}
      <img
        data-probe-target="image-alt"
        width={24}
        height={24}
        src="data:image/gif;base64,R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw=="
      />
      <input data-probe-target="label" type="text" />
    </div>
  ),

  /* doc 06 §6.4: "Visible focus states." An inline `outline: none` beats the
   * `:focus-visible` rule in index.css on specificity, which is exactly how a
   * component would lose its ring in real life. The keyboard walkthrough must
   * report this stop. */
  "probe-focus-suppressed": () => (
    <button type="button" data-probe="focus-suppressed" style={{ outline: "none" }}>
      A button whose focus ring was suppressed
    </button>
  ),
};

function scenarioName(): string {
  return new URLSearchParams(window.location.search).get("scenario") ?? "";
}

/** Read by detectors.pw.ts to assert the two maps never overlap. */
export const SCENARIO_NAMES = Object.keys(SCENARIOS);
export const PROBE_NAMES = Object.keys(PROBES);

export function Harness() {
  const name = scenarioName();
  const Render = SCENARIOS[name] ?? PROBES[name];
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
