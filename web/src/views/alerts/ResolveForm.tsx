// SPDX-License-Identifier: Apache-2.0

/*
 * Resolve one alert, or every open alert in a group — RM-330 (#506),
 * ADR-0044's 2026-10-03 amendment.
 *
 * A reason, then a passkey. Nothing is written until the signed-in operator
 * completes a fresh passkey ceremony: the server holds the alerts and the
 * reason with the challenge, and writes them only when the assertion
 * verifies. The resolution records the account's name, the time and the
 * reason; the alert itself is never changed.
 *
 * A refusal is shown in the server's own words (an alert someone else just
 * resolved is a 409 naming it), and a closed passkey prompt says that
 * nothing was resolved — never a generic failure.
 */

import { useId, useState, type FormEvent } from "react";

import {
  AuthRequestError,
  realBrowser,
  resolveAlerts,
  type WebAuthnBrowser,
} from "../auth/client";
import { strings } from "./strings";
import {
  fieldHelp,
  fieldLabel,
  fieldStack,
  formActions,
  formDone,
  formError,
  primaryButton,
  reasonInput,
  resolveForm,
} from "./styles";

/** migration 0003's bound on a resolution's reason. */
const MAX_REASON_BYTES = 2048;

export interface ResolveFormProps {
  readonly eventIds: readonly string[];
  /** Called once the resolutions are written, so the caller reads again. */
  readonly onResolved: () => void;
  /** The passkey API; the real browser's unless a test supplies one. */
  readonly browser?: WebAuthnBrowser;
  readonly apiBase?: string;
}

type Phase =
  | { readonly kind: "idle" }
  | { readonly kind: "working" }
  | { readonly kind: "failed"; readonly message: string }
  | { readonly kind: "done"; readonly count: number };

export function ResolveForm({ eventIds, onResolved, browser, apiBase }: ResolveFormProps) {
  const reasonId = useId();
  const helpId = useId();
  const [reason, setReason] = useState("");
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const label =
    eventIds.length === 1 ? strings.resolve.heading : strings.resolve.groupHeading(eventIds.length);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmed = reason.trim();
    if (trimmed === "") {
      setPhase({ kind: "failed", message: strings.resolve.needReasonDetail });
      return;
    }
    const passkeys = browser ?? realBrowser();
    if (!passkeys.supported) {
      setPhase({ kind: "failed", message: strings.resolve.unsupportedDetail });
      return;
    }
    setPhase({ kind: "working" });
    try {
      const written = await resolveAlerts(eventIds, trimmed, passkeys, apiBase);
      setPhase({ kind: "done", count: written.length });
      onResolved();
    } catch (error) {
      setPhase({ kind: "failed", message: failureMessage(error) });
    }
  };

  const working = phase.kind === "working";
  return (
    <form aria-label={label} className={resolveForm} onSubmit={(e) => void submit(e)} noValidate>
      <div className={fieldStack}>
        <label htmlFor={reasonId} className={fieldLabel}>
          {strings.resolve.reasonLabel}
        </label>
        <textarea
          id={reasonId}
          aria-describedby={helpId}
          className={reasonInput}
          maxLength={MAX_REASON_BYTES}
          value={reason}
          disabled={working || phase.kind === "done"}
          onChange={(e) => setReason(e.target.value)}
        />
        <p id={helpId} className={fieldHelp}>
          {strings.resolve.reasonDetail}
        </p>
      </div>
      <div className={formActions}>
        <button
          type="submit"
          className={primaryButton}
          disabled={working || phase.kind === "done"}
        >
          {working ? strings.resolve.workingLabel : strings.resolve.confirmLabel}
        </button>
      </div>
      {phase.kind === "failed" ? (
        <p role="alert" className={formError}>
          {phase.message}
        </p>
      ) : null}
      {phase.kind === "done" ? (
        <p role="status" className={formDone}>
          {strings.resolve.doneDetail(phase.count)}
        </p>
      ) : null}
    </form>
  );
}

function failureMessage(error: unknown): string {
  if (error instanceof AuthRequestError) return strings.resolve.failedWith(error.message);
  if (error instanceof DOMException && error.name === "NotAllowedError") {
    return strings.resolve.cancelledDetail;
  }
  if (error instanceof Error && error.message === "no passkey was offered") {
    return strings.resolve.cancelledDetail;
  }
  return strings.resolve.failedWith(error instanceof Error ? error.message : String(error));
}
