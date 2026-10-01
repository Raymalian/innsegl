// SPDX-License-Identifier: Apache-2.0

/*
 * ADR-0062's first-enrolment page: display name + the one-time code minted
 * by `innsegl admin-credential enrol-code` on this machine, then a passkey
 * ceremony. A refusal of that code — missing, wrong, used or expired —
 * arrives as an ordinary AuthRequestError and is shown verbatim, per doc 06
 * §6.1: say what failed.
 */

import { useId, useState, type FormEvent } from "react";

import { AuthRequestError, enrol, realBrowser, type WebAuthnBrowser } from "./client";
import { strings } from "./strings";
import {
  degraded,
  fieldInput,
  fieldLabel,
  fieldStack,
  focusRing,
  noticeBase,
  noticeBody,
  pageHeading,
  pageShell,
  primaryButton,
  proseText,
  secondaryText,
} from "./styles";

export interface EnrolPageProps {
  readonly onEnrolled: (displayName: string) => void;
  /** Injected for tests; defaults to the real browser. */
  readonly browser?: WebAuthnBrowser;
}

type Phase =
  | { readonly status: "idle" }
  | { readonly status: "working" }
  | { readonly status: "failed"; readonly message: string };

export function EnrolPage({ onEnrolled, browser = realBrowser() }: EnrolPageProps) {
  const headingId = useId();
  const nameId = useId();
  const nameHintId = useId();
  const codeId = useId();
  const codeHintId = useId();

  const [displayName, setDisplayName] = useState("");
  const [code, setCode] = useState("");
  const [phase, setPhase] = useState<Phase>({ status: "idle" });

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setPhase({ status: "working" });
    try {
      await enrol(displayName.trim(), code.trim(), browser);
      onEnrolled(displayName.trim());
    } catch (err) {
      setPhase({ status: "failed", message: messageFor(err) });
    }
  };

  const working = phase.status === "working";

  return (
    <section aria-labelledby={headingId} className={pageShell}>
      <h1 id={headingId} className={pageHeading}>
        {strings.enrol.heading}
      </h1>
      <p className={proseText}>{strings.enrol.intro}</p>

      <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4">
        <div className={fieldStack}>
          <label htmlFor={nameId} className={fieldLabel}>
            {strings.enrol.displayNameLabel}
          </label>
          <input
            id={nameId}
            name="display_name"
            type="text"
            autoComplete="off"
            required
            aria-describedby={nameHintId}
            value={displayName}
            onChange={(event) => setDisplayName(event.target.value)}
            className={`${fieldInput} ${focusRing}`}
          />
          <span id={nameHintId} className={secondaryText}>
            {strings.enrol.displayNameHint}
          </span>
        </div>

        <div className={fieldStack}>
          <label htmlFor={codeId} className={fieldLabel}>
            {strings.enrol.codeLabel}
          </label>
          <input
            id={codeId}
            name="code"
            type="text"
            spellCheck={false}
            autoComplete="off"
            required
            aria-describedby={codeHintId}
            value={code}
            onChange={(event) => setCode(event.target.value)}
            className={`${fieldInput} font-mono ${focusRing}`}
          />
          <span id={codeHintId} className={secondaryText}>
            {strings.enrol.codeHint}
          </span>
        </div>

        <button
          type="submit"
          disabled={working}
          className={`${primaryButton} ${focusRing}`}
        >
          {working ? strings.enrol.working : strings.enrol.button}
        </button>
      </form>

      {phase.status === "failed" && (
        <p role="alert" className={`${noticeBase} ${degraded}`}>
          <span className={noticeBody}>{phase.message}</span>
        </p>
      )}
    </section>
  );
}

function messageFor(err: unknown): string {
  if (err instanceof AuthRequestError) return err.message;
  if (err instanceof Error && err.message.includes("passkey support")) {
    return strings.enrol.unsupported;
  }
  if (err instanceof Error && /abort|cancel/i.test(err.message)) {
    return strings.enrol.cancelled;
  }
  return strings.enrol.failed;
}
