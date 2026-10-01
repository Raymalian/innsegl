// SPDX-License-Identifier: Apache-2.0

/*
 * ADR-0062's accounts amendment (#445) — the page the setup link opens:
 * `make start` / `install.sh` print it once, with the one-time code already
 * in the URL, so nobody ever types a code here (the old EnrolPage did, and
 * is retired in this same change). A name and a passkey ceremony, then the
 * account's first ten recovery codes — shown exactly once, via
 * RecoveryCodesStep — before `onEnrolled` hands the session to AuthGate.
 *
 * `code` is read by the caller (AuthGate, off the address bar) and handed in
 * as a prop rather than read here, for the same reason routes.ts's own
 * comment gives for keeping view state in the URL: one place parses it.
 */

import { useId, useState, type FormEvent } from "react";

import { RecoveryCodesStep } from "./RecoveryCodesStep";
import { AuthRequestError, enrol, realBrowser, type WebAuthnBrowser } from "./client";
import { strings } from "./strings";
import {
  degraded,
  fieldInput,
  fieldLabel,
  fieldStack,
  focusRing,
  link,
  noticeBase,
  noticeBody,
  pageHeading,
  pageShell,
  primaryButton,
  proseText,
  secondaryText,
  srOnly,
} from "./styles";

export interface SetupPageProps {
  /** `SetupStatus.needed`, already fetched by AuthGate. */
  readonly setupNeeded: boolean;
  /** The one-time code from `?code=…`, or "" if the link carried none. */
  readonly code: string;
  readonly onEnrolled: (displayName: string) => void;
  /** Injected for tests; defaults to the real browser. */
  readonly browser?: WebAuthnBrowser;
  /** Where "go to sign in" points; defaults to "/". Injected for tests. */
  readonly signInHref?: string;
}

type Phase =
  | { readonly status: "idle" }
  | { readonly status: "working" }
  | { readonly status: "failed"; readonly message: string }
  | { readonly status: "codes"; readonly displayName: string; readonly codes: string[] };

export function SetupPage({
  setupNeeded,
  code,
  onEnrolled,
  browser = realBrowser(),
  signInHref = "/",
}: SetupPageProps) {
  const headingId = useId();
  const nameId = useId();
  const nameHintId = useId();

  const [displayName, setDisplayName] = useState("");
  const [phase, setPhase] = useState<Phase>({ status: "idle" });

  if (!setupNeeded) {
    return (
      <section aria-labelledby={headingId} className={pageShell}>
        <h1 id={headingId} className={pageHeading}>
          {strings.setup.alreadyDoneHeading}
        </h1>
        <p className={proseText}>{strings.setup.alreadyDoneBody}</p>
        <a href={signInHref} className={link}>
          {strings.setup.signInLink}
        </a>
      </section>
    );
  }

  if (code === "") {
    return (
      <section aria-labelledby={headingId} className={pageShell}>
        <h1 id={headingId} className={pageHeading}>
          {strings.setup.missingCodeHeading}
        </h1>
        <p className={proseText}>{strings.setup.missingCodeBody}</p>
      </section>
    );
  }

  if (phase.status === "codes") {
    return (
      <section aria-labelledby={headingId} className={pageShell}>
        <h1 id={headingId} className={srOnly}>
          {strings.setup.heading}
        </h1>
        <RecoveryCodesStep
          codes={phase.codes}
          onContinue={() => onEnrolled(phase.displayName)}
        />
      </section>
    );
  }

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setPhase({ status: "working" });
    try {
      const result = await enrol(displayName.trim(), code, browser);
      setPhase({
        status: "codes",
        displayName: result.displayName || displayName.trim(),
        codes: [...result.recoveryCodes],
      });
    } catch (err) {
      setPhase({ status: "failed", message: messageFor(err) });
    }
  };

  const working = phase.status === "working";

  return (
    <section aria-labelledby={headingId} className={pageShell}>
      <h1 id={headingId} className={pageHeading}>
        {strings.setup.heading}
      </h1>
      <p className={proseText}>{strings.setup.intro}</p>

      <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4">
        <div className={fieldStack}>
          <label htmlFor={nameId} className={fieldLabel}>
            {strings.setup.displayNameLabel}
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
            {strings.setup.displayNameHint}
          </span>
        </div>

        <button
          type="submit"
          disabled={working}
          className={`${primaryButton} ${focusRing}`}
        >
          {working ? strings.setup.working : strings.setup.button}
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
    return strings.setup.unsupported;
  }
  if (err instanceof Error && /abort|cancel/i.test(err.message)) {
    return strings.setup.cancelled;
  }
  return strings.setup.failed;
}
