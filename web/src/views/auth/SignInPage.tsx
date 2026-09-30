// SPDX-License-Identifier: Apache-2.0

/*
 * ADR-0062's sign-in page: one passkey button, no username field —
 * discoverable/usernameless login, so there is nothing for a form to ask
 * for. doc 06's calm-audit-console voice: factual, unvarnished, no
 * reassurance copy.
 */

import { useId, useState } from "react";

import { AuthRequestError, realBrowser, signIn, type WebAuthnBrowser } from "./client";
import { strings } from "./strings";
import { degraded, focusRing, noticeBase, noticeBody, pageHeading, pageShell, primaryButton, proseText } from "./styles";

export interface SignInPageProps {
  readonly onSignedIn: (displayName: string) => void;
  /** Injected for tests; defaults to the real browser. */
  readonly browser?: WebAuthnBrowser;
}

type Phase =
  | { readonly status: "idle" }
  | { readonly status: "working" }
  | { readonly status: "failed"; readonly message: string };

export function SignInPage({ onSignedIn, browser = realBrowser() }: SignInPageProps) {
  const headingId = useId();
  const [phase, setPhase] = useState<Phase>({ status: "idle" });

  const start = async () => {
    setPhase({ status: "working" });
    try {
      const displayName = await signIn(browser);
      onSignedIn(displayName);
    } catch (err) {
      setPhase({ status: "failed", message: messageFor(err) });
    }
  };

  return (
    <section aria-labelledby={headingId} className={pageShell}>
      <h1 id={headingId} className={pageHeading}>
        {strings.signIn.heading}
      </h1>
      <p className={proseText}>{strings.signIn.intro}</p>
      <button
        type="button"
        onClick={() => void start()}
        disabled={phase.status === "working"}
        className={`${primaryButton} ${focusRing}`}
      >
        {phase.status === "working" ? strings.signIn.working : strings.signIn.button}
      </button>
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
    return strings.signIn.unsupported;
  }
  if (err instanceof Error && /abort|cancel/i.test(err.message)) {
    return strings.signIn.cancelled;
  }
  return strings.signIn.failed;
}
