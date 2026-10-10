// SPDX-License-Identifier: Apache-2.0

/*
 * ADR-0062's sign-in page: one passkey button, no username field —
 * discoverable/usernameless login — plus #445's two additions: a toggle to
 * a recovery-code form for when every passkey is unreachable, and a
 * no-account notice for a deployment where SetupStatus.needed is still
 * true (there is nothing to sign into yet). doc 06's calm-audit-console
 * voice: factual, unvarnished, no reassurance copy.
 */

import { useEffect, useId, useState, type FormEvent } from "react";

import { navigate } from "../../app/router";
import {
  AuthRequestError,
  beginOrganisationSignIn,
  realBrowser,
  recover,
  signIn,
  type WebAuthnBrowser,
} from "./client";
import { strings } from "./strings";
import {
  degraded,
  fieldInput,
  fieldLabel,
  fieldStack,
  focusRing,
  inlineLinkButton,
  noticeBase,
  noticeBody,
  pageHeading,
  pageShell,
  primaryButton,
  proseText,
  secondaryText,
} from "./styles";

export interface SignInPageProps {
  /** `SetupStatus.needed`: true when no account exists yet, in which case
   * there is nothing to offer a passkey button for. */
  readonly setupNeeded?: boolean;
  readonly onSignedIn: (displayName: string) => void;
  /** A recovery code signed in; `remaining` is the server's own count of
   * codes left, read fresh rather than decremented client-side. */
  readonly onRecovered: (displayName: string, remaining: number) => void;
  /** Injected for tests; defaults to the real browser. */
  readonly browser?: WebAuthnBrowser;
  /** Sends the browser to the organisation's identity provider (#485).
   * Injected for tests; defaults to a full-page navigation. */
  readonly goTo?: (url: string) => void;
}

/** `?sso=<reason>` on the very first render: why the organisation's
 * sign-in sent the browser back. Worded from the catalogue only, never
 * echoed; a reason it does not know reads as the generic one. */
function initialSSOReason(): string | null {
  const reason = new URLSearchParams(window.location.search).get("sso");
  if (reason === null) return null;
  return strings.ssoReasons[reason] ?? strings.ssoReasons["internal"] ?? null;
}

type Phase =
  | { readonly status: "idle" }
  | { readonly status: "working" }
  | { readonly status: "failed"; readonly message: string };

export function SignInPage({
  setupNeeded = false,
  onSignedIn,
  onRecovered,
  browser = realBrowser(),
  goTo = (url: string) => window.location.assign(url),
}: SignInPageProps) {
  const headingId = useId();
  const recoveryId = useId();
  const recoveryHintId = useId();
  const ssoId = useId();
  const ssoHintId = useId();

  const [phase, setPhase] = useState<Phase>({ status: "idle" });
  const [showRecovery, setShowRecovery] = useState(false);
  const [recoveryCode, setRecoveryCode] = useState("");
  const [recoveryPhase, setRecoveryPhase] = useState<Phase>({ status: "idle" });
  const [showSSO, setShowSSO] = useState(false);
  const [ssoName, setSSOName] = useState("");
  const [ssoPhase, setSSOPhase] = useState<Phase>({ status: "idle" });
  const [ssoReason] = useState(initialSSOReason);

  // Shown once: a reload of /?sso=… would otherwise repeat it forever.
  useEffect(() => {
    if (ssoReason !== null) navigate(window.location.pathname, { replace: true });
  }, [ssoReason]);

  if (setupNeeded) {
    return (
      <section aria-labelledby={headingId} className={pageShell}>
        <h1 id={headingId} className={pageHeading}>
          {strings.signIn.noAccountHeading}
        </h1>
        <p className={proseText}>{strings.signIn.noAccountIntro}</p>
      </section>
    );
  }

  const start = async () => {
    setPhase({ status: "working" });
    try {
      const displayName = await signIn(browser);
      onSignedIn(displayName);
    } catch (err) {
      setPhase({ status: "failed", message: messageFor(err) });
    }
  };

  const submitRecovery = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setRecoveryPhase({ status: "working" });
    try {
      const result = await recover(recoveryCode.trim());
      onRecovered(result.display_name, result.remaining);
    } catch (err) {
      setRecoveryPhase({
        status: "failed",
        message: err instanceof AuthRequestError ? err.message : strings.signIn.recoveryFailed,
      });
    }
  };

  const toggle = (
    <button
      type="button"
      onClick={() => setShowRecovery((shown) => !shown)}
      className={`${inlineLinkButton} self-start`}
    >
      {showRecovery ? strings.signIn.recoveryHideLink : strings.signIn.recoveryLink}
    </button>
  );

  const submitSSO = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSSOPhase({ status: "working" });
    try {
      goTo(await beginOrganisationSignIn(ssoName.trim()));
    } catch (err) {
      setSSOPhase({
        status: "failed",
        message: err instanceof AuthRequestError ? err.message : strings.signIn.ssoFailed,
      });
    }
  };

  const ssoToggle = (
    <button
      type="button"
      onClick={() => setShowSSO((shown) => !shown)}
      className={`${inlineLinkButton} self-start`}
    >
      {showSSO ? strings.signIn.ssoHideLink : strings.signIn.ssoLink}
    </button>
  );

  // #485: the organisation's own sign-in, a view of its own.
  if (showSSO) {
    return (
      <section aria-labelledby={headingId} className={pageShell}>
        <h1 id={headingId} className={pageHeading}>
          {strings.signIn.ssoHeading}
        </h1>
        <p className={proseText}>{strings.signIn.ssoIntro}</p>
        <form onSubmit={(e) => void submitSSO(e)} className="flex flex-col gap-4">
          <div className={fieldStack}>
            <label htmlFor={ssoId} className={fieldLabel}>
              {strings.signIn.ssoLabel}
            </label>
            <input
              id={ssoId}
              name="sign_in_name"
              type="text"
              spellCheck={false}
              autoComplete="organization"
              autoCapitalize="none"
              autoFocus
              required
              aria-describedby={ssoHintId}
              value={ssoName}
              onChange={(event) => setSSOName(event.target.value)}
              className={`${fieldInput} font-mono ${focusRing}`}
            />
            <span id={ssoHintId} className={secondaryText}>
              {strings.signIn.ssoHint}
            </span>
          </div>
          <button
            type="submit"
            disabled={ssoPhase.status === "working"}
            className={`${primaryButton} ${focusRing}`}
          >
            {ssoPhase.status === "working" ? strings.signIn.ssoWorking : strings.signIn.ssoButton}
          </button>
          {ssoPhase.status === "failed" && (
            <p role="alert" className={`${noticeBase} ${degraded}`}>
              <span className={noticeBody}>{ssoPhase.message}</span>
            </p>
          )}
        </form>
        {ssoToggle}
      </section>
    );
  }

  // One action per view: the passkey, the recovery code or the
  // organisation's sign-in, never two buttons at once.
  if (showRecovery) {
    return (
      <section aria-labelledby={headingId} className={pageShell}>
        <h1 id={headingId} className={pageHeading}>
          {strings.signIn.recoveryHeading}
        </h1>
        <p className={proseText}>{strings.signIn.recoveryIntro}</p>
        <form onSubmit={(e) => void submitRecovery(e)} className="flex flex-col gap-4">
          <div className={fieldStack}>
            <label htmlFor={recoveryId} className={fieldLabel}>
              {strings.signIn.recoveryLabel}
            </label>
            <input
              id={recoveryId}
              name="code"
              type="text"
              spellCheck={false}
              autoComplete="one-time-code"
              autoCapitalize="none"
              autoFocus
              required
              aria-describedby={recoveryHintId}
              value={recoveryCode}
              onChange={(event) => setRecoveryCode(event.target.value)}
              className={`${fieldInput} font-mono ${focusRing}`}
            />
            <span id={recoveryHintId} className={secondaryText}>
              {strings.signIn.recoveryHint}
            </span>
          </div>
          <button
            type="submit"
            disabled={recoveryPhase.status === "working"}
            className={`${primaryButton} ${focusRing}`}
          >
            {recoveryPhase.status === "working"
              ? strings.signIn.recoveryWorking
              : strings.signIn.recoveryButton}
          </button>
          {recoveryPhase.status === "failed" && (
            <p role="alert" className={`${noticeBase} ${degraded}`}>
              <span className={noticeBody}>{recoveryPhase.message}</span>
            </p>
          )}
        </form>
        {toggle}
      </section>
    );
  }

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
      {phase.status !== "failed" && ssoReason !== null && (
        <p role="alert" className={`${noticeBase} ${degraded}`}>
          <span className={noticeBody}>{ssoReason}</span>
        </p>
      )}
      <div className="flex flex-col gap-2">
        {toggle}
        {ssoToggle}
      </div>
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
