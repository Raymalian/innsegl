// SPDX-License-Identifier: Apache-2.0

/*
 * The page an invitation link opens (#481; E28 #486). The link is
 * `<origin>/invite#iv_…`: the code is in the fragment, which a browser
 * never sends to a server, so it reaches the API only in the body of the
 * requests below.
 *
 * Two people open it. Someone with no account yet gives a display name and
 * creates a passkey: the server makes the user, the passkey and the
 * membership together (POST /auth/invitation/begin|finish), and the new
 * account's recovery codes are shown once before `onJoined`. Someone already
 * signed in joins with the account they have
 * (POST /account/invitations/accept). Either way the page first asks what
 * the link invites to (POST /auth/invitation), which spends nothing; an
 * unusable link is one answer, whatever made it unusable.
 *
 * AuthGate renders this in place of the dashboard at /invite, signed in or
 * not, like the setup page.
 */

import { useEffect, useId, useState, type FormEvent } from "react";

import { RecoveryCodesStep } from "./RecoveryCodesStep";
import {
  AuthRequestError,
  acceptInvitation,
  joinWithNewPasskey,
  previewInvitation,
  realBrowser,
  type InvitationPreview,
  type WebAuthnBrowser,
} from "./client";
import { formatDate } from "./format";
import { strings } from "./strings";
import {
  degraded,
  fieldInput,
  fieldLabel,
  fieldStack,
  focusRing,
  link,
  mutedText,
  noticeBase,
  noticeBody,
  pageHeading,
  pageShell,
  primaryButton,
  proseText,
  secondaryText,
  srOnly,
} from "./styles";

export interface InvitePageProps {
  /** Whether a session exists: join with it, or make a new account. */
  readonly signedIn: boolean;
  /** Called once the person is a member: with the new account's display
   * name, or "" when they joined with the account they had. */
  readonly onJoined: (displayName: string) => void;
  /** Injected for tests; defaults to the real browser. */
  readonly browser?: WebAuthnBrowser;
}

/** The code a link carries in its fragment, "" when it carries none. */
export function inviteCodeFromHash(hash: string): string {
  return hash.replace(/^#/, "").trim();
}

type Preview =
  | { readonly status: "loading" }
  | { readonly status: "unusable" }
  | { readonly status: "failed"; readonly message: string }
  | { readonly status: "ready"; readonly invitation: InvitationPreview };

type Phase =
  | { readonly status: "idle" }
  | { readonly status: "working" }
  | { readonly status: "failed"; readonly message: string }
  | { readonly status: "codes"; readonly displayName: string; readonly codes: string[] }
  | { readonly status: "joined" };

export function InvitePage({ signedIn, onJoined, browser = realBrowser() }: InvitePageProps) {
  const headingId = useId();
  const nameId = useId();
  const nameHintId = useId();
  const [code] = useState(() => inviteCodeFromHash(window.location.hash));
  const [preview, setPreview] = useState<Preview>({ status: "loading" });
  const [displayName, setDisplayName] = useState("");
  const [phase, setPhase] = useState<Phase>({ status: "idle" });

  useEffect(() => {
    if (code === "") return;
    let live = true;
    previewInvitation(code).then(
      (invitation) => {
        if (live) setPreview({ status: "ready", invitation });
      },
      (err: unknown) => {
        if (!live) return;
        if (err instanceof AuthRequestError && err.status === 404) {
          setPreview({ status: "unusable" });
          return;
        }
        setPreview({ status: "failed", message: messageFor(err) });
      },
    );
    return () => {
      live = false;
    };
  }, [code]);

  const shell = (heading: string, body: React.ReactNode, hideHeading = false) => (
    <section aria-labelledby={headingId} className={pageShell}>
      <h1 id={headingId} className={hideHeading ? srOnly : pageHeading}>
        {heading}
      </h1>
      {body}
    </section>
  );

  if (code === "") {
    return shell(strings.invite.missingHeading, <p className={proseText}>{strings.invite.missingBody}</p>);
  }
  if (preview.status === "unusable") {
    return shell(strings.invite.unusableHeading, <p className={proseText}>{strings.invite.unusableBody}</p>);
  }
  if (preview.status === "loading") {
    return shell(
      strings.invite.heading,
      <p role="status" aria-busy="true" className={mutedText}>
        {strings.invite.loading}
      </p>,
    );
  }
  if (preview.status === "failed") {
    return shell(
      strings.invite.heading,
      <p role="alert" className={`${noticeBase} ${degraded}`}>
        <span className={noticeBody}>{preview.message}</span>
      </p>,
    );
  }

  const invitation = preview.invitation;

  if (phase.status === "codes") {
    return shell(
      strings.invite.heading,
      <RecoveryCodesStep codes={phase.codes} onContinue={() => onJoined(phase.displayName)} />,
      true,
    );
  }
  if (phase.status === "joined") {
    return shell(
      strings.invite.joinedHeading,
      <>
        <p className={proseText}>{strings.invite.joinedBody(invitation.organisation)}</p>
        <a href="/" className={link}>
          {strings.invite.continueLink}
        </a>
      </>,
    );
  }

  const working = phase.status === "working";

  const createAccount = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setPhase({ status: "working" });
    try {
      const result = await joinWithNewPasskey(code, displayName.trim(), browser);
      setPhase({
        status: "codes",
        displayName: result.displayName || displayName.trim(),
        codes: [...result.recoveryCodes],
      });
    } catch (err) {
      setPhase({ status: "failed", message: messageFor(err) });
    }
  };

  const join = async () => {
    setPhase({ status: "working" });
    try {
      await acceptInvitation(code);
      setPhase({ status: "joined" });
      onJoined("");
    } catch (err) {
      setPhase({ status: "failed", message: messageFor(err) });
    }
  };

  return shell(
    strings.invite.heading,
    <>
      <p className={proseText}>{strings.invite.invitedTo(invitation.organisation, invitation.role)}</p>
      <p className={secondaryText}>
        {strings.invite.expires} {formatDate(invitation.expires_at)}
      </p>

      {signedIn ? (
        <>
          <p className={proseText}>{strings.invite.joinIntro}</p>
          <button
            type="button"
            disabled={working}
            onClick={() => void join()}
            className={`${primaryButton} ${focusRing}`}
          >
            {working ? strings.invite.working : strings.invite.joinButton}
          </button>
        </>
      ) : (
        <form onSubmit={(e) => void createAccount(e)} className="flex flex-col gap-4">
          <p className={proseText}>{strings.invite.newIntro}</p>
          <div className={fieldStack}>
            <label htmlFor={nameId} className={fieldLabel}>
              {strings.invite.displayNameLabel}
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
              {strings.invite.displayNameHint}
            </span>
          </div>
          <button type="submit" disabled={working} className={`${primaryButton} ${focusRing}`}>
            {working ? strings.invite.working : strings.invite.createButton}
          </button>
        </form>
      )}

      {phase.status === "failed" && (
        <p role="alert" className={`${noticeBase} ${degraded}`}>
          <span className={noticeBody}>{phase.message}</span>
        </p>
      )}
    </>,
  );
}

function messageFor(err: unknown): string {
  if (err instanceof AuthRequestError) return err.message;
  if (err instanceof Error && err.message.includes("passkey support")) {
    return strings.invite.unsupported;
  }
  if (err instanceof Error && /abort|cancel/i.test(err.message)) {
    return strings.invite.cancelled;
  }
  return strings.invite.failed;
}
