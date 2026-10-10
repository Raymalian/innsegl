// SPDX-License-Identifier: Apache-2.0

// ADR-0062, and #445's accounts amendment: "every dashboard page ... refuses
// to answer without a valid session." The SERVER is what actually enforces
// that (internal/api/server.go's deny-by-default gate) — this component is
// the honest mirror of it on the client: the app shell renders NOTHING but
// a sign-in or setup screen until a session exists, so a reader never sees
// so much as a load-failure placeholder for a view the server was always
// going to refuse.
//
// Account management (/setup, /account) is shell/auth infrastructure, the
// same category SignInPage already was — not one of doc 06 §3's six ledger
// views — so it is decided here, off the address bar directly, rather than
// through routes.ts's `VIEWS`/`Route`.
//
// A render-prop children function, not a plain ReactNode: the authenticated
// branch needs to hand the app shell a sign-out control (and now the
// account-name link beside it) for its header (App.tsx's own `account`
// slot), and a render prop is what lets this file own that control without
// App.tsx importing anything from views/auth.

import { Fragment, useId, useState, type ReactNode } from "react";

import { OrganisationSwitcher } from "./OrganisationSwitcher";
import { AccountMenu } from "./SignOutControl";
import { useStrings } from "./i18n";
import { navigate, usePath } from "./router";
import { isInvitePath, isSetupPath, setupCodeFrom } from "./routes";
import { strings as authStrings } from "../views/auth/strings";
import { SetupPage, SignInPage, useSessionState } from "../views/auth";
import { InvitePage } from "../views/auth/InvitePage";
import { mutedText, noticeBase } from "../views/auth/styles";

export interface AuthGateProps {
  readonly children: (account: ReactNode) => ReactNode;
  /** Injected for tests; defaults to same-origin `/api/v1`. */
  readonly apiBase?: string;
}

export function AuthGate({ children, apiBase }: AuthGateProps) {
  const headingId = useId();
  const strings = useStrings();
  const path = usePath();
  const { state, markAuthenticated, markSignedOut, reload } = useSessionState(apiBase);
  // RM-307 (#486): a new organisation choice remounts the dashboard, so
  // every view reads again under the scope the server now applies.
  const [scopeKey, setScopeKey] = useState(0);

  if (state.status === "checking") {
    return (
      <p
        role="status"
        aria-busy="true"
        aria-labelledby={headingId}
        className={`${noticeBase} ${mutedText}`}
      >
        <span id={headingId}>{authStrings.session.checking}</span>
      </p>
    );
  }

  // An invitation link (#481): a new person makes an account with it; a
  // signed-in one joins with theirs. Either way, then the dashboard.
  if (isInvitePath(path)) {
    const signedIn = state.status === "authenticated";
    return (
      <InvitePage
        signedIn={signedIn}
        onJoined={(displayName) => {
          if (!signedIn) {
            navigate("/");
            reload();
          } else if (displayName === "") {
            reload();
          }
        }}
      />
    );
  }

  if (state.status === "unauthenticated") {
    if (isSetupPath(path)) {
      return (
        <SetupPage
          setupNeeded={state.setupNeeded}
          code={setupCodeFrom(path)}
          onEnrolled={markAuthenticated}
        />
      );
    }
    return (
      <SignInPage
        setupNeeded={state.setupNeeded}
        onSignedIn={markAuthenticated}
        onRecovered={(displayName) => {
          markAuthenticated(displayName);
          // #445: land on the account page with the notice that tells the
          // reader a recovery code, not a passkey, is why they are signed
          // in — AccountPage itself reads and then strips this once.
          navigate("/account?notice=recovery-signin");
        }}
      />
    );
  }

  return (
    <Fragment key={scopeKey}>
      {children(
        <>
          {/* RM-333 (#511): the account name is a menu button holding Account
           * and Sign out. It stays visible at every width, because sign-out
           * now lives inside it; `max-w` + `truncate` keep a long name from
           * crowding the anchoring heartbeat (FE-128 measures that row at
           * 720px). */}
          <OrganisationSwitcher
            organisations={state.organisations}
            onChange={() => setScopeKey((k) => k + 1)}
          />
          <div role="group" aria-label={strings.labels.header.account} className="flex items-center">
            <AccountMenu displayName={state.displayName} onSignedOut={markSignedOut} />
          </div>
        </>,
      )}
    </Fragment>
  );
}
