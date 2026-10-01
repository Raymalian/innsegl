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

import { useId, type ReactNode } from "react";

import { SignOutControl } from "./SignOutControl";
import { Link, navigate, usePath } from "./router";
import { isSetupPath, setupCodeFrom } from "./routes";
import { strings as authStrings } from "../views/auth/strings";
import { SetupPage, SignInPage, useSessionState } from "../views/auth";
import { chromeButton, focusRing, mutedText, noticeBase } from "../views/auth/styles";

export interface AuthGateProps {
  readonly children: (account: ReactNode) => ReactNode;
  /** Injected for tests; defaults to same-origin `/api/v1`. */
  readonly apiBase?: string;
}

export function AuthGate({ children, apiBase }: AuthGateProps) {
  const headingId = useId();
  const path = usePath();
  const { state, markAuthenticated, markSignedOut } = useSessionState(apiBase);

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
    <>
      {children(
        <>
          {/* `hidden md:inline`: FE-128 measures every view at 720px with
           * the anchoring heartbeat's own long fixture text sharing this
           * row (App.tsx's `min-w-0 flex-1` heartbeat slot, doc 06 §3.1's
           * "never hidden" — so IT is not the element that yields).
           * MEASURED: adding this link at its natural width (a short name
           * like "Test Operator" alone) left the heartbeat only 23px for
           * content that needs 108px. This link is chrome, not the
           * heartbeat, so it is what gives way below `md`; `max-w` +
           * `truncate` is the backstop for an unusually long name at `md`
           * and above, where it stays reachable but never dominates the
           * row. */}
          <Link
            to="/account"
            title={state.displayName}
            className={`${chromeButton} ${focusRing} hidden max-w-[10rem] truncate md:inline`}
          >
            {state.displayName}
          </Link>
          <SignOutControl onSignedOut={markSignedOut} />
        </>,
      )}
    </>
  );
}
