// SPDX-License-Identifier: Apache-2.0

// ADR-0062: "every dashboard page ... refuses to answer without a valid
// session." The SERVER is what actually enforces that (internal/api/
// server.go's deny-by-default gate) — this component is the honest mirror
// of it on the client: the app shell renders NOTHING but a sign-in or
// first-enrolment screen until a session exists, so a reader never sees so
// much as a load-failure placeholder for a view the server was always going
// to refuse.
//
// A render-prop children function, not a plain ReactNode: the authenticated
// branch needs to hand the app shell a sign-out control for its header
// (App.tsx's own `account` slot), and a render prop is what lets this file
// own that control without App.tsx importing anything from views/auth.

import { useId, type ReactNode } from "react";

import { SignOutControl } from "./SignOutControl";
import { strings as authStrings } from "../views/auth/strings";
import { EnrolPage, SignInPage, useSessionState } from "../views/auth";
import { mutedText, noticeBase } from "../views/auth/styles";

export interface AuthGateProps {
  readonly children: (account: ReactNode) => ReactNode;
  /** Injected for tests; defaults to same-origin `/api/v1`. */
  readonly apiBase?: string;
}

export function AuthGate({ children, apiBase }: AuthGateProps) {
  const headingId = useId();
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
    return state.enrolled ? (
      <SignInPage onSignedIn={markAuthenticated} />
    ) : (
      <EnrolPage onEnrolled={markAuthenticated} />
    );
  }

  return (
    <>{children(<SignOutControl onSignedOut={markSignedOut} />)}</>
  );
}
