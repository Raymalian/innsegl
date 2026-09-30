// SPDX-License-Identifier: Apache-2.0

/*
 * RM-260/RM-261's sign-in surface (ADR-0062). src/app/AuthGate.tsx is what
 * mounts these; everything else is exported so each piece — the ceremony
 * client, the session-state hook, the two pages — can be tested on its own.
 */

export { SignInPage } from "./SignInPage";
export type { SignInPageProps } from "./SignInPage";

export { EnrolPage } from "./EnrolPage";
export type { EnrolPageProps } from "./EnrolPage";

export {
  AuthRequestError,
  enrol,
  fetchEnrolled,
  fetchSessionStatus,
  realBrowser,
  signIn,
  signOut,
} from "./client";
export type {
  CredentialsContainerLike,
  PublicKeyCredentialStaticLike,
  SessionStatus,
  WebAuthnBrowser,
} from "./client";

export { useSessionState } from "./session";
export type { SessionResource, SessionState } from "./session";

export { strings } from "./strings";
export type { AuthStrings } from "./strings";
