// SPDX-License-Identifier: Apache-2.0

/*
 * RM-260/RM-261's sign-in surface and #445's accounts amendment (ADR-0062).
 * src/app/AuthGate.tsx is what mounts SetupPage/SignInPage/AccountPage;
 * everything else is exported so each piece — the ceremony client, the
 * session-state hook, the pages — can be tested on its own.
 */

export { SignInPage } from "./SignInPage";
export type { SignInPageProps } from "./SignInPage";

export { SetupPage } from "./SetupPage";
export type { SetupPageProps } from "./SetupPage";

export { AccountPage } from "./AccountPage";
export type { AccountPageProps } from "./AccountPage";

export { RecoveryCodesStep } from "./RecoveryCodesStep";
export type { RecoveryCodesStepProps } from "./RecoveryCodesStep";

export {
  AuthRequestError,
  addPasskey,
  enrol,
  fetchAccount,
  fetchSessionStatus,
  fetchSetupStatus,
  generateRecoveryCodes,
  realBrowser,
  recover,
  removePasskey,
  renamePasskey,
  signIn,
  signOut,
  updateAccount,
} from "./client";
export type {
  CredentialsContainerLike,
  EnrolResult,
  PublicKeyCredentialStaticLike,
  SessionStatus,
  WebAuthnBrowser,
} from "./client";

export { useSessionState } from "./session";
export type { SessionResource, SessionState } from "./session";

export { strings } from "./strings";
export type { AuthStrings } from "./strings";

export { formatDate } from "./format";

export type {
  Account,
  AccountPasskey,
  EnrolFinished,
  RecoverResult,
  RecoveryCodes,
  SetupStatus,
} from "./types";
