// SPDX-License-Identifier: Apache-2.0

/*
 * Every user-visible string the sign-in and first-enrolment pages render —
 * public-verify's own strings.ts pattern (a local catalogue, not the shell's
 * useStrings()), for the same reason: this directory is separately owned.
 *
 * doc 06 §6.1: factual, unvarnished, specific; no "successfully", no
 * "seamless", no "trusted by", no exclamation marks. §5.4: sentence case,
 * labels with no terminal punctuation, helper text with it.
 */

export const strings = {
  signIn: {
    heading: "Sign in",
    intro: "This dashboard shows what an agent did. Sign in with your passkey to see it.",
    button: "Sign in with a passkey",
    working: "Waiting for your passkey",
    unsupported:
      "This browser has no passkey support, so there is no way to sign in from it.",
    cancelled: "The passkey prompt was closed before it finished. Try again.",
    failed: "Sign-in failed",
  },
  enrol: {
    heading: "Set up the first passkey",
    intro:
      "Nobody has signed in here yet. Enter the one-time code an operator minted on this machine, and this browser will create the passkey that signs in from now on.",
    displayNameLabel: "Display name",
    displayNameHint: "Shown next to what you sign in to see — not part of your identity.",
    codeLabel: "One-time code",
    codeHint: "Minted with innsegl admin-credential enrol-code, on this machine, by a person.",
    button: "Create a passkey",
    working: "Waiting for your passkey",
    unsupported:
      "This browser has no passkey support, so enrolment cannot complete from it.",
    cancelled: "The passkey prompt was closed before it finished. Try again.",
    failed: "Enrolment failed",
  },
  session: {
    checking: "Checking sign-in status",
  },
  signOut: {
    button: "Sign out",
    working: "Signing out",
  },
} as const;

export type AuthStrings = typeof strings;
