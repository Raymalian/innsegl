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
    noAccountHeading: "No account yet",
    noAccountIntro:
      "Nobody has created an account on this deployment yet. Open the one-time setup link printed by make start or install.sh to create one.",
    recoveryLink: "Use a recovery code",
    recoveryHideLink: "Use a passkey instead",
    recoveryLabel: "Recovery code",
    recoveryHint: "One of the ten single-use codes shown when the account was created.",
    recoveryButton: "Sign in with this code",
    recoveryWorking: "Checking the code",
    recoveryFailed: "That recovery code could not be used",
  },
  setup: {
    heading: "Create your account",
    intro:
      "This browser will create the passkey that signs in to this dashboard from now on.",
    missingCodeHeading: "No setup link",
    missingCodeBody:
      "This page needs the one-time setup link printed by make start or install.sh — open that link rather than this address directly.",
    alreadyDoneHeading: "Already set up",
    alreadyDoneBody: "An account already exists on this deployment. Sign in instead.",
    signInLink: "Go to sign in",
    displayNameLabel: "Display name",
    displayNameHint: "Shown next to what you sign in to see — not part of your identity.",
    button: "Create passkey",
    working: "Waiting for your passkey",
    unsupported:
      "This browser has no passkey support, so the account cannot be created from it.",
    cancelled: "The passkey prompt was closed before it finished. Try again.",
    failed: "Setting up the account failed",
  },
  recoveryCodes: {
    heading: "Save your recovery codes",
    intro:
      "Each code signs in once, in place of a passkey, if every passkey on this account is lost. Save them somewhere else — they are shown only this once.",
    copyButton: "Copy",
    copiedButton: "Copied",
    downloadButton: "Download",
    savedCheckbox: "I have saved these codes",
    continueButton: "Continue",
  },
  session: {
    checking: "Checking sign-in status",
  },
  signOut: {
    button: "Sign out",
    working: "Signing out",
  },
  account: {
    heading: "Account",
    recoverySignInNotice:
      "You signed in with a recovery code. Add a passkey so you can sign in normally.",
    codesRemainingSuffix: "codes left",
    profileHeading: "Profile",
    nameLabel: "Name",
    editButton: "Edit",
    saveButton: "Save",
    cancelButton: "Cancel",
    saving: "Saving",
    passkeysHeading: "Passkeys",
    passkeyNameHeader: "Name",
    passkeyAddedHeader: "Added",
    passkeyLastUsedHeader: "Last used",
    passkeyActionsHeader: "Actions",
    passkeyNeverUsed: "Never",
    currentDevice: "This device",
    renameButton: "Rename",
    removeButton: "Remove",
    removeConfirmPrompt: "Remove this passkey? It cannot sign in again.",
    removeConfirmButton: "Remove it",
    removeCancelButton: "Keep it",
    removeLastTooltip: "The last passkey on an account cannot be removed.",
    removeFailed: "That passkey could not be removed",
    addHeading: "Add a passkey",
    addNameLabel: "Name",
    addNameHint: "A name for this device, so it can be told apart from the others later.",
    addButton: "Create passkey",
    addWorking: "Waiting for your passkey",
    addUnsupported: "This browser has no passkey support, so it cannot add a passkey.",
    addCancelled: "The passkey prompt was closed before it finished. Try again.",
    addFailed: "Adding the passkey failed",
    recoveryHeading: "Recovery codes",
    recoveryOf: "of 10 left",
    regenerateButton: "Generate new codes",
    regenerateConfirmPrompt:
      "Generate ten new recovery codes? Every code shown before this stops working.",
    regenerateConfirmButton: "Generate new codes",
    regenerateCancelButton: "Keep the current codes",
    loadFailed: "The account could not be loaded",
  },
} as const;

export type AuthStrings = typeof strings;
