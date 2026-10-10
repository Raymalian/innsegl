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
    recoveryHeading: "Sign in with a recovery code",
    recoveryIntro:
      "Use this when no passkey can sign you in. A code works once, then takes you to your account page to add a passkey.",
    recoveryHint: "One of your ten single-use codes. Dashes and spaces do not matter.",
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
  invite: {
    heading: "Join an organisation",
    invitedTo: (organisation: string, role: string) =>
      `You are invited to ${organisation} as ${role === "admin" ? "an" : "a"} ${role}.`,
    expires: "The link works once and expires",
    loading: "Reading the invitation",
    missingHeading: "No invitation in this link",
    missingBody:
      "This page needs the whole invitation link. Open the link you were sent, or ask for a new one.",
    unusableHeading: "This invitation link is not usable",
    unusableBody:
      "It may be wrong, already used, withdrawn or expired. Ask the person who invited you for a new one.",
    newIntro: "This browser will create the passkey you sign in with from now on.",
    displayNameLabel: "Display name",
    displayNameHint: "Shown to the other members of the organisation.",
    createButton: "Create passkey and join",
    joinIntro: "You are signed in. Join with the account you have.",
    joinButton: "Join",
    working: "Joining",
    joinedHeading: "You have joined",
    joinedBody: (organisation: string) =>
      `You are now a member of ${organisation}. Choose it in the header to see only its runs.`,
    continueLink: "Go to the dashboard",
    unsupported: "This browser has no passkey support, so you cannot join from it.",
    cancelled: "The passkey prompt was closed before it finished. Try again.",
    failed: "Joining failed",
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
    unnamedPasskey: "Unnamed passkey",
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

    /* RM-333 (#511) */
    summary:
      "Who you are on this deployment, what your role allows, the machines that record for your organisation, and where you are signed in.",
    identityLabel: "Identity",
    userIdLabel: "User ID",
    memberSince: "Member since",
    organisationLabel: "Organisation",
    roleLabel: "Role",
    noOrganisation: "Not a member of any organisation",
    operatorOrganisation: "Runs this deployment",
    copyUserId: "Copy user ID",
    copied: "Copied",
    roles: {
      owner: "Owner",
      admin: "Admin",
      member: "Member",
    },
    privilegesHeading: "What you can do",
    privilegesIntro: "What your role allows on this dashboard. The server checks every one of these.",
    privilegesAllowed: "Allowed",
    privilegesDenied: "Not allowed here",
    /** Decorative marks beside each item; hidden from screen readers, the
     * list headings carry the meaning. */
    privilegeAllowedMark: "\u2713",
    privilegeDeniedMark: "\u2013",
    privileges: {
      read_ledger: "Read runs, alerts and proofs",
      resolve_alerts: "Resolve alerts, confirmed with a passkey",
      manage_own_sign_in: "Manage your own passkeys, recovery codes and sign-ins",
      connect_machine: "Connect a machine",
      revoke_machine: "Revoke a machine",
      grant_repositories: "Grant repositories to the organisation",
      manage_members: "Add or remove members",
    },
    privilegeNotes: {
      connect_machine: "An owner or admin can.",
      revoke_machine: "An owner or admin can.",
      grant_repositories:
        "Done on the core host with innsegl accounts grant-repo. A repository is also claimed the first time a machine records for it.",
      manage_members: "Not on the dashboard yet.",
    },

    machinesHeading: "Machines",
    machinesIntro:
      "Client machines and runners enrolled for your organisation. A revoked machine can no longer record.",
    machineNameHeader: "Name",
    machineKindHeader: "Kind",
    machineStatusHeader: "Status",
    machineReposHeader: "Repositories",
    machineEnrolledHeader: "Enrolled",
    machineLastActiveHeader: "Last active",
    machineActionsHeader: "Actions",
    machineKind: {
      workstation: "Workstation",
      service: "Runner",
    },
    machineStatus: {
      active: "Active",
      suspended: "Suspended",
      revoked: "Revoked",
    },
    allRepositories: "All repositories",
    notYet: "Not yet",
    noMachines: "No machine is enrolled yet.",
    revokeButton: "Revoke",
    revokeConfirmPrompt: "Revoke this machine? It cannot record again. Your passkey confirms it.",
    revokeConfirmButton: "Revoke with passkey",
    revokeCancelButton: "Keep it",
    revokeWorking: "Waiting for your passkey",
    revokeFailed: "The machine could not be revoked",
    revokeNeedsRole: "Only an owner or admin can revoke",

    connectHeading: "Connect a machine",
    connectIntro:
      "Mints a single-use enrolment token after your passkey confirms it. The token is shown once and works for 15 minutes.",
    connectButton: "Continue with passkey",
    connectWorking: "Waiting for your passkey",
    connectFailed: "No token was minted",
    connectNeedsRole: "An owner or admin of the organisation can connect a machine.",
    connectOrganisationLabel: "Organisation",
    connectKindLabel: "What kind of machine?",
    connectKindHelp: {
      workstation: "A person's computer. Records the Claude Code sessions run on it.",
      service: "A CI runner or server. Records agents that run unattended.",
    },
    tokenLabel: "Enrolment token",
    tokenOnce: "Shown once. Copy it now; it cannot be shown again.",
    commandLabel: "Run this on the new machine",
    connectCaPlaceholder: "<core-ca.pem>",
    connectCaNote:
      "Replace <core-ca.pem> with a copy of the core's CA certificate. It is on the core host; install.sh prints its path.",
    expiresLabel: "Expires",
    copyToken: "Copy token",
    copyCommand: "Copy command",
    connectDone: "Done",

    repositoriesHeading: "Repositories",
    repositoriesIntro: "Repositories your organisation holds, with what the ledger recorded for each.",
    repoHeader: "Repository",
    repoRunsHeader: "Runs",
    repoCommitsHeader: "Commits",
    repoLastHeader: "Last activity",
    repoSinceHeader: "Held since",
    noRepositories: "Your organisation holds no repository yet.",
    nothingRecorded: "Nothing recorded",

    agentsHeading: "Agents",
    agentsIntro: "Agents that ran on your organisation's machines.",
    agentTypesHeading: "Agent types",
    agentTypeRuns: "runs",
    recentRunsHeading: "Recent agent runs",
    runHeader: "Run",
    runAgentHeader: "Agent type",
    runTaskHeader: "Task",
    runMachineHeader: "Machine",
    runStartedHeader: "Started",
    noAgents: "No run has been recorded through your organisation's machines yet.",

    spineUnavailable: "This deployment keeps no organisation records, so there is nothing to show here.",
    sectionFailed: "This section could not be loaded",

    addOpenButton: "Add a passkey",

    sessionsHeading: "Sign-ins",
    sessionsIntro: "Browsers signed in to this account now.",
    sessionStartedHeader: "Signed in",
    sessionExpiresHeader: "Expires",
    sessionMethodHeader: "With",
    sessionRecoveryCode: "A recovery code",
    sessionPasskey: (name: string) => (name === "" ? "A passkey" : `Passkey \u201c${name}\u201d`),
    thisBrowser: "This browser",
    signOutOthers: "Sign out other sign-ins",
    signOutOthersWorking: "Signing out",
    signedOutOthers: "Other sign-ins signed out:",
    noOtherSessions: "No other sign-in is open.",
  },
} as const;

export type AuthStrings = typeof strings;
