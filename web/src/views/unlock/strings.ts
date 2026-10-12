// SPDX-License-Identifier: Apache-2.0

/*
 * Every user-visible string of the unlock-key section, the unlock page and
 * the banner (#616). doc 06 §6.1: factual, specific, no exclamation marks.
 */

export const strings = {
  section: {
    heading: "Unlock keys",
    intro:
      "Hardware security keys that can unlock the CA key store from this dashboard when the operator machine is away. Every use needs the key's PIN and a touch. Synced passkeys cannot be unlock keys.",
    activationNote:
      "A new key stays pending until a reseal adds it to the set the unlock material is sealed to. Until one key is active, add it from the operator machine:",
    activationCommand: (recipient: string) => `innsegl ca-custody reseal --add ${recipient}`,
    activationPlaceholder: "<custody recipient>",
    copyCommand: "Copy command",
    custodyOff:
      "CA custody is off on this core. Keys can be enrolled, but none can unlock until custody is on.",
    custodyUnreachable: "The custodian is not answering, so each key's state is unknown.",
    empty: "No unlock keys yet.",
    loading: "Loading the unlock keys",
    loadFailed: "The unlock keys could not be loaded",
    labelHeader: "Key",
    stateHeader: "State",
    fingerprintHeader: "Custody recipient",
    addedHeader: "Added",
    lastUsedHeader: "Last used",
    actionsHeader: "Actions",
    neverUsed: "Never",
    ownerOf: (owner: string) => `Enrolled by ${owner}`,
    states: {
      pending: "Pending",
      active: "Active",
      revoked: "Revoked",
      unknown: "Unknown",
    } as Readonly<Record<string, string>>,
    revokeButton: "Revoke",
    revokeConfirmPrompt:
      "Revoke this key? It leaves the set at the next reseal. Copies sealed to it earlier still open with it. Your passkey confirms it.",
    revokeConfirmButton: "Revoke with passkey",
    revokeCancelButton: "Keep it",
    revokeWorking: "Waiting for your passkey",
    revokeFailed: "The key could not be revoked",
    addOpenButton: "Add a security key",
    addLabel: "Name for this key",
    addLabelHint: "1 to 64 characters, such as the place it is kept.",
    addSteps:
      "Your sign-in passkey confirms it is you. Then touch the security key twice and enter its PIN each time.",
    addButton: "Add the key",
    addWorking: "Waiting for your passkey and security key",
    cancelButton: "Cancel",
    addedNotice:
      "Added. The key is pending until a reseal applies it.",
    addFailed: "The security key could not be added",
    defaultLabel: (n: number) => `Security key ${n}`,
  },
  support: {
    webkit:
      "This browser cannot use a security key's PRF yet, which unlocking needs. Use Chrome, Edge or Firefox.",
    none: "This browser has no WebAuthn, so it cannot use a security key. Use Chrome, Edge or Firefox.",
    noPRF:
      "This browser or security key returned no PRF (hmac-secret), so it cannot unlock. Nothing was saved or sent to the core. Use Chrome, Edge or Firefox with a FIDO2 key that has hmac-secret.",
    cancelled: "The prompt was closed before it finished. Try again.",
  },
  banner: {
    title: "The CA cannot sign",
    body: "The CA key store is locked, so the core issues no signing certificates until it is unlocked.",
    reason: (reason: string) => `The custodian says: ${reason}`,
    action: "Unlock with a security key",
  },
  unlock: {
    heading: "Unlock the CA key store",
    intro:
      "Touch one of your active unlock keys and enter its PIN. This browser opens the sealed unlock material with the key and sends the material to the core once. The key's secret never leaves this browser.",
    button: "Unlock with a security key",
    working: "Waiting for your security key",
    done: "Unlocked. The CA can sign again.",
    doneButStill: "The unlock was accepted, but the CA still cannot sign.",
    notSealed:
      "The sealed material is not sealed to this key. A new key is pending until a reseal applies it.",
    failed: "The CA key store could not be unlocked",
    close: "Close",
  },
} as const;
