// SPDX-License-Identifier: Apache-2.0

/*
 * The account contract (#445): internal/api/account.go, member for member.
 */

export interface SetupStatus {
  needed: boolean;
}

export interface EnrolFinished {
  authenticated: boolean;
  display_name: string;
  /** The account's first ten recovery codes, shown once. */
  recovery_codes: string[];
}

export interface RecoverResult {
  authenticated: boolean;
  display_name: string;
  remaining: number;
}

export interface AccountPasskey {
  id: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
  /** The passkey this session signed in with. */
  current: boolean;
}

export interface Account {
  user_id: string;
  display_name: string;
  created_at: string;
  passkeys: AccountPasskey[];
  recovery_codes_remaining: number;
}

export interface RecoveryCodes {
  codes: string[];
}
