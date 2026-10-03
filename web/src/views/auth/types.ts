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
  /** RM-333 (#511): every organisation the user holds a live membership in. */
  organisations: AccountOrganisation[];
}

/* ── RM-333 (#511): the organisation, its machines, repositories and agents,
 * and the person's own sign-ins. internal/api/account.go, member for member. */

export type Role = "owner" | "admin" | "member";

/** The action keys rolePrivileges answers. An unknown key is shown as it
 * arrives rather than dropped. */
export type PrivilegeAction =
  | "read_ledger"
  | "resolve_alerts"
  | "manage_own_sign_in"
  | "connect_machine"
  | "revoke_machine"
  | "grant_repositories"
  | "manage_members";

export interface Privilege {
  action: string;
  allowed: boolean;
}

export interface AccountOrganisation {
  id: string;
  name: string;
  role: string;
  operator: boolean;
  privileges: Privilege[];
}

export interface AccountMachine {
  id: string;
  organisation_id: string;
  organisation: string;
  name: string;
  kind: string;
  status: string;
  repos: string[];
  enrolled_at: string;
  /** When the machine last renewed its certificate. */
  last_renewed_at: string | null;
  /** When a run was last mapped to it at the gateway. */
  last_run_at: string | null;
  revoked_at: string | null;
  can_manage: boolean;
}

/** `GET /api/v1/account/machines`: the machines, and the core's CA
 * fingerprint as `innsegl connect --ca-fingerprint` takes it ("" when the
 * API cannot read it). */
export interface AccountMachines {
  readonly machines: AccountMachine[];
  readonly ca_fingerprint: string;
}

export interface EnrolmentToken {
  token: string;
  expires_at: string;
  organisation_id: string;
  kind: string;
  repos: string[];
}

export interface AccountSession {
  id: string;
  created_at: string;
  expires_at: string;
  current: boolean;
  /** Null for a sign-in a recovery code opened. */
  passkey_name: string | null;
}

export interface AccountRepository {
  repo: string;
  organisation_id: string;
  organisation: string;
  since: string;
  runs: number;
  commits: number;
  last_event_at: string | null;
}

export interface AccountAgentType {
  agent_type: string;
  runs: number;
  last_registered_at: string;
}

export interface AccountAgentRun {
  run_id: string;
  agent_type: string;
  task_ref: string;
  registered_at: string;
  machine_id: string;
  machine_name: string;
}

export interface AccountAgents {
  agent_types: AccountAgentType[];
  recent_runs: AccountAgentRun[];
}

export interface RecoveryCodes {
  codes: string[];
}
