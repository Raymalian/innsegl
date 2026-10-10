// SPDX-License-Identifier: Apache-2.0

package api

import "time"

// The account contract (#445, ADR-0062's 2026-10-01 amendment): a person's
// own account — the setup link that creates it, the passkeys they manage,
// and the recovery codes that get them back in. web/src/views/auth/types.ts
// mirrors these member for member.

// SetupStatus answers GET /api/v1/auth/setup, without a session: whether an
// account still needs creating (no passkey exists yet).
type SetupStatus struct {
	Needed bool `json:"needed"`
}

// EnrolFinished answers POST /api/v1/auth/enrol/finish: the session it
// opened, and the account's first ten recovery codes, shown once.
type EnrolFinished struct {
	Authenticated bool     `json:"authenticated"`
	DisplayName   string   `json:"display_name"`
	RecoveryCodes []string `json:"recovery_codes"`
}

// RecoverRequest is POST /api/v1/auth/recover's body: one recovery code.
type RecoverRequest struct {
	Code string `json:"code"`
}

// RecoverResult answers it: the session it opened, and how many codes are
// left.
type RecoverResult struct {
	Authenticated bool   `json:"authenticated"`
	DisplayName   string `json:"display_name"`
	Remaining     int    `json:"remaining"`
}

// Account answers GET /api/v1/account.
type Account struct {
	UserID                 string           `json:"user_id"`
	DisplayName            string           `json:"display_name"`
	CreatedAt              time.Time        `json:"created_at"`
	Passkeys               []AccountPasskey `json:"passkeys"`
	RecoveryCodesRemaining int              `json:"recovery_codes_remaining"`
	// Organisations is every organisation the user holds a live membership
	// in (RM-333, #511). Empty, never null.
	Organisations []AccountOrganisation `json:"organisations"`
	// SignIns is every organisation sign-in linked to the account (#485).
	// Empty, never null.
	SignIns []AccountSignIn `json:"sign_ins"`
}

// AccountPasskey is one passkey on the account. Current is the one this
// session signed in with; false when it signed in with a recovery code.
type AccountPasskey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	Current    bool       `json:"current"`
}

// AccountUpdate is PATCH /api/v1/account's body.
type AccountUpdate struct {
	DisplayName string `json:"display_name"`
}

// PasskeyBeginRequest is POST /api/v1/account/passkeys/begin's body: the name
// the new passkey will carry. The answer is the same ceremonyResponse
// enrolment returns; .../finish takes the same finishRequest and answers the
// AccountPasskey it added.
type PasskeyBeginRequest struct {
	Name string `json:"name"`
}

// PasskeyRename is PATCH /api/v1/account/passkeys/{id}'s body.
type PasskeyRename struct {
	Name string `json:"name"`
}

// RecoveryCodes answers POST /api/v1/account/recovery-codes: ten new codes,
// shown once; every earlier code is void.
type RecoveryCodes struct {
	Codes []string `json:"codes"`
}

// ---------------------------------------------------------------------------
// RM-333 (#511): the organisation, its machines, repositories and agents,
// and the person's own sign-ins. ADR-0062's 2026-10-03 amendment.
// ---------------------------------------------------------------------------

// AccountOrganisation is one organisation the signed-in user holds a live
// membership in, with the role and what that role may do.
type AccountOrganisation struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Role       string      `json:"role"`
	Operator   bool        `json:"operator"`
	Privileges []Privilege `json:"privileges"`
}

// Privilege is one action and whether the role may take it on the
// dashboard. The list is rolePrivileges's, and the handlers that gate an
// action read the same table, so the page cannot claim a permission the
// server does not enforce.
type Privilege struct {
	Action  string `json:"action"`
	Allowed bool   `json:"allowed"`
}

// AccountMachine is one installation (a client machine or a CI runner) of an
// organisation the user belongs to.
//
// LastRenewedAt is when the machine last renewed its certificate; LastRunAt
// is when a run was last mapped to it at the gateway. Either is null when it
// never happened. Nothing else records when a machine was last seen.
type AccountMachine struct {
	ID             string     `json:"id"`
	OrganisationID string     `json:"organisation_id"`
	Organisation   string     `json:"organisation"`
	Name           string     `json:"name"`
	Kind           string     `json:"kind"`
	Status         string     `json:"status"`
	Repos          []string   `json:"repos"`
	EnrolledAt     time.Time  `json:"enrolled_at"`
	LastRenewedAt  *time.Time `json:"last_renewed_at"`
	LastRunAt      *time.Time `json:"last_run_at"`
	RevokedAt      *time.Time `json:"revoked_at"`
	CanManage      bool       `json:"can_manage"`
}

// AccountMachines answers GET /api/v1/account/machines.
type AccountMachines struct {
	Machines []AccountMachine `json:"machines"`
	// CAFingerprint is the core's CA as `innsegl connect --ca-fingerprint`
	// takes it ("sha256:<hex>"), or empty when this API cannot read it.
	CAFingerprint string `json:"ca_fingerprint"`
}

// MachineRevokeRequest is POST /api/v1/account/machines/revoke/begin's body.
// The answer is a passkey request challenge; .../finish takes the same
// finishRequest every ceremony takes and answers the revoked AccountMachine.
type MachineRevokeRequest struct {
	MachineID string `json:"machine_id"`
}

// EnrolmentTokenRequest is POST /api/v1/account/enrolment-tokens/begin's
// body. Kind defaults to workstation and Repos to ["*"].
type EnrolmentTokenRequest struct {
	OrganisationID string   `json:"organisation_id"`
	Kind           string   `json:"kind"`
	Repos          []string `json:"repos"`
}

// EnrolmentToken answers .../enrolment-tokens/finish. Token is the plaintext,
// shown once: the server keeps only its hash and never logs it.
type EnrolmentToken struct {
	Token          string    `json:"token"`
	ExpiresAt      time.Time `json:"expires_at"`
	OrganisationID string    `json:"organisation_id"`
	Kind           string    `json:"kind"`
	Repos          []string  `json:"repos"`
}

// AccountSession is one live sign-in of the user. ID is a short, stable
// label derived from the stored hash; it opens nothing. PasskeyName is null
// for a sign-in a recovery code opened.
type AccountSession struct {
	ID          string    `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Current     bool      `json:"current"`
	PasskeyName *string   `json:"passkey_name"`
	// OrganisationSignIn names the organisation whose identity provider
	// opened this session (#485); null for a passkey or recovery code.
	OrganisationSignIn *string `json:"organisation_sign_in"`
}

// AccountSessions answers GET /api/v1/account/sessions.
type AccountSessions struct {
	Sessions []AccountSession `json:"sessions"`
}

// SignedOut answers POST /api/v1/account/sessions/sign-out-others.
type SignedOut struct {
	SignedOut int `json:"signed_out"`
}

// AccountRepository is one repository an organisation of the user holds a
// live grant on, with what the ledger recorded for it. LastEventAt is null
// when the ledger holds nothing for it yet.
type AccountRepository struct {
	Repo           string     `json:"repo"`
	OrganisationID string     `json:"organisation_id"`
	Organisation   string     `json:"organisation"`
	Since          time.Time  `json:"since"`
	Runs           int        `json:"runs"`
	Commits        int        `json:"commits"`
	LastEventAt    *time.Time `json:"last_event_at"`
	// Held is whether the core holds a copy of this repository in its mirror
	// (ADR-0065). False until a client pushes it: its commits cannot be
	// proved here yet, and that is what the page says rather than a 404.
	Held bool `json:"held"`
}

// AccountRepositories answers GET /api/v1/account/repositories.
type AccountRepositories struct {
	Repositories []AccountRepository `json:"repositories"`
}

// AccountAgentType is one agent type that ran through the organisation's
// machines, with how many runs and when the last one registered.
type AccountAgentType struct {
	AgentType        string    `json:"agent_type"`
	Runs             int       `json:"runs"`
	LastRegisteredAt time.Time `json:"last_registered_at"`
}

// AccountAgentRun is one recent run mapped to one of the organisation's
// machines at the gateway.
type AccountAgentRun struct {
	RunID        string    `json:"run_id"`
	AgentType    string    `json:"agent_type"`
	TaskRef      string    `json:"task_ref"`
	RegisteredAt time.Time `json:"registered_at"`
	MachineID    string    `json:"machine_id"`
	MachineName  string    `json:"machine_name"`
}

// AccountAgents answers GET /api/v1/account/agents.
type AccountAgents struct {
	AgentTypes []AccountAgentType `json:"agent_types"`
	RecentRuns []AccountAgentRun  `json:"recent_runs"`
}
