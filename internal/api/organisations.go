// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"time"
)

// The organisation half of the account page (RM-333, #511, ADR-0062's
// 2026-10-03 amendment): which organisations the signed-in user belongs to,
// their machines and repositories, and the two changes a member with the
// right role makes from the dashboard — connecting a machine and revoking
// one.
//
// The accounts spine lives in internal/accounts, which imports this package
// (for AssertCannotWriteLedger), so this package names what it needs as an
// interface and internal/accounts.Store implements it. Both connect as the
// auth-writer role; nothing here touches the ledger's schema.

// Organisations is the accounts spine as the account page reads and changes
// it.
type Organisations interface {
	// Memberships answers the user's LIVE memberships, oldest first.
	Memberships(ctx context.Context, userID string) ([]OrgMembership, error)
	// Machines answers every installation of the named organisations,
	// oldest first.
	Machines(ctx context.Context, accountIDs []string) ([]OrgMachine, error)
	// RepoGrants answers the live repository grants of the named
	// organisations, by repository.
	RepoGrants(ctx context.Context, accountIDs []string) ([]OrgRepoGrant, error)
	// RevokeMachine revokes one installation for good, audited with actor.
	// ErrMachineNotFound or ErrMachineRevoked when it cannot.
	RevokeMachine(ctx context.Context, machineID, actor string) error
	// MintEnrolmentToken mints a single-use enrolment token and answers its
	// plaintext, once. ErrOrgInvalid for a kind or repos list the spine
	// refuses.
	MintEnrolmentToken(ctx context.Context, accountID, actor, kind string, repos []string) (token string, expiresAt time.Time, err error)
	// FoundOperator creates the deployment's own organisation, with its
	// first user as owner, when there is none; it answers whether it did.
	FoundOperator(ctx context.Context) (bool, error)
}

// OrgMembership is one live membership.
type OrgMembership struct {
	AccountID string
	Name      string
	Operator  bool
	Role      string
}

// OrgMachine is one installation.
type OrgMachine struct {
	ID            string
	AccountID     string
	Name          string
	Kind          string
	Repos         []string
	Status        string
	CreatedAt     time.Time
	LastRenewedAt *time.Time
	RevokedAt     *time.Time
}

// OrgRepoGrant is one live repository grant.
type OrgRepoGrant struct {
	AccountID string
	Repo      string
	Since     time.Time
}

// Errors an Organisations implementation answers.
var (
	ErrMachineNotFound = errors.New("api: no such machine")
	ErrMachineRevoked  = errors.New("api: the machine is already revoked")
	ErrOrgInvalid      = errors.New("api: the organisation refused that request")
)

// Roles, spelled as migration 0010's CHECK spells them.
const (
	roleOwner  = "owner"
	roleAdmin  = "admin"
	roleMember = "member"
)

// Privilege actions. The dashboard renders each one; the handlers below gate
// on the same table.
const (
	PrivilegeReadLedger        = "read_ledger"
	PrivilegeResolveAlerts     = "resolve_alerts"
	PrivilegeManageOwnSignIn   = "manage_own_sign_in"
	PrivilegeConnectMachine    = "connect_machine"
	PrivilegeRevokeMachine     = "revoke_machine"
	PrivilegeGrantRepositories = "grant_repositories"
	PrivilegeManageMembers     = "manage_members"
)

// privilegeActions is the order the page lists them in.
var privilegeActions = []string{
	PrivilegeReadLedger, PrivilegeResolveAlerts, PrivilegeManageOwnSignIn,
	PrivilegeConnectMachine, PrivilegeRevokeMachine,
	PrivilegeGrantRepositories, PrivilegeManageMembers,
}

// roleMay answers whether a role may take an action on the dashboard. It is
// the one table: rolePrivileges lists it and the mint and revoke handlers
// gate on it.
//
// Reading the ledger, resolving alerts and managing one's own passkeys,
// recovery codes and sign-ins need only a session (and, for a resolution, a
// fresh passkey), whatever the role. Connecting and revoking machines need
// owner or admin. Granting repositories and managing members are not on the
// dashboard for any role: repositories are granted by first use or with
// `innsegl accounts grant-repo` on the core host, and members are not
// managed anywhere yet.
func roleMay(role, action string) bool {
	switch action {
	case PrivilegeReadLedger, PrivilegeResolveAlerts, PrivilegeManageOwnSignIn:
		return role == roleOwner || role == roleAdmin || role == roleMember
	case PrivilegeConnectMachine, PrivilegeRevokeMachine:
		return role == roleOwner || role == roleAdmin
	default:
		return false
	}
}

// rolePrivileges lists every action with whether role may take it.
func rolePrivileges(role string) []Privilege {
	out := make([]Privilege, len(privilegeActions))
	for i, a := range privilegeActions {
		out[i] = Privilege{Action: a, Allowed: roleMay(role, a)}
	}
	return out
}
