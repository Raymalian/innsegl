// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The organisation half of the account page (RM-333, #511, ADR-0062's
// 2026-10-03 amendment): which organisations the signed-in user belongs to,
// their machines and repositories, and the two changes a member with the
// right role makes from the dashboard — connecting a machine and revoking
// one. Members, roles and invitations (#480, #481) are the rest of it.
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
	// SuspendMachine and ResumeMachine move one installation between active
	// and suspended, audited with actor (#471). ErrMachineNotFound, or
	// ErrMachineRevoked for a revoked one.
	SuspendMachine(ctx context.Context, machineID, actor string) error
	ResumeMachine(ctx context.Context, machineID, actor string) error
	// MintEnrolmentToken mints a single-use enrolment token and answers its
	// plaintext, once. ErrOrgInvalid for a kind or repos list the spine
	// refuses.
	MintEnrolmentToken(ctx context.Context, accountID, actor, kind string, repos []string) (token string, expiresAt time.Time, err error)
	// FoundOperator creates the deployment's own organisation, with its
	// first user as owner, when there is none; it answers whether it did.
	FoundOperator(ctx context.Context) (bool, error)

	// Members answers an organisation's live members, oldest first (#480).
	Members(ctx context.Context, accountID string) ([]OrgMember, error)
	// SetRole gives a live member another role. ErrOrgForbidden when the
	// actor may not, ErrLastOwner when it would leave no owner,
	// ErrOrgNotFound for no such live member.
	SetRole(ctx context.Context, accountID, userID, role, actor string) error
	// RemoveMember ends a membership, revokes every session of the member
	// and suspends the active installations they created in the
	// organisation. Errors as SetRole's.
	RemoveMember(ctx context.Context, accountID, userID, actor string) (OrgRemoval, error)
	// Invitations answers an organisation's invitations, newest first
	// (#481). Never a code: only its hash is stored.
	Invitations(ctx context.Context, accountID string) ([]OrgInvitation, error)
	// CreateInvitation mints a single-use invitation and answers its code,
	// once. ErrOrgForbidden when the actor may not invite to that role.
	CreateInvitation(ctx context.Context, accountID, role, actor string) (code string, inv OrgInvitation, err error)
	// WithdrawInvitation withdraws a pending invitation, with actor's role
	// checked as creating one is. ErrOrgNotFound for no such pending
	// invitation, ErrOrgForbidden when the actor may not.
	WithdrawInvitation(ctx context.Context, accountID string, invitationID int64, actor string) error
	// PeekInvitation answers what a usable code invites to, spending
	// nothing. ErrInvitationInvalid for any code that is not usable.
	PeekInvitation(ctx context.Context, code string) (OrgInvitationPeek, error)
	// AcceptInvitation spends a code for an existing user.
	// ErrInvitationInvalid, or ErrAlreadyMember without spending it.
	AcceptInvitation(ctx context.Context, code, userID string) (OrgMembership, error)
	// AcceptInvitationAsNewUser spends a code for a user that create makes
	// in the same transaction: a failure leaves neither the user nor a
	// spent code.
	AcceptInvitationAsNewUser(ctx context.Context, code string, create func(q Querier) (userID string, err error)) (OrgMembership, error)
}

// Querier is the transaction AcceptInvitationAsNewUser lends to create.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
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
	CreatedBy     string
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

// OrgMember is one live member of an organisation.
type OrgMember struct {
	UserID      string
	DisplayName string
	Role        string
	Since       time.Time
}

// OrgRemoval is what removing a member changed.
type OrgRemoval struct {
	SessionsRevoked int
	Suspended       []string // installation ids
}

// Invitation states, as OrgInvitation.State spells them.
const (
	InvitationPending   = "pending"
	InvitationAccepted  = "accepted"
	InvitationWithdrawn = "withdrawn"
	InvitationExpired   = "expired"
)

// OrgInvitation is one invitation, without its code.
type OrgInvitation struct {
	ID         int64
	AccountID  string
	Role       string
	State      string
	CreatedBy  string // empty when the operator's CLI made it
	AcceptedBy string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// OrgInvitationPeek is what a usable code invites to.
type OrgInvitationPeek struct {
	AccountID   string
	AccountName string
	Role        string
	ExpiresAt   time.Time
}

// Errors an Organisations implementation answers.
var (
	ErrMachineNotFound = errors.New("api: no such machine")
	ErrMachineRevoked  = errors.New("api: the machine is already revoked")
	ErrOrgInvalid      = errors.New("api: the organisation refused that request")
	// ErrOrgForbidden: the actor's role does not allow the change (#480).
	ErrOrgForbidden = errors.New("api: your role in the organisation does not allow that")
	// ErrOrgNotFound: no such live member or invitation in the organisation.
	ErrOrgNotFound = errors.New("api: no such member or invitation in the organisation")
	// ErrLastOwner: the change would leave the organisation with no owner.
	ErrLastOwner = errors.New("api: an organisation keeps at least one owner")
	// ErrAlreadyMember: the user already holds a live membership.
	ErrAlreadyMember = errors.New("api: already a member of this organisation")
	// ErrInvitationInvalid is the one answer for a code that is malformed,
	// unknown, expired, withdrawn or already used: telling them apart would
	// be an oracle.
	ErrInvitationInvalid = errors.New("api: that invitation link is not usable")
)

// Roles, spelled as migration 0010's CHECK spells them.
const (
	roleOwner  = "owner"
	roleAdmin  = "admin"
	roleMember = "member"
)

// Privilege actions. The dashboard renders each listed one; the handlers
// below and internal/accounts' Authorise gate on the same table.
const (
	PrivilegeReadLedger        = "read_ledger"
	PrivilegeResolveAlerts     = "resolve_alerts"
	PrivilegeManageOwnSignIn   = "manage_own_sign_in"
	PrivilegeConnectMachine    = "connect_machine"
	PrivilegeRevokeMachine     = "revoke_machine"
	PrivilegeGrantRepositories = "grant_repositories"
	PrivilegeManageMembers     = "manage_members"
	// The owner's alone, and not listed on the account page until the
	// dashboard shows them (E28): giving or taking the owner role, and
	// erasing the organisation.
	PrivilegeManageOwners      = "manage_owners"
	PrivilegeEraseOrganisation = "erase_organisation"
)

// privilegeActions is the order the page lists them in.
var privilegeActions = []string{
	PrivilegeReadLedger, PrivilegeResolveAlerts, PrivilegeManageOwnSignIn,
	PrivilegeConnectMachine, PrivilegeRevokeMachine,
	PrivilegeGrantRepositories, PrivilegeManageMembers,
}

// roleMay answers whether a role may take an action. It is the one table
// (Authorization E1): rolePrivileges lists it, this package's handlers and
// internal/accounts' Authorise gate on it. It scopes the account surface
// only: nothing an agent does is refused because of a role.
//
//	owner   everything, including the owner role and erasing the organisation
//	admin   members other than owners, and every machine
//	member  read, and connecting machines of their own (revoking their own
//	        machine is the handlers' own-machine rule, not a privilege)
//
// Reading the ledger, resolving alerts and managing one's own passkeys,
// recovery codes and sign-ins need only a session (and, for a resolution, a
// fresh passkey), whatever the role. Repositories are granted by first use
// or with `innsegl accounts grant-repo` on the core host, by no role on the
// dashboard.
func roleMay(role, action string) bool {
	switch action {
	case PrivilegeReadLedger, PrivilegeResolveAlerts, PrivilegeManageOwnSignIn, PrivilegeConnectMachine:
		return role == roleOwner || role == roleAdmin || role == roleMember
	case PrivilegeRevokeMachine, PrivilegeManageMembers:
		return role == roleOwner || role == roleAdmin
	case PrivilegeManageOwners, PrivilegeEraseOrganisation:
		return role == roleOwner
	default:
		return false
	}
}

// RoleMay is roleMay for internal/accounts, which checks the same table.
func RoleMay(role, action string) bool { return roleMay(role, action) }

// rolePrivileges lists every action with whether role may take it.
func rolePrivileges(role string) []Privilege {
	out := make([]Privilege, len(privilegeActions))
	for i, a := range privilegeActions {
		out[i] = Privilege{Action: a, Allowed: roleMay(role, a)}
	}
	return out
}
