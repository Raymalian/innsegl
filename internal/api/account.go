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
