// SPDX-License-Identifier: Apache-2.0

package cacustody

import "time"

// The core's routes, for the operator's enrolled machine (ADR-0076).
const (
	// CorePath answers CoreStatus.
	CorePath = "/_core/ca-custody"
	// CoreMaterialPath is the sealed unlock material.
	CoreMaterialPath = "/_core/ca-custody/material"
	// CoreUnlockPath takes the opened material, by POST.
	CoreUnlockPath = "/_core/ca-custody/unlock"
	// CoreResealPath stages a reseal, by POST (ADR-0082 decision 7).
	CoreResealPath = "/_core/ca-custody/reseal"
	// CoreResealConfirmPath confirms it, by POST.
	CoreResealConfirmPath = "/_core/ca-custody/reseal/confirm"
	// CoreRecipientsPath lists the set the material is sealed to.
	CoreRecipientsPath = "/_core/ca-custody/recipients"
)

// ResealRequest starts a reseal: the material the opener opened, the
// opener's own recipient, the set to seal to, and SetDigest of the set the
// operator confirmed.
type ResealRequest struct {
	Material   Material `json:"material"`
	Opener     string   `json:"opener_recipient"`
	Recipients []string `json:"recipients"`
	SetDigest  string   `json:"set_digest"`
}

// ResealStaged is the staged copy, for the opener to open, and the set it
// is sealed to. It is applied only by a confirm before ExpiresAt.
type ResealStaged struct {
	Sealed     []byte    `json:"sealed"`
	Recipients []string  `json:"recipients"`
	SetDigest  string    `json:"set_digest"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// ResealConfirm applies a staged copy: what OpenStaged read from it, and
// the set's digest again.
type ResealConfirm struct {
	Material  Material `json:"material"`
	Check     string   `json:"check"`
	SetDigest string   `json:"set_digest"`
}

// RecipientSet is the set the material is sealed to. Recorded false is a
// store initialised before the reseal existed: the set is the configured one.
type RecipientSet struct {
	Recipients []string `json:"recipients"`
	Digest     string   `json:"digest"`
	Recorded   bool     `json:"recorded"`
}

// CoreStatus is the core's answer on CorePath. Enabled false is a core that
// keeps its CA key in a file.
type CoreStatus struct {
	Enabled     bool `json:"enabled"`
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
	// CanSign and Reason are the custodian's Status, passed through.
	CanSign bool   `json:"can_sign"`
	Reason  string `json:"reason,omitempty"`
	Error   string `json:"error,omitempty"`
	// TokenSecondsLeft is how long the CA's token has left, read from the
	// store (#601). Zero when unknown; a read-only field.
	TokenSecondsLeft int64 `json:"token_seconds_left,omitempty"`
}
