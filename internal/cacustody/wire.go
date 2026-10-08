// SPDX-License-Identifier: Apache-2.0

package cacustody

// The core's routes, for the operator's enrolled machine (ADR-0076).
const (
	// CorePath answers CoreStatus.
	CorePath = "/_core/ca-custody"
	// CoreMaterialPath is the sealed unlock material.
	CoreMaterialPath = "/_core/ca-custody/material"
	// CoreUnlockPath takes the opened material, by POST.
	CoreUnlockPath = "/_core/ca-custody/unlock"
)

// CoreStatus is the core's answer on CorePath. Enabled false is a core that
// keeps its CA key in a file.
type CoreStatus struct {
	Enabled      bool   `json:"enabled"`
	Initialized  bool   `json:"initialized"`
	Sealed       bool   `json:"sealed"`
	TokenPresent bool   `json:"token_present"`
	Error        string `json:"error,omitempty"`
}
