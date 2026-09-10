// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// The per-run secret that makes a run_id insufficient.
//
// # What it closes
//
// get_credential mints a JWT-SVID for whatever run_id it is handed. It does not
// go through SPIFFE workload attestation — it calls SPIRE's admin mint API — so
// the Docker selectors on the entry are not the control. The only control was
// the listener's bind address, and `run_id` is not a secret: it is printed in
// the Agent-Run trailer of every commit, shown on the dashboard, and returned by
// the query API. Any process that could reach the MCP could mint any agent's
// credential by reading a run id off a commit.
//
// A run token is handed to the agent ONCE, at registration, and required
// thereafter. Knowing the public run id is then not enough.
//
// # Why it is derived rather than stored
//
// HMAC over the run id under a server-held secret. Nothing is persisted, so
// there is no table to migrate, no row to leak and no schema change to a
// protected surface (doc 02). The server can always recompute the token for a
// run it is asked about, and a caller cannot, which is the whole property.
//
// The label is domain separation: the same secret used for anything else
// produces different bytes here, so a token can never be mistaken for, or
// derived from, another use of the key.
// PUBLIC by design, and not a credential: it is the domain-separation label
// mixed into the MAC, so the same secret used elsewhere cannot produce a run
// token and a run token cannot be replayed into another use of the key. The
// security is in the secret; publishing this changes nothing.
const runTokenLabel = "innsegl:run-token:v1\x00" //nolint:gosec // G101: a domain-separation label, not a secret

// RunToken is the token for one run under one secret. An empty secret yields an
// empty token, which is how a deployment with no secret configured is told
// apart from one whose token did not match.
func RunToken(secret, runID string) string {
	if secret == "" || runID == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(runTokenLabel))
	mac.Write([]byte(runID))
	return hex.EncodeToString(mac.Sum(nil))
}

// RunTokenValid reports whether presented is the token for runID.
//
// Constant time, and false for an empty presented token even when the secret is
// empty: "no secret configured" is a decision for the caller to make once, at
// wiring, and never a comparison that happens to pass.
func RunTokenValid(secret, runID, presented string) bool {
	want := RunToken(secret, runID)
	if want == "" || presented == "" {
		return false
	}
	return hmac.Equal([]byte(want), []byte(presented))
}
