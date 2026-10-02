// SPDX-License-Identifier: Apache-2.0

package clientjournal

// ImportPath is the core's import endpoint, behind the client-certificate
// guard.
const ImportPath = "/_core/journal"

// ImportRequest is the body of POST ImportPath: entries in sequence order.
type ImportRequest struct {
	Entries []Sealed `json:"entries"`
}

// ImportResponse answers one result per entry processed, in order. Entries
// after a rejected or retried one are not processed and get no result.
type ImportResponse struct {
	Results []ImportResult `json:"results"`
}

// ImportResult is the core's answer for one entry.
type ImportResult struct {
	Hash   string `json:"hash"`
	Seq    uint64 `json:"seq"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// Import statuses. The client deletes an entry answered recorded, duplicate
// or stored, and keeps one answered rejected or retry.
const (
	// ImportRecorded: verified, recorded under a run, stored.
	ImportRecorded = "recorded"
	// ImportDuplicate: this entry was imported before; nothing was done.
	ImportDuplicate = "duplicate"
	// ImportStored: verified and stored on the core as evidence, but not
	// recorded under a run; Reason says why (a repository the installation
	// may not record, a refusal of the replayed request).
	ImportStored = "stored"
	// ImportRejected: the signature, the installation or the chain does not
	// verify. Kept on the client for inspection; nothing after it imports.
	ImportRejected = "rejected"
	// ImportRetry: the core could not finish now (a dependency outage);
	// nothing was stored. The same entry is sent again later.
	ImportRetry = "retry"
)

// Acknowledged reports whether the client may delete an entry answered s.
func Acknowledged(status string) bool {
	return status == ImportRecorded || status == ImportDuplicate || status == ImportStored
}
