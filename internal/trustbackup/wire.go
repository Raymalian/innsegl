// SPDX-License-Identifier: Apache-2.0

package trustbackup

// The core's routes for the operator's enrolled machine (ADR-0074), behind
// the client certificate.
const (
	// CorePath lists the kept bundles and the producer's last run, as a
	// Listing.
	CorePath = "/_core/trust-backup"
	// CoreLatestPath is the newest bundle's ciphertext, named and checksummed
	// in the two headers below.
	CoreLatestPath = "/_core/trust-backup/latest"

	HeaderName   = "X-Innsegl-Trust-Backup-Name"
	HeaderSHA256 = "X-Innsegl-Trust-Backup-Sha256"
)

// Listing is the answer of GET CorePath.
type Listing struct {
	Bundles []Entry `json:"bundles"`
	// Status is the producer's last run; absent when it has written none.
	Status *Status `json:"status,omitempty"`
}
