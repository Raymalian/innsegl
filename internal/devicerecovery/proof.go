// SPDX-License-Identifier: Apache-2.0

// Package devicerecovery defines the device proof signed for certificate recovery.
package devicerecovery

import "encoding/json"

// RecoveryMessage binds device proof to one core, operation and exact CSR.
func Message(origin, id, challenge, csr string) []byte {
	b, err := json.Marshal(struct {
		Version      string `json:"version"`
		Origin       string `json:"origin"`
		Installation string `json:"installation_id"`
		Operation    string `json:"operation"`
		Challenge    string `json:"challenge"`
		CSR          string `json:"csr"`
	}{"innsegl recovery v1", origin, id, "recover", challenge, csr})
	if err != nil {
		panic(err)
	} // All fields are strings; encoding cannot fail.
	return b
}
