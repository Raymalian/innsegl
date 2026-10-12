// SPDX-License-Identifier: Apache-2.0

//go:build !(darwin && cgo)

package client

// platformVault is nil: there is no hardware key store in this build. Linux
// keeps the machine key as a 0600 file (a TPM is not used yet), and so does
// a macOS build made without cgo, such as a cross-compiled release binary.
func platformVault() keyVault { return nil }
