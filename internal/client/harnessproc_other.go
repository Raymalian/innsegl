// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package client

// readProc reads nothing here: sessions on this platform end by their hook
// or by the silence backstop.
func readProc(int) (procInfo, bool) { return procInfo{}, false }
