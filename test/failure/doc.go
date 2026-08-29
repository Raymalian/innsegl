// SPDX-License-Identifier: Apache-2.0

// Package failure holds the cross-component failure-injection suite: the
// layer-F cases of doc 07 that cannot live inside the package they are about,
// because proving them means pulling a dependency out from under it.
//
// It has no production code and never will. The file you are reading exists so
// that `go build ./...` has something to build in this directory; everything
// else here is a _test.go file.
//
// The cases are named for their doc 07 test IDs. Today: SPI-006 and SPI-007
// (RM-018, #26), which kill a real SPIRE server and a real SPIRE agent and
// assert what IP §6.1 requires of the MCP when identity is unavailable.
package failure
