// SPDX-License-Identifier: Apache-2.0

// Package deploytest holds the container harnesses and compose helpers that
// the test/deploy packages share: a real Postgres carrying the shipped ledger
// scripts, a real object store, and the interpolated compose files.
//
// It exists because test/deploy outgrew one go test binary. Its container
// tests ran 372s alone and past the ten-minute -timeout on a loaded CI runner
// (PR #620), so they were split into ledgerdb, objectstore, lifecycle and
// custody, which run as separate packages and so in parallel. What they share
// lives here, once.
package deploytest
