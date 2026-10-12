// SPDX-License-Identifier: Apache-2.0

// Package lifecycle measures how the stack starts and updates: inputs that
// recreate their readers, bring-up that fails when a service does not come up,
// the settings an update records, update signing and the core's container
// name. It is split from test/deploy to keep each package well inside go
// test's -timeout (deploytest's package comment says why).
package lifecycle
