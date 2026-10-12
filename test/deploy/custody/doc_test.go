// SPDX-License-Identifier: Apache-2.0

// Package custody measures CA custody, the trust root and the dev stack's
// separate names. It is split from test/deploy to keep each package well
// inside go test's -timeout (deploytest's package comment says why).
package custody
