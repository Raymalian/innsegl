// SPDX-License-Identifier: Apache-2.0

// Package objectstore measures the shipped object-store provisioning: what the
// scoped store identity may and may not do to the bucket, and that only the
// gateway reaches the Filer. It is split from test/deploy to keep each package
// well inside go test's -timeout (deploytest's package comment says why).
package objectstore
