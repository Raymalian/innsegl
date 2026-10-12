// SPDX-License-Identifier: Apache-2.0

// Package ledgerdb measures the ledger database the reference deployment
// provisions: the append-only, reader and resolver roles, the API's grants,
// and the move of service credentials, against a real Postgres and the pinned
// MySQL. It is split from test/deploy to keep each package well inside go
// test's -timeout (deploytest's package comment says why).
package ledgerdb
