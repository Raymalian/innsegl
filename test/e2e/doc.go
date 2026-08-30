// SPDX-License-Identifier: Apache-2.0

// Package e2e holds doc 07's TC-GH cases: the two halves of I6, the one
// invariant this system cannot prove with cryptography.
//
//	I6: No GitHub contributor is ever added. Commit author is the human
//	operator or a deliberately unlinked address; agent identity lives only in
//	trailers + signature. Never emit `Co-authored-by:` with a resolvable
//	account.
//
// Every other invariant is settled by an artefact — a hash chain, a Merkle
// root, a Fulcio certificate, a Rekor entry. I6 is settled by GitHub's
// behaviour, which is neither ours nor stable. So it is enforced twice, from
// opposite directions, and the two halves are not interchangeable:
//
//   - GH-002 (C) is a gate over commits that already exist in this repository.
//     It asks OUR question — signing.AuthorPolicy.CheckAuthor, the same call
//     sign_commit makes — of every non-merge commit reachable from HEAD, and
//     fails the pull request when one of them is authored by an address the
//     policy does not admit. It is deterministic and it runs everywhere.
//
//   - GH-001 (E) is the empirical half. It pushes commits with an unlinked
//     author to a scratch GitHub repository, waits for propagation, and asks
//     GITHUB's contributors API whether a contributor appeared. It needs a
//     real repository, a real credential and a wall-clock wait, so it does not
//     run in ordinary CI. It is not a formality: GH-002 proves we followed our
//     own rule, and only GH-001 proves the rule is the right one.
//
// # The run date is an artefact, not a comment
//
// Threat model §5, residual risk 3:
//
//	GitHub contributor-logic change. I6's empirical guarantee (GH-001) is a
//	snapshot of external behavior; the test is dated and re-run on a schedule.
//
// A snapshot with no date is not a snapshot. testdata/gh-001-run.json is the
// dated record: status, the UTC instant of the last real run, the scratch
// repository, the author address used, the commit SHAs pushed, the contributor
// lists observed before and after, and the interval after which the snapshot is
// stale. TestGH001TheRecordedRunDateIsHonest reads that file on every single
// CI run — it never skips — and fails when the recorded run has aged past the
// interval, so the schedule is enforced by the suite rather than by memory.
//
// Until a human provisions the credential, the file records status
// "never-run", the honest state: I6's empirical half is UNPROVEN. Nothing in
// this package reports otherwise.
//
// # E3: GitHub will not show these commits as Verified
//
// IP §3, exemption E3:
//
//	GitHub "Verified" badge parity. GitHub's UI does not render gitsign
//	signatures as Verified. Do not chase this; our verification is
//	`gitsign verify` + Rekor + dashboard. Document the limitation.
//
// This is where a reader arrives asking why, so it is stated here. A commit
// Innsegl signs carries a real, checkable signature: an ephemeral keypair, a
// Fulcio certificate binding the run's SPIFFE ID, and a Rekor entry that
// timestamps it. GitHub's commit view will nonetheless show it as Unverified,
// and the contributors graph will show nothing at all — which is the point of
// this package's other half.
//
// The reason is that GitHub verifies a commit signature against the set of
// keys a GitHub ACCOUNT has uploaded. Gitsign's whole design is that no such
// key exists: the private key is generated per commit and destroyed, and the
// binding to an identity is the short-lived certificate plus the transparency
// log entry, neither of which GitHub's badge consults. An "Unverified" badge on
// an Innsegl commit therefore means "GitHub holds no uploaded key that made
// this signature", which is true, and says nothing about whether the signature
// is good.
//
// This is expected, permanent, and NOT a defect. Chasing it would mean
// uploading a long-lived key to an account — reintroducing the standing key
// E8 removes and the account attribution I6 removes, to win a badge. The
// verification that counts is `innsegl verify` (RM-037), which checks the
// signature, the certificate and the Rekor inclusion proof without consulting
// this system's database at all (I5), and the dashboard's three-check panel.
//
// # Why this package has no production code
//
// It never will. doc.go exists so that `go build ./...` has something to build
// in this directory; everything else here is a _test.go file. The gate has to
// ask internal/signing's question rather than a second question shaped like
// it — ADR-0028's CheckAuthor is exported for exactly this caller — and a
// second copy of an allowlist that has no cryptographic backstop is the way
// I6 would quietly stop being true.
package e2e
