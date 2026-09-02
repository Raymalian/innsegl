// SPDX-License-Identifier: Apache-2.0

// Package deploy holds the tests that measure the reference deployment
// itself — doc 05 §1's twelve rows, the Dockerfile that builds the shipped
// binary, and the append-only database role the topology requires.
//
// It is deliberately a package of its own rather than part of test/smoke.
// test/smoke owns the fresh-clone contract (OPS-004/OPS-005) and takes the
// shipped compose projects down with their volumes for the length of a run;
// nothing here does that, and nothing here may, because a release gate that
// two packages can tear out from under each other is not a gate.
package deploy
