// SPDX-License-Identifier: Apache-2.0

// Package load holds doc 07's TC-OPS load cases: the layer-F work that can
// only be observed by running the real components together for long enough
// that their steady state, rather than their first call, is what is measured.
//
// Today that is OPS-002 (RM-052, #60): sustained append load across at least
// three segment rollovers, asserting that the chain has no gaps, that every
// segment seals and anchors, and that the anchoring heartbeat stays accurate
// throughout.
//
// It has no production code and never will. The file you are reading exists so
// that `go build ./...` has something to build in this directory; everything
// else here is a _test.go file.
//
// # What this package is for, and what it is not for
//
// doc 05 §4 sizes the deployment from an estimate and says so: "Sizing posture
// (initial, revisit with data) ... The first real load test (OPS-002) replaces
// these estimates with measurements; per the verification methodology,
// measured numbers supersede this section and get recorded in an ADR
// appendix." This package is where those measurements come from, and
// ADR-0039 is where they are recorded.
//
// A load test is the easiest place in a repository to produce a confident
// wrong number, so every number this package emits is emitted with the
// conditions it was taken under — host, container images, worker count, and
// whether the race detector was on — and the run refuses to report a
// throughput figure at all unless it has first established that the generator
// was not the thing being measured. See measuredRun in ops002_test.go.
package load
