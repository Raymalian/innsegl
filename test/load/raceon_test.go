// SPDX-License-Identifier: Apache-2.0

//go:build race

package load

// raceDetectorState is reported beside every number this package measures.
//
// It is not a footnote. The race detector instruments every memory access in
// the process, and the append path this test measures is Go code all the way
// down to the socket — so a throughput taken under -race is a lower bound on
// the same code built without it, and a reader who is not told which build
// produced a number cannot tell the two apart. CI runs -race, so the numbers
// CI prints are the conservative ones.
const raceDetectorState = "on"
