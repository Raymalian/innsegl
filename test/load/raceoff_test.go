// SPDX-License-Identifier: Apache-2.0

//go:build !race

package load

// raceDetectorState is reported beside every number this package measures.
// See raceon_test.go for why it is part of the measurement rather than a
// footnote to it.
const raceDetectorState = "off"
