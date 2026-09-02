// SPDX-License-Identifier: Apache-2.0

// Package smoke holds OPS-004, the fresh-clone contract (RM-054, #62).
//
// This package is the adopter's first five minutes, executed. Everything else
// in the test catalogue asks whether a component is correct; this asks whether
// a stranger who clones the repository and follows deploy/compose/README.md
// reaches a green happy path — and, doc 08's versioning policy having made the
// compose stack and `make smoke` part of the compatibility surface, it is a
// release gate rather than documentation. If `make smoke` from the previous
// minor's README fails on a new minor, that is a breaking change misfiled as a
// minor and the release is blocked.
//
// It is the only package in the repository that drives the SHIPPED compose
// project names — `innsegl-spire` and `innsegl-sigstore` — rather than the
// per-process overlays of ADR-0022. That is deliberate and it is the point:
// the adopter has no overlay, and `deploy/compose/spire/register.sh` addresses
// the shipped container names directly. Running the README's literal commands
// is the only way to find out whether the README's literal commands work.
package smoke
