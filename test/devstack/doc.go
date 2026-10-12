// SPDX-License-Identifier: Apache-2.0

// Package devstack holds the end-to-end cases that need a running DEVELOPMENT
// stack (`make dev-stack`, ADR-0072) and nothing else: OPS-208, the in-place
// update rehearsal's checks, and OPS-209, a second unlock device that unlocks
// the CA key store with the operator's machine out of the loop (#617,
// ADR-0082).
//
// They talk to the stack the developer brought up, over its published
// loopback ports, so they are opt-in: INNSEGL_DEVSTACK_E2E=1 runs them, and
// without it every case skips naming what it needs. They refuse to start
// unless the stack's containers carry the innsegl-dev prefix, so they never
// reach a live core (ADR-0072; a live test once left a fake repository in a
// production ledger for good).
//
//	INNSEGL_DEVSTACK_E2E=1         run at all
//	INNSEGL_DEVSTACK_STATE=DIR     where the dev owner's soft passkey is kept
//	                               between the phases of a rehearsal
//	INNSEGL_DEVSTACK_IDENTITY=F    the dev stack's own age identity, the one
//	                               INNSEGL_CA_CUSTODY_RECIPIENTS names; never
//	                               the operator's
//	INNSEGL_DEVSTACK_PHASE=before|after   OPS-208's half
//	INNSEGL_DEVSTACK_DASHBOARD     [http://localhost:8082]
//	INNSEGL_DEVSTACK_CORE          [https://localhost:28095]
//	INNSEGL_DEVSTACK_CA            [~/.innsegl/dev/ca/gateway-ca.pem]
//
// Run with the stack up, one package, -p 1. reference/ca-custody.md carries
// the command.
package devstack
