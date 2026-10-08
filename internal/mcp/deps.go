// SPDX-License-Identifier: Apache-2.0

package mcp

import "sync"

// deps is the one dependency set the tools and the gateway's in-process entry
// points run on.
//
// Each Configure function installs one member and returns a function
// restoring what was there before; each tool and entry point reads only the
// member it needs. Before #555 every tool kept its own mutex and pointer, and
// the commit-sign path read sign_commit's: so a deployment with no
// -workspace could not sign a commit through the gateway at all. Here the
// workspace-free signing dependencies (commitSigner) are their own member,
// installed with or without the sign_commit tool.
//
// It is package state because ADR-0016 §5's registration seam hands a binder
// nothing but the *Server, and because callers outside this package install
// through the exported Configure functions.
type deps struct {
	mu sync.RWMutex

	credential   *credentialService
	recordEvent  *recordEventService
	retire       *retireService
	signCommit   *signCommitService
	commitSigner *signCommitService
	commitClaim  *commitClaimService
	observe      *observeService
	agentMessage *agentMessageService
	signPayload  *signPayloadState
}

// active is this process's dependency set.
var active deps

// install puts v in one member of the active set and returns a function
// restoring whatever was there before.
func install[T any](slot **T, v *T) func() {
	active.mu.Lock()
	defer active.mu.Unlock()
	previous := *slot
	*slot = v
	return func() {
		active.mu.Lock()
		defer active.mu.Unlock()
		*slot = previous
	}
}

// installed reads one member of the active set.
func installed[T any](slot **T) *T {
	active.mu.RLock()
	defer active.mu.RUnlock()
	return *slot
}
