// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"fmt"
)

// OperatorAuthors answers an installation's pinned operator author (#545,
// GH-008): the pair the installation's own operator machine reported on first
// use. internal/accounts.Store answers it on a hosted core.
type OperatorAuthors interface {
	OperatorAuthor(ctx context.Context, installation string) (name, email string, ok bool, err error)
}

// admitsAuthor is gate 3's one question (GH-009): may this name and address
// author a commit relayed by this installation?
//
// The deployment's own policy first — the unlinked agent address and the
// configured pairs (signers.Admits). Failing that, on a hosted core, the pair
// this installation pinned, by name and address together. Nothing else: no
// installation (the single-host shape), no pin, another installation's pin, or
// a pin source that cannot answer each leave the policy's refusal standing.
//
// The pinned pair is never printed: the refusal reaches a log.
func admitsAuthor(ctx context.Context, signers SignCommitSigners, authors OperatorAuthors,
	installation, name, email string,
) error {
	policyErr := signers.Admits(name, email)
	if policyErr == nil || installation == "" || authors == nil {
		return policyErr
	}
	pinnedName, pinnedEmail, ok, err := authors.OperatorAuthor(ctx, installation)
	if err != nil {
		return fmt.Errorf("%w; this installation's pinned operator author could not be read: %w", policyErr, err)
	}
	if !ok {
		return fmt.Errorf("%w; this installation has no operator author pinned (set a repository to "+
			"operator mode on the operator's machine: innsegl author repo <path> operator)", policyErr)
	}
	if pinnedName == name && pinnedEmail == email {
		return nil
	}
	return fmt.Errorf("%w; it is not the operator author this installation pinned. To pin another, "+
		"run on the core host: innsegl accounts author-reset %s", policyErr, installation)
}
