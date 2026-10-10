// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"innsegl.dev/innsegl/internal/event"
)

// Repositories decides what the chain SAYS about the repository and branch a
// run works in (ADR-0080).
//
// Under ModeLiteral it returns doc 02 §5's literal values, checked. Under
// ModePseudonymous it returns schema 5's keyed pseudonym:
//
//	repo   = pn:<key-id>:hex32(HMAC-SHA256(key, "repo:" + repo))
//	branch = pn:<key-id>:hex32(HMAC-SHA256(key, "branch:" + repo + "\n" + branch))
//
// The key is this deployment's repository key, a separate secret from the
// one Pseudonymiser holds (ADR-0080 decision 2): rotating one never carries
// the other's risk. Like that one, it is needed to CREATE a pseudonym and
// never to RESOLVE one; resolution is the ledger's alias table.
type Repositories struct {
	mode  Mode
	key   []byte
	keyID string
}

// MinRepoKeyBytes is the repository key's floor. The shipped generator writes
// 64 hex characters.
const MinRepoKeyBytes = 32

// repoPseudonymHex is how many hex digits of the HMAC a pseudonym keeps:
// 128 bits, because these values are join keys and a collision would merge
// two repositories' runs (ADR-0080 decision 1).
const repoPseudonymHex = 32

const (
	domainRepo   = "repo"
	domainBranch = "branch"

	// detachedBranch is doc 02 §5's literal for a detached HEAD. It is a
	// state, not a name, and stays literal in both modes.
	detachedBranch = "detached"
)

// NewRepositories builds the repository pseudonymiser. A pseudonymous
// deployment with no key, or a short one, is refused: guessing would write a
// literal name the configuration said would never reach the chain. A literal
// deployment may hold a key, because the shipped generator always writes one
// so that switching needs no second step; it is not used.
func NewRepositories(mode Mode, key string) (*Repositories, error) {
	switch mode {
	case ModeLiteral:
		return &Repositories{mode: mode}, nil
	case ModePseudonymous:
		if len(key) < MinRepoKeyBytes {
			return nil, fmt.Errorf(
				"repository mode %q needs a repository key of at least %d bytes and was "+
					"given %d: without one every repository and branch name would reach the "+
					"chain, which is permanent. Supply the key, or keep mode %q",
				mode, MinRepoKeyBytes, len(key), ModeLiteral)
		}
		sum := sha256.Sum256([]byte("innsegl-repo-key-id:" + key))
		return &Repositories{
			mode:  mode,
			key:   []byte(key),
			keyID: "rk-" + hex.EncodeToString(sum[:])[:8],
		}, nil
	default:
		return nil, fmt.Errorf("repository mode %q is neither %q nor %q",
			mode, ModePseudonymous, ModeLiteral)
	}
}

// Mode reports which form this deployment writes.
func (r *Repositories) Mode() Mode { return r.mode }

// KeyID names the key new pseudonyms are made under; empty in literal mode.
func (r *Repositories) KeyID() string { return r.keyID }

// Repo returns what the chain records for a repository. The literal is
// checked against doc 02 §5 before it is hidden, so a value refused as a
// literal is refused here too, and a pseudonym is never hidden twice.
func (r *Repositories) Repo(repo string) (string, error) {
	if err := event.ValidateRepo(repo); err != nil {
		return "", err
	}
	if r.mode == ModeLiteral {
		return repo, nil
	}
	return r.render(domainRepo + ":" + repo), nil
}

// Branch returns what the chain records for a branch of repo. It is keyed by
// the repository, so one branch name in two repositories is two values.
func (r *Repositories) Branch(repo, branch string) (string, error) {
	if err := event.ValidateRepo(repo); err != nil {
		return "", err
	}
	if err := event.ValidateBranch(branch); err != nil {
		return "", err
	}
	if r.mode == ModeLiteral || branch == detachedBranch {
		return branch, nil
	}
	return r.render(domainBranch + ":" + repo + "\n" + branch), nil
}

func (r *Repositories) render(msg string) string {
	mac := hmac.New(sha256.New, r.key)
	mac.Write([]byte(msg))
	return event.PseudonymPrefix + r.keyID + ":" + hex.EncodeToString(mac.Sum(nil))[:repoPseudonymHex]
}
