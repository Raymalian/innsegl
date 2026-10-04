// SPDX-License-Identifier: Apache-2.0

package mirror

import (
	"context"
	"fmt"
	"strings"

	"innsegl.dev/innsegl/internal/event"
)

// SignedRefPrefix holds the signed commits the core wrote itself, one ref
// per commit, so the mirror keeps each one (ADR-0065).
const SignedRefPrefix = "refs/innsegl/signed/"

// StoreSigned writes the signed commit object the core built into the mirror
// of repo, and keeps it under SignedRefPrefix+sha. A client pushes a
// commit's objects before it is signed and nothing pushes the signed commit
// after, so without this the mirror held no signed commit to prove. The
// object's id must be sha: the bytes are exactly the commit git records, or
// they are refused.
func (s *Store) StoreSigned(ctx context.Context, repo, sha string, body []byte) error {
	if err := event.ValidateGitObjectID(sha); err != nil {
		return err
	}
	dir, err := s.Dir(repo)
	if err != nil {
		return err
	}
	out, err := s.git(ctx, dir, strings.NewReader(string(body)), "hash-object", "-w", "-t", "commit", "--stdin")
	if err != nil {
		return err
	}
	if got := strings.TrimSpace(string(out)); got != sha {
		return fmt.Errorf("mirror: the signed commit hashes to %s, not %s", got, sha)
	}
	_, err = s.git(ctx, dir, nil, "update-ref", SignedRefPrefix+sha, sha)
	return err
}
