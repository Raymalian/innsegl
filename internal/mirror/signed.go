// SPDX-License-Identifier: Apache-2.0

package mirror

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"innsegl.dev/innsegl/internal/commitpath"
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

// SnapshotTree answers the tree of the workspace snapshot an installation
// pushed for one tool call (#467, ADR-0065 decision 3), and whether the
// mirror holds it. A snapshot the mirror does not hold -- no mirror yet, no
// ref, a tree it lacks -- is "not held", never an error: the core records
// only a tree it holds, and a snapshot that never arrived is a witness
// missing, not a fault.
func (s *Store) SnapshotTree(ctx context.Context, repo, installation, toolUseID string) (string, bool, error) {
	if !commitpath.IsToolUseID(toolUseID) || !isInstallationID(installation) {
		return "", false, fmt.Errorf("mirror: %q/%q is not a snapshot ref", installation, toolUseID)
	}
	dir, err := s.Dir(repo)
	if errors.Is(err, ErrNoMirror) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	tree, ok := s.answers(ctx, dir, "rev-parse", "--verify", "--quiet",
		commitpath.SnapshotRef(installation, toolUseID)+"^{tree}")
	if !ok {
		return "", false, nil
	}
	if _, held := s.answers(ctx, dir, "cat-file", "-e", tree); !held {
		return "", false, nil
	}
	return tree, true, nil
}

// answers runs a git query whose failure means "no": an absent ref, an
// object the mirror lacks.
func (s *Store) answers(ctx context.Context, dir string, args ...string) (string, bool) {
	out, err := s.git(ctx, dir, nil, args...)
	return strings.TrimSpace(string(out)), err == nil
}
