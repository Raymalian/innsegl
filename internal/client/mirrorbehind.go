// SPDX-License-Identifier: Apache-2.0

package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// MirrorBehind is a branch whose push the core's mirror refused because it
// is not a fast-forward of the mirror's copy (#465): the branch was
// rewritten here, or moved on elsewhere. The mirror keeps no rewrites, so
// its copy stays where it was until a push that builds on it. Recorded once
// per branch by the detached push, read by `innsegl status`, cleared by the
// next push of that branch the mirror takes.
type MirrorBehind struct {
	Repo   string    `json:"repo"`
	Branch string    `json:"branch"`
	Local  string    `json:"local"`
	Reason string    `json:"reason"`
	Since  time.Time `json:"since"`
}

// mirrorBehindFile is where they are kept, under the client folder.
func mirrorBehindFile(p Paths) string { return filepath.Join(p.Dir, "mirror-behind.json") }

// ReadMirrorBehind answers every recorded branch, sorted by repository and
// branch. No file is nothing recorded.
func ReadMirrorBehind(p Paths) ([]MirrorBehind, error) {
	raw, err := os.ReadFile(mirrorBehindFile(p))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", mirrorBehindFile(p), err)
	}
	var out []MirrorBehind
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("read %s: %w", mirrorBehindFile(p), err)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Repo != out[j].Repo {
			return out[i].Repo < out[j].Repo
		}
		return out[i].Branch < out[j].Branch
	})
	return out, nil
}

// RecordMirrorBehind records e unless its branch is recorded already, and
// reports whether it wrote anything: a refusal is recorded once, from the
// first time it happened.
func RecordMirrorBehind(p Paths, e MirrorBehind) (bool, error) {
	all, err := ReadMirrorBehind(p)
	if err != nil {
		return false, err
	}
	for _, have := range all {
		if have.Repo == e.Repo && have.Branch == e.Branch {
			return false, nil
		}
	}
	return true, writeMirrorBehind(p, append(all, e))
}

// ClearMirrorBehind forgets repo's branch, once the mirror took a push of
// it. Nothing recorded is not an error.
func ClearMirrorBehind(p Paths, repo, branch string) error {
	all, err := ReadMirrorBehind(p)
	if err != nil {
		return err
	}
	kept := all[:0]
	for _, have := range all {
		if have.Repo != repo || have.Branch != branch {
			kept = append(kept, have)
		}
	}
	if len(kept) == len(all) {
		return nil
	}
	return writeMirrorBehind(p, kept)
}

// writeMirrorBehind replaces the file whole, through a rename, so a reader
// never sees half of it.
func writeMirrorBehind(p Paths, all []MirrorBehind) error {
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(p.Dir, "mirror-behind-*.json")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), mirrorBehindFile(p))
}
