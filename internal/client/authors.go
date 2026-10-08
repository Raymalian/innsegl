// SPDX-License-Identifier: Apache-2.0

package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"innsegl.dev/innsegl/internal/signing"
)

// Who an agent commit is authored as, per repository (ENF-010).
//
// The default, everywhere, is the unlinked agent address: no GitHub account
// can hold it, so no contributor ever appears (I6). Some repositories cannot
// live with that: a private repository whose deploy host builds only commits
// authored by a member of its team never deploys agent work. I6 names the one
// other author it allows — "the human operator" — so the operator may set such
// a repository to author agent commits as the operator. The agent is still in
// the trailers and in the signature; the author line was never the record.
//
// This file is a convenience, not the gate. An agent running as the same user
// could write it, or set GIT_AUTHOR_* in its own command (which the hook
// already respects). Neither widens anything: the core admits only the
// operator pair pinned in its own configuration, by name and address, or the
// unlinked agent address, and it is out of an agent's reach on another host.

// The two modes a repository can be in.
const (
	AuthorAgent    = "agent"
	AuthorOperator = "operator"
)

// ErrAuthorIdentity is an operator identity that cannot be used: it does not
// read as `Name <address>`, or the hook could not pass it to git safely.
var ErrAuthorIdentity = errors.New("not a usable commit author identity")

// Authors is authors.json.
type Authors struct {
	// Operator is the operator's identity as git writes it, `Name <address>`
	// — normally a GitHub noreply address, so the deploy host recognises it.
	Operator string `json:"operator,omitempty"`
	// Repos maps a repository's git common directory to AuthorOperator. A
	// repository not listed is in agent mode.
	Repos map[string]string `json:"repos,omitempty"`
}

// ReadAuthors reads authors.json. No file means every repository is in agent
// mode.
func ReadAuthors(p Paths) (Authors, error) {
	data, err := os.ReadFile(p.Authors)
	if errors.Is(err, os.ErrNotExist) {
		return Authors{}, nil
	}
	if err != nil {
		return Authors{}, err
	}
	var a Authors
	if err := json.Unmarshal(data, &a); err != nil {
		return Authors{}, fmt.Errorf("%s: %w", p.Authors, err)
	}
	return a, nil
}

// WriteAuthors replaces authors.json, mode 0600.
func WriteAuthors(p Paths, a Authors) error {
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.Authors), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(p.Authors, append(data, '\n'), 0o600)
}

// SetOperator returns a with the operator identity set. It must read as
// `Name <address>` and hold no single quote or control character: the hook
// passes it to git inside single quotes, where nothing else needs escaping.
func (a Authors) SetOperator(identity string) (Authors, error) {
	if _, _, err := parseAuthorIdentity(identity); err != nil {
		return a, err
	}
	a.Operator = identity
	return a, nil
}

// SetRepo returns a with one repository, named by its git common directory,
// set to mode. Operator mode needs no typed identity: the hook reads the
// repository's own GitHub noreply address from git (#545, ENF-013).
func (a Authors) SetRepo(commonDir, mode string) (Authors, error) {
	repos := make(map[string]string, len(a.Repos)+1)
	for k, v := range a.Repos {
		repos[k] = v
	}
	switch mode {
	case AuthorAgent:
		delete(repos, commonDir)
	case AuthorOperator:
		repos[commonDir] = AuthorOperator
	default:
		return a, fmt.Errorf("a repository's author mode is %q or %q, not %q", AuthorAgent, AuthorOperator, mode)
	}
	if len(repos) == 0 {
		repos = nil
	}
	a.Repos = repos
	return a, nil
}

// IsOperator reports whether the repository with this git common directory
// is in operator mode.
func (a Authors) IsOperator(commonDir string) bool { return a.Repos[commonDir] == AuthorOperator }

// OperatorFor returns the typed operator identity (the optional override)
// when the repository with this git common directory is in operator mode and
// one is set.
func (a Authors) OperatorFor(commonDir string) (name, email string, ok bool) {
	if a.Repos[commonDir] != AuthorOperator {
		return "", "", false
	}
	name, email, err := parseAuthorIdentity(a.Operator)
	if err != nil {
		return "", "", false
	}
	return name, email, true
}

// parseAuthorIdentity reads `Name <address>` with internal/signing's own
// parser — the syntax the core's pinned operator pairs are written in — and
// refuses what the hook could not quote.
func parseAuthorIdentity(identity string) (name, email string, err error) {
	if strings.ContainsRune(identity, '\'') {
		return "", "", fmt.Errorf("%w: it holds a single quote", ErrAuthorIdentity)
	}
	for _, r := range identity {
		if r < 0x20 || r == 0x7f {
			return "", "", fmt.Errorf("%w: it holds a control character", ErrAuthorIdentity)
		}
	}
	op, perr := signing.ParseOperator(identity)
	if perr != nil {
		return "", "", fmt.Errorf("%w: %w", ErrAuthorIdentity, perr)
	}
	if op.Name == "" || op.Address == "" {
		return "", "", fmt.Errorf("%w: write it as `Name <address>`", ErrAuthorIdentity)
	}
	return op.Name, op.Address, nil
}
