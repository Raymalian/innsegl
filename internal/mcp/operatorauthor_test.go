// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/signing"
)

// pinnedAuthors is an OperatorAuthors answering from a map, installation →
// pinned pair.
type pinnedAuthors map[string][2]string

func (p pinnedAuthors) OperatorAuthor(_ context.Context, installation string) (string, string, bool, error) {
	pair, ok := p[installation]
	return pair[0], pair[1], ok, nil
}

type failingAuthors struct{}

func (failingAuthors) OperatorAuthor(context.Context, string) (string, string, bool, error) {
	return "", "", false, errors.New("store down")
}

// GH-009 (PROPOSED for doc 07) — gate 3 admits, for a commit relayed by an
// installation, that installation's pinned operator author (#545).
//
// Beside the agent address and the deployment's configured pairs, the one
// other author a hosted core admits is the pair the installation's own
// operator machine pinned on first use (GH-008). Another installation's pin
// admits nothing here, an unpinned installation admits no operator, and a
// store that cannot answer refuses rather than admits.
func TestGH009Gate3AdmitsTheInstallationsPinnedOperator(t *testing.T) {
	const (
		name  = "Fixture Alpha"
		email = "12345+alpha@users.noreply.github.com"
	)
	signers := NewGitsignSigners(signing.Config{Author: signing.AuthorPolicy{AllowUnlinked: true}})
	pins := pinnedAuthors{"inst-a": {name, email}, "inst-b": {"Fixture Beta", "67890+beta@users.noreply.github.com"}}
	cases := []struct {
		desc         string
		authors      OperatorAuthors
		installation string
		author       string
		email        string
		admit        bool
	}{
		{"the installation's pinned pair", pins, "inst-a", name, email, true},
		{"the pinned address under another name", pins, "inst-a", "Someone Else", email, false},
		{"another installation's pinned pair", pins, "inst-b", name, email, false},
		{"an installation with no pin", pins, "inst-c", name, email, false},
		{"the single-host shape: no installation", pins, "", name, email, false},
		{"no pin source configured", nil, "inst-a", name, email, false},
		{"a pin source that cannot answer", failingAuthors{}, "inst-a", name, email, false},
		{"the unlinked agent address, always", pins, "inst-c", "Innsegl", "agent@innsegl.invalid", true},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := admitsAuthor(context.Background(), signers, tc.authors, tc.installation, tc.author, tc.email)
			if tc.admit && err != nil {
				t.Fatalf("admitted = %v, want admitted", err)
			}
			if !tc.admit && err == nil {
				t.Fatal("admitted, want refused")
			}
		})
	}
}

// A refusal for an installation whose pin differs says how to change it, on
// the core, without printing the pinned name or address.
func TestGH009ARefusedPairNamesTheResetAndNotThePin(t *testing.T) {
	signers := NewGitsignSigners(signing.Config{Author: signing.AuthorPolicy{AllowUnlinked: true}})
	pins := pinnedAuthors{"inst-a": {"Fixture Alpha", "12345+alpha@users.noreply.github.com"}}
	err := admitsAuthor(context.Background(), signers, pins, "inst-a", "Fixture Beta", "67890+beta@users.noreply.github.com")
	if err == nil {
		t.Fatal("admitted a pair that differs from the pin")
	}
	msg := err.Error()
	if !strings.Contains(msg, "innsegl accounts author-reset inst-a") {
		t.Fatalf("the refusal does not name the reset: %s", msg)
	}
	if strings.Contains(msg, "Fixture Alpha") || strings.Contains(msg, "12345+alpha") {
		t.Fatalf("the refusal prints the pinned pair: %s", msg)
	}
}
