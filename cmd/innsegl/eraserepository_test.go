// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/ledger"
)

// LED-046 at the command line (ADR-0080 decisions 3 and 4, operator
// decision 6): `innsegl erase-repository` removes a repository's aliases and
// its mirror, and changes no event.
func TestLED046EraseRepositoryRemovesTheAliasesAndTheMirror(t *testing.T) {
	ownerDSN, _, _ := freshLedgerDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	store, err := ledger.Open(ctx, ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	repos, err := identity.NewRepositories(identity.ModePseudonymous, testRepoKey)
	if err != nil {
		t.Fatal(err)
	}
	store.UseRepositories(repos)
	const repo = "example.test/acme/withdrawn"
	rec, err := store.Append(ctx, event.Fields{
		event.FieldEventType: event.EventTypeRunRegistered, event.FieldSource: event.SourceMCP,
		event.FieldRunID: "run-erase", event.FieldSpiffeID: "spiffe://innsegl.dev/agent/a/b/run-erase",
		event.FieldIdempotencyKey: "reg-erase", event.FieldAgentType: "a", event.FieldTaskRef: "b",
		event.FieldRepo: repo, event.FieldBranch: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	pn, _ := rec[event.FieldRepo].(string)

	mirrorRoot := t.TempDir()
	bare := filepath.Join(mirrorRoot, "example.test", "acme", "withdrawn.git")
	if err := os.MkdirAll(bare, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bare, "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code := runEraseRepository(ctx, []string{"-dsn", ownerDSN, "-mirror-dir", mirrorRoot, "-repo", repo}, &out, &errOut)
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "2 aliases") || !strings.Contains(out.String(), "mirror") {
		t.Errorf("stdout does not report what was erased:\n%s", out.String())
	}
	if _, err := os.Stat(bare); !os.IsNotExist(err) {
		t.Errorf("the mirror is still there: %v", err)
	}
	names, err := store.ResolveNames(ctx, pn)
	if err != nil || names[pn] != pn {
		t.Errorf("the repository still resolves: %v, %v", names[pn], err)
	}
	if after, err := store.EventAt(ctx, 1); err != nil || after[event.FieldRepo] != pn {
		t.Errorf("the event changed: %v, %v", after[event.FieldRepo], err)
	}

	t.Run("a second run erases nothing and says so", func(t *testing.T) {
		var out, errOut bytes.Buffer
		if code := runEraseRepository(ctx, []string{"-dsn", ownerDSN, "-mirror-dir", mirrorRoot, "-repo", repo}, &out, &errOut); code != exitOK {
			t.Fatalf("exit %d\n%s", code, errOut.String())
		}
		if !strings.Contains(out.String(), "no alias") {
			t.Errorf("stdout:\n%s", out.String())
		}
	})
}

func TestLED046EraseRepositoryUsage(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no repository", []string{"-dsn", "postgres://x"}, "-repo"},
		{"a pseudonym rather than a name", []string{"-dsn", "postgres://x", "-repo", "pn:rk-0a1b2c3d:" + strings.Repeat("a", 32)}, "-repo"},
		{"no database", []string{"-repo", "example.test/acme/api"}, "-dsn"},
		{"an argument", []string{"-dsn", "postgres://x", "-repo", "example.test/acme/api", "extra"}, "unexpected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envLedgerDSN, "")
			var out, errOut bytes.Buffer
			if code := runEraseRepository(context.Background(), tc.args, &out, &errOut); code != exitUsage {
				t.Errorf("exit %d, want %d", code, exitUsage)
			}
			if !strings.Contains(errOut.String(), tc.want) {
				t.Errorf("stderr does not name %q:\n%s", tc.want, errOut.String())
			}
		})
	}
}
