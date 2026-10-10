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

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/ledger"
)

// ACC-010 at the command line (#482, ADR-0080 decision 3): `innsegl
// erase-organisation` removes an organisation's account rows, its
// repositories' aliases and their mirrors, and changes no event.
func TestACC010EraseOrganisationRemovesRowsAliasesAndMirrors(t *testing.T) {
	ownerDSN, _, authDSN := freshLedgerDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	store, err := ledger.Open(ctx, ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	conn, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	if _, err = conn.Exec(ctx, `INSERT INTO innsegl.repo_mode (mode, key_id) VALUES ('pseudonymous', 'rk-test0001');
		INSERT INTO innsegl_auth.users (user_id, display_name) VALUES ('u-owner', 'Owner'), ('u-admin', 'Admin')`); err != nil {
		t.Fatal(err)
	}
	writer, err := accounts.Open(ctx, authDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(writer.Close)
	org, err := writer.CreateAccount(ctx, accounts.CreateAccountParams{Name: "Withdrawn Ltd", Owner: "u-owner"})
	if err != nil {
		t.Fatal(err)
	}
	if err = writer.AddMember(ctx, org.ID, "u-admin", accounts.RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	const repo = "example.test/withdrawn/plans"
	if err = writer.GrantRepo(ctx, org.ID, repo, ""); err != nil {
		t.Fatal(err)
	}

	repos, err := identity.NewRepositories(identity.ModePseudonymous, testRepoKey)
	if err != nil {
		t.Fatal(err)
	}
	store.UseRepositories(repos)
	rec, err := store.Append(ctx, event.Fields{
		event.FieldEventType: event.EventTypeRunRegistered, event.FieldSource: event.SourceMCP,
		event.FieldRunID: "run-org-erase", event.FieldSpiffeID: "spiffe://innsegl.dev/agent/a/b/run-org-erase",
		event.FieldIdempotencyKey: "reg-org-erase", event.FieldAgentType: "a", event.FieldTaskRef: "b",
		event.FieldRepo: repo, event.FieldBranch: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	pn, ok := rec[event.FieldRepo].(string)
	if !ok {
		t.Fatalf("the chain holds %v, want a pseudonym", rec[event.FieldRepo])
	}
	headBefore, err := store.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}

	mirrorRoot := t.TempDir()
	bare := filepath.Join(mirrorRoot, "example.test", "withdrawn", "plans.git")
	if merr := os.MkdirAll(bare, 0o700); merr != nil {
		t.Fatal(merr)
	}
	if werr := os.WriteFile(filepath.Join(bare, "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); werr != nil {
		t.Fatal(werr)
	}

	run := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := runEraseOrganisation(ctx, args, &out, &errOut)
		return code, out.String(), errOut.String()
	}
	if code, _, stderr := run("-dsn", ownerDSN, "-mirror-dir", mirrorRoot, "-account", org.ID, "-by", "u-admin"); code == exitOK ||
		!strings.Contains(stderr, "owner") {
		t.Fatalf("an admin erases: exit %d: %s", code, stderr)
	}
	code, out, stderr := run("-dsn", ownerDSN, "-mirror-dir", mirrorRoot, "-account", org.ID, "-by", "u-owner")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	for _, want := range []string{org.ID, "1 repositories", "2 members", "removed the mirror of " + repo} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout does not report %q:\n%s", want, out)
		}
	}
	if _, serr := os.Stat(bare); !os.IsNotExist(serr) {
		t.Errorf("the mirror is still there: %v", serr)
	}
	names, err := store.ResolveNames(ctx, pn)
	if err != nil || names[pn] != pn {
		t.Errorf("the repository still resolves: %v, %v", names[pn], err)
	}
	if headAfter, herr := store.Head(ctx); herr != nil || headAfter != headBefore {
		t.Errorf("the chain head moved: %v -> %v (%v)", headBefore, headAfter, herr)
	}
	list, err := writer.ListAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range list {
		if a.ID == org.ID {
			t.Errorf("the organisation is still listed")
		}
	}

	if code, _, stderr := run("-dsn", ownerDSN, "-account", org.ID); code == exitOK || !strings.Contains(stderr, "no such") {
		t.Errorf("erasing again: exit %d: %s", code, stderr)
	}
}

func TestACC011EraseOrganisationUsage(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no organisation", []string{"-dsn", "postgres://x"}, "-account"},
		{"no database", []string{"-account", "abc"}, "-dsn"},
		{"an argument", []string{"-dsn", "postgres://x", "-account", "abc", "extra"}, "unexpected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envLedgerDSN, "")
			var out, errOut bytes.Buffer
			if code := runEraseOrganisation(context.Background(), tc.args, &out, &errOut); code != exitUsage {
				t.Errorf("exit %d, want %d", code, exitUsage)
			}
			if !strings.Contains(errOut.String(), tc.want) {
				t.Errorf("stderr does not name %q:\n%s", tc.want, errOut.String())
			}
		})
	}
}
