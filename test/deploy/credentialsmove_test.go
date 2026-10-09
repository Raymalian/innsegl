// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/dockertest"
)

// ---------------------------------------------------------------------------
// OPS-163 (PROPOSED for doc 07's TC-OPS) — an existing ledger moves onto this
// host's own passwords at the next bring-up, in one transaction (ADR-0078).
//
// Against a real Postgres, running the SHIPPED db-init.sh:
//   a  a fresh host: the owner opens with its file; nothing moves; every
//      role logs in with its file's password.
//   b  a ledger an earlier release made, on the old public owner password:
//      every role moves; the new passwords open, the old ones are refused.
//   c  a second run moves nothing and still succeeds.
//   d  a move that fails half way (a role held by another session) is rolled
//      back: the run refuses, and every old password still works. Released,
//      the next run moves.
//   e  an owner password none of the candidates opens: refused, nothing
//      changed; with INNSEGL_LEDGER_OWNER_PASSWORD set to it, moved.
//
// db-init runs inside the ledger's container, but connects to the server by
// the container's own network address: Postgres trusts loopback in this
// image, and a test that went through loopback would accept any password.
// ---------------------------------------------------------------------------

var legacyOwnerConst = regexp.MustCompile(`(?m)^LEDGER_OWNER_LEGACY_PUBLIC_PASSWORD='([^']+)'$`)

func legacyOwnerPassword(t *testing.T) string {
	t.Helper()
	body := readFile(t, filepath.Join(repoRoot(t), "deploy", "compose", "innsegl", "db-init.sh"))
	m := legacyOwnerConst.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("db-init.sh defines no LEDGER_OWNER_LEGACY_PUBLIC_PASSWORD")
	}
	return m[1]
}

func randomCredential(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

type ledgerCreds map[string]string // role -> password; "owner" for the owner

var moveRoles = map[string]string{
	"owner":      ownerRole,
	"appender":   appenderRole,
	"reader":     readerRole,
	"backup":     backupRole,
	"authwriter": authwriterRole,
	"resolver":   resolverRole,
}

func newCreds(t *testing.T) ledgerCreds {
	c := ledgerCreds{}
	for k := range moveRoles {
		c[k] = randomCredential(t)
	}
	return c
}

// movePG is one ledger container with the test's own view of it.
type movePG struct {
	*ledgerContainer
	ip string
}

func startMovePG(ctx context.Context, t *testing.T, owner string) *movePG {
	t.Helper()
	pg, err := startLedgerOwner(ctx, t, owner)
	skip, failure := dockertest.StartupOutcome(err)
	switch containerRequirement(pg != nil, skip, failure) {
	case failTest:
		t.Fatalf("the ledger's Postgres did not start on a machine that has Docker: %s", failure)
	case skipTest:
		t.Skipf("skipping OPS-163: %s. The move is measured against a real Postgres.", skip)
	case proceed:
	}
	t.Cleanup(pg.stop)
	if cerr := pg.copyDeployScripts(ctx, repoRoot(t)); cerr != nil {
		t.Fatal(cerr)
	}
	ip, err := dockertest.Docker(ctx, "inspect", "-f",
		"{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", pg.name)
	if err != nil || ip == "" {
		t.Fatalf("reading the container's address: %v", err)
	}
	return &movePG{ledgerContainer: pg, ip: ip}
}

// dbInit runs the shipped db-init.sh. With files set, the credentials are
// written to /run/creds and INNSEGL_CREDENTIALS_DIR names them, as in the
// stack; otherwise env carries them, as an earlier release's compose did.
func (p *movePG) dbInit(ctx context.Context, t *testing.T, c ledgerCreds, files bool, extra ...string) (string, error) {
	t.Helper()
	args := []string{"exec",
		"--env", "PGHOST=" + p.ip,
		"--env", "PGPORT=5432",
		"--env", "PGUSER=" + ownerRole,
		"--env", "PGDATABASE=" + ownerDatabase,
		"--env", "INNSEGL_APPENDER_ROLE=" + appenderRole,
		"--env", "INNSEGL_READER_ROLE=" + readerRole,
		"--env", "INNSEGL_BACKUP_ROLE=" + backupRole,
		"--env", "INNSEGL_AUTHWRITER_ROLE=" + authwriterRole,
		"--env", "INNSEGL_RESOLVER_ROLE=" + resolverRole,
		"--env", "INNSEGL_READONLY_SQL=/innsegl/api/readonly.sql",
		"--env", "INNSEGL_AUTHWRITER_SQL=/innsegl/api/authwriter.sql",
		"--env", "INNSEGL_RESOLVER_SQL=/innsegl/api/resolver.sql",
	}
	if files {
		dir := t.TempDir()
		for k, v := range c {
			name := "ledger-" + k
			if err := os.WriteFile(filepath.Join(dir, name), []byte(v+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := dockertest.Docker(ctx, "exec", p.name, "rm", "-rf", "/run/creds"); err != nil {
			t.Fatal(err)
		}
		if _, err := dockertest.Docker(ctx, "cp", dir+"/.", p.name+":/run/creds"); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--env", "INNSEGL_CREDENTIALS_DIR=/run/creds")
	} else {
		args = append(args,
			"--env", "PGPASSWORD="+c["owner"],
			"--env", "INNSEGL_APPENDER_PASSWORD="+c["appender"],
			"--env", "INNSEGL_READER_PASSWORD="+c["reader"],
			"--env", "INNSEGL_BACKUP_PASSWORD="+c["backup"],
			"--env", "INNSEGL_AUTHWRITER_PASSWORD="+c["authwriter"],
			"--env", "INNSEGL_RESOLVER_PASSWORD="+c["resolver"])
	}
	args = append(args, extra...)
	args = append(args, p.name, "sh", "/innsegl/init/db-init.sh")
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return string(out), err
}

// opens reports whether role logs in with password, over the network path.
func (p *movePG) opens(ctx context.Context, role, password string) bool {
	_, err := dockertest.Docker(ctx, "exec", "--env", "PGPASSWORD="+password, p.name,
		"psql", "-X", "-q", "-h", p.ip, "-U", role, "-d", ownerDatabase, "-c", "SELECT 1")
	return err == nil
}

func (p *movePG) requireOpens(ctx context.Context, t *testing.T, c ledgerCreds, want bool, what string) {
	t.Helper()
	for k, role := range moveRoles {
		if got := p.opens(ctx, role, c[k]); got != want {
			t.Errorf("%s: %s logs in with the %s passwords = %v, want %v", what, role, what, got, want)
		}
	}
}

func TestOPS163AFreshLedgerOpensWithItsFiles(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	c := newCreds(t)
	p := startMovePG(ctx, t, c["owner"])
	out, err := p.dbInit(ctx, t, c, true)
	if err != nil {
		t.Fatalf("db-init on a fresh host: %v\n%s", err, out)
	}
	if !strings.Contains(out, "nothing to move") {
		t.Errorf("a fresh host moved something:\n%s", out)
	}
	p.requireOpens(ctx, t, c, true, "file")
	if p.opens(ctx, ownerRole, legacyOwnerPassword(t)) {
		t.Error("the old public owner password opens a fresh ledger")
	}
	for _, v := range c {
		if strings.Contains(out, v) {
			t.Fatal("db-init printed a password")
		}
	}
}

// legacyLedger makes a ledger the way an earlier release did: the owner on
// the old public default, the roles on values given in the environment.
func legacyLedger(ctx context.Context, t *testing.T) (*movePG, ledgerCreds) {
	t.Helper()
	old := newCreds(t)
	old["owner"] = legacyOwnerPassword(t)
	p := startMovePG(ctx, t, old["owner"])
	if out, err := p.dbInit(ctx, t, old, false); err != nil {
		t.Fatalf("provisioning the earlier release's ledger: %v\n%s", err, out)
	}
	p.requireOpens(ctx, t, old, true, "old")
	return p, old
}

func TestOPS163BCThePublicDefaultLedgerMovesOnceAndThenStays(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	p, old := legacyLedger(ctx, t)
	c := newCreds(t)

	out, err := p.dbInit(ctx, t, c, true)
	if err != nil {
		t.Fatalf("db-init on a legacy host: %v\n%s", err, out)
	}
	if !strings.Contains(out, "public default") || !strings.Contains(out, "in one transaction") {
		t.Errorf("the move did not say what it moved from:\n%s", out)
	}
	p.requireOpens(ctx, t, c, true, "new")
	p.requireOpens(ctx, t, old, false, "old")

	out, err = p.dbInit(ctx, t, c, true)
	if err != nil {
		t.Fatalf("a second run failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "nothing to move") {
		t.Errorf("a second run moved again:\n%s", out)
	}
	p.requireOpens(ctx, t, c, true, "new")
}

func TestOPS163DAMoveThatFailsHalfWayChangesNothing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	p, old := legacyLedger(ctx, t)
	c := newCreds(t)

	// Another session holds the resolver's row: an uncommitted ALTER ROLE.
	// The move alters the owner and three roles before it reaches this one.
	holdCtx, release := context.WithCancel(ctx)
	hold := exec.CommandContext(holdCtx, "docker", "exec", "-i", p.name,
		"psql", "-X", "-q", "-U", ownerRole, "-d", ownerDatabase)
	hold.Stdin = strings.NewReader("BEGIN;\nALTER ROLE " + resolverRole +
		" CONNECTION LIMIT 7;\nSELECT pg_sleep(120);\n")
	if err := hold.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { release(); discardError("", hold.Wait()) }()
	waitHeld(ctx, t, p)

	out, err := p.dbInit(ctx, t, c, true, "--env", "INNSEGL_CREDENTIALS_LOCK_TIMEOUT=2s")
	if err == nil {
		t.Fatalf("db-init succeeded while a role was held:\n%s", out)
	}
	if !strings.Contains(out, "REFUSED") || !strings.Contains(out, "rolled back") {
		t.Errorf("the refusal does not say the move was rolled back:\n%s", out)
	}
	p.requireOpens(ctx, t, old, true, "old")
	p.requireOpens(ctx, t, c, false, "new")

	release()
	discardError("", hold.Wait())
	discardError(dockertest.Docker(ctx, "exec", p.name, "psql", "-X", "-q", "-U", ownerRole,
		"-d", ownerDatabase, "-c", "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE query LIKE '%pg_sleep(120)%' AND pid <> pg_backend_pid()"))

	out, err = p.dbInit(ctx, t, c, true)
	if err != nil {
		t.Fatalf("the run after the hold was released: %v\n%s", err, out)
	}
	p.requireOpens(ctx, t, c, true, "new")
	p.requireOpens(ctx, t, old, false, "old")
}

func waitHeld(ctx context.Context, t *testing.T, p *movePG) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		n, err := dockertest.Docker(ctx, "exec", p.name, "psql", "-X", "-A", "-t", "-U", ownerRole,
			"-d", ownerDatabase, "-c", "SELECT count(*) FROM pg_stat_activity WHERE query LIKE '%pg_sleep(120)%' AND pid <> pg_backend_pid()")
		if err == nil && strings.TrimSpace(n) == "1" {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("the session holding the role never started")
}

func TestOPS163EAnUnknownOwnerPasswordIsRefusedUntilNamed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	old := newCreds(t)
	p := startMovePG(ctx, t, old["owner"])
	if out, err := p.dbInit(ctx, t, old, false); err != nil {
		t.Fatalf("provisioning: %v\n%s", err, out)
	}
	c := newCreds(t)
	out, err := p.dbInit(ctx, t, c, true)
	if err == nil || !strings.Contains(out, "REFUSED") {
		t.Fatalf("an owner none of the candidates opens was not refused (err %v):\n%s", err, out)
	}
	p.requireOpens(ctx, t, old, true, "old")

	out, err = p.dbInit(ctx, t, c, true, "--env", "INNSEGL_LEDGER_OWNER_PASSWORD="+old["owner"])
	if err != nil {
		t.Fatalf("with INNSEGL_LEDGER_OWNER_PASSWORD set: %v\n%s", err, out)
	}
	p.requireOpens(ctx, t, c, true, "new")
	p.requireOpens(ctx, t, old, false, "old")
}
