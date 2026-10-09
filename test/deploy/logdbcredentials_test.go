// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/dockertest"
)

// ---------------------------------------------------------------------------
// OPS-163f/g (PROPOSED) — the log database moves onto this host's own
// passwords with no old password, at its next start (ADR-0078).
//
// Against the pinned MySQL image, with the init file the SHIPPED bootstrap
// renders:
//   f  a fresh data directory: Trillian's user and Rekor's open with this
//      host's values, root@'%' does not exist, root@localhost opens with its
//      file, and the image's own first-start setup is not locked out.
//   g  a data directory an earlier release made, on upstream's well-known
//      password: after one start with the new init file, the new values
//      open, and the old ones are refused, root's included. A second start
//      changes nothing.
//
// The image is amd64-only; under emulation each first start takes minutes.
// ---------------------------------------------------------------------------

var trillianDBImagePin = regexp.MustCompile(`(?m)^  (gcr\.io/trillian-opensource-ci/db_server:\S+)$`)
var opensslImagePin = regexp.MustCompile(`(?m)^  (alpine/openssl:\S+)$`)

type logDB struct {
	t      *testing.T
	ctx    context.Context
	prefix string
	image  string
	vols   []string
	conts  []string
}

func (l *logDB) vol(name string) string {
	v := l.prefix + "-" + name
	if _, err := dockertest.Docker(l.ctx, "volume", "create", v); err != nil {
		l.t.Fatal(err)
	}
	l.vols = append(l.vols, v)
	return v
}

func (l *logDB) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, c := range l.conts {
		discardError(dockertest.Docker(ctx, "rm", "-f", c))
	}
	for _, v := range l.vols {
		discardError(dockertest.Docker(ctx, "volume", "rm", "-f", v))
	}
}

// start runs MySQL on data with args, and waits until Trillian's user, with
// the password in pwFile (a path inside the container, or a literal with
// "lit:"), can read Trillian's table over TCP: the healthcheck's question.
func (l *logDB) start(name, data string, args []string, user, pw string) string {
	l.t.Helper()
	c := l.prefix + "-" + name
	discardError(dockertest.Docker(l.ctx, "rm", "-f", c))
	run := []string{"run", "--detach", "--name", c, "--platform", "linux/amd64",
		"-v", data + ":/var/lib/mysql"}
	run = append(run, args...)
	if _, err := dockertest.Docker(l.ctx, run...); err != nil {
		l.t.Fatalf("starting MySQL: %v", err)
	}
	l.conts = append(l.conts, c)
	deadline := time.Now().Add(8 * time.Minute)
	for time.Now().Before(deadline) {
		if l.opens(c, user, pw) {
			return c
		}
		time.Sleep(3 * time.Second)
	}
	logs, err := dockertest.Docker(l.ctx, "logs", "--tail", "40", c)
	l.t.Fatalf("MySQL never let %s in:\n%s%v", user, logs, err)
	return ""
}

// opens reports whether user logs in over TCP with password.
func (l *logDB) opens(c, user, password string) bool {
	_, err := dockertest.Docker(l.ctx, "exec", "-e", "MYSQL_PWD="+password, c,
		"mysql", "--protocol=TCP", "-h127.0.0.1", "-u"+user, "-N", "-B", "-e", "SELECT 1")
	return err == nil
}

// rootLocal reports whether root logs in on the local socket with password.
func (l *logDB) rootLocal(c, password string) bool {
	_, err := dockertest.Docker(l.ctx, "exec", "-e", "MYSQL_PWD="+password, c,
		"mysql", "-uroot", "-N", "-B", "-e", "SELECT 1")
	return err == nil
}

func (l *logDB) query(c, rootPW, sql string) string {
	out, err := dockertest.Docker(l.ctx, "exec", "-e", "MYSQL_PWD="+rootPW, c,
		"mysql", "-uroot", "-N", "-B", "-e", sql)
	if err != nil {
		l.t.Fatalf("%s: %v", sql, err)
	}
	return strings.TrimSpace(out)
}

func (l *logDB) value(store, name string) string {
	out, err := dockertest.Docker(l.ctx, "run", "--rm", "--network", "none", "-v", store+":/s:ro",
		"--entrypoint", "cat", opensslImage(l.t), "/s/"+name)
	if err != nil {
		l.t.Fatal(err)
	}
	return strings.TrimSpace(out)
}

func opensslImage(t *testing.T) string {
	m := opensslImagePin.FindStringSubmatch(readFile(t, filepath.Join(repoRoot(t), "deploy", "compose", "sigstore.yml")))
	if m == nil {
		t.Fatal("no openssl pin in sigstore.yml")
	}
	return m[1]
}

// bootstrap runs the SHIPPED sigstore bootstrap with the credential volumes
// compose gives it, and returns the trust volume and the logdb volume.
func (l *logDB) bootstrap() (store, logdbVol string) {
	l.t.Helper()
	sig := filepath.Join(repoRoot(l.t), "deploy", "compose")
	store, logdbVol = l.vol("store"), l.vol("logdb")
	args := []string{"run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp",
		"-e", "INNSEGL_SPIRE_JWT_ISSUER=http://spire-oidc:8080",
		"-e", "INNSEGL_CREDENTIALS_STORE=/run/innsegl/credentials-store",
		"-v", sig + "/sigstore/bootstrap.sh:/bootstrap.sh:ro",
		"-v", sig + "/sigstore/ca-lib.sh:/ca-lib.sh:ro",
		"-v", sig + "/credentials-lib.sh:/credentials-lib.sh:ro",
		"-v", sig + "/sigstore/fulcio-config.yaml:/in/fulcio-config.yaml:ro",
		"-v", sig + "/sigstore/rekor-index.sql:/in/rekor-index.sql:ro",
		"-v", l.vol("fulcio") + ":/out/fulcio", "-v", l.vol("rekor") + ":/out/rekor",
		"-v", store + ":/run/innsegl/credentials-store",
		"-v", logdbVol + ":/run/innsegl/render/logdb",
		"-v", l.vol("trillian") + ":/run/innsegl/render/trillian",
		"-v", l.vol("rekorindex") + ":/run/innsegl/render/rekor-index",
		"--entrypoint", "/bin/sh", opensslImage(l.t), "/bootstrap.sh"}
	if out, err := dockertest.Docker(l.ctx, args...); err != nil {
		l.t.Fatalf("the bootstrap failed: %v\n%s", err, out)
	}
	return store, logdbVol
}

// shippedArgs is trillian-db as sigstore.yml runs it.
func shippedArgs(logdbVol string) []string {
	return []string{
		"-e", "MYSQL_ROOT_PASSWORD_FILE=/run/innsegl/credentials/logdb/root",
		"-e", "MYSQL_DATABASE=test", "-e", "MYSQL_USER=test",
		"-e", "MYSQL_PASSWORD_FILE=/run/innsegl/credentials/logdb/trillian",
		"-v", logdbVol + ":/run/innsegl/credentials/logdb:ro",
	}
}

func newLogDB(t *testing.T) *logDB {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	t.Cleanup(cancel)
	if err := dockertest.Usable(ctx); err != nil {
		t.Skipf("skipping: %v. The log database's move is measured against the pinned MySQL.", err)
	}
	m := trillianDBImagePin.FindStringSubmatch(readFile(t, filepath.Join(repoRoot(t), "deploy", "compose", "sigstore.yml")))
	if m == nil {
		t.Fatal("no trillian-db pin in sigstore.yml")
	}
	l := &logDB{t: t, ctx: ctx, prefix: fmt.Sprintf("innsegl-logdbcred-%d-%d", os.Getpid(), time.Now().UnixNano()%100000), image: m[1]}
	t.Cleanup(l.cleanup)
	return l
}

func TestOPS163FAFreshLogDatabaseOpensWithItsFiles(t *testing.T) {
	l := newLogDB(t)
	store, logdbVol := l.bootstrap()
	root, trillian, rekor := l.value(store, "logdb-root"), l.value(store, "logdb-trillian"), l.value(store, "logdb-rekor")

	args := append(shippedArgs(logdbVol), l.image, "mysqld", "--init-file=/run/innsegl/credentials/logdb/init.sql")
	c := l.start("fresh", l.vol("data"), args, "test", trillian)

	if !l.opens(c, "rekor", rekor) {
		t.Error("Rekor's index user does not open with this host's password")
	}
	if !l.rootLocal(c, root) {
		t.Error("root@localhost does not open with this host's password")
	}
	if n := l.query(c, root, "SELECT COUNT(*) FROM mysql.user WHERE user = 'root' AND host = '%'"); n != "0" {
		t.Errorf("root@'%%' exists (%s); nothing uses it, and the init file removes it", n)
	}
}

func TestOPS163GALegacyLogDatabaseMovesAtItsNextStart(t *testing.T) {
	l := newLogDB(t)
	data := l.vol("data")

	// An earlier release: upstream's well-known password for every user, and
	// the index user's old one. Test code may name them; no shipped file may.
	const oldPW, oldRekor = "zaphod", "rekor-index"
	tmpl := readFile(t, filepath.Join(repoRoot(t), "deploy", "compose", "sigstore", "rekor-index.sql"))
	oldInit := filepath.Join(t.TempDir(), "rekor-index.sql")
	if err := os.WriteFile(oldInit, []byte(strings.ReplaceAll(tmpl, "@REKOR_INDEX_PASSWORD@", oldRekor)), 0o644); err != nil {
		t.Fatal(err)
	}
	c := l.start("old", data, []string{
		"-e", "MYSQL_ROOT_PASSWORD=" + oldPW, "-e", "MYSQL_DATABASE=test",
		"-e", "MYSQL_USER=test", "-e", "MYSQL_PASSWORD=" + oldPW,
		"-v", oldInit + ":/etc/mysql/rekor-index.sql:ro",
		l.image, "mysqld", "--init-file=/etc/mysql/rekor-index.sql"}, "test", oldPW)
	if !l.opens(c, "rekor", oldRekor) || !l.opens(c, "root", oldPW) {
		t.Fatal("the earlier release's database did not open with its own passwords")
	}
	if _, err := dockertest.Docker(l.ctx, "stop", c); err != nil {
		t.Fatal(err)
	}

	store, logdbVol := l.bootstrap()
	root, trillian, rekor := l.value(store, "logdb-root"), l.value(store, "logdb-trillian"), l.value(store, "logdb-rekor")
	args := append(shippedArgs(logdbVol), l.image, "mysqld", "--init-file=/run/innsegl/credentials/logdb/init.sql")
	c = l.start("new", data, args, "test", trillian)

	if !l.opens(c, "rekor", rekor) {
		t.Error("Rekor's index user does not open with this host's password")
	}
	if !l.rootLocal(c, root) {
		t.Error("root@localhost does not open with this host's password")
	}
	for user, pw := range map[string]string{"test": oldPW, "rekor": oldRekor, "root": oldPW} {
		if l.opens(c, user, pw) {
			t.Errorf("%s still opens over TCP with the old password", user)
		}
	}
	if l.rootLocal(c, oldPW) {
		t.Error("root@localhost still opens with the old password")
	}
	if n := l.query(c, root, "SELECT COUNT(*) FROM test.Trees"); n == "" {
		t.Error("Trillian's table is not there after the move")
	}

	// A second start with the same files changes nothing.
	if _, err := dockertest.Docker(l.ctx, "restart", c); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Minute)
	for !l.opens(c, "test", trillian) {
		if time.Now().After(deadline) {
			t.Fatal("after a second start Trillian's user no longer opens")
		}
		time.Sleep(3 * time.Second)
	}
	if !l.opens(c, "rekor", rekor) || !l.rootLocal(c, root) {
		t.Error("a second start changed a password")
	}
}
