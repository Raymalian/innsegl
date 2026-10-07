// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/go-sql-driver/mysql"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/client/clienttest"
	"innsegl.dev/innsegl/internal/gateway"
	"innsegl.dev/innsegl/internal/trustbackup"
)

// trustVolumes lays out stand-ins for what the core backs up.
func trustVolumes(t *testing.T) (env map[string]string, args []string) {
	t.Helper()
	root := t.TempDir()
	for p, body := range map[string]string{
		"fulcio/ca.crt":           "CERT",
		"fulcio/ca.key":           "CAKEY",
		"rekor/log.key":           "LOGKEY",
		"identity/secret":         "IDSECRET",
		"spire/upstream-ca.key":   "SPIREKEY",
		"gateway/ca.key":          "GWKEY",
		"history/trust-history.j": "{}",
	} {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	idFile := filepath.Join(root, "identity.txt")
	if err := os.WriteFile(idFile, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env = map[string]string{
		trustbackup.EnvRecipients:    id.Recipient().String(),
		envTrustBackupMySQLUser:      "test",
		envTrustBackupMySQLPassword:  "hunter2",
		"INNSEGL_FULCIO_CA_PASSWORD": "capw",
		"TEST_IDENTITY_FILE":         idFile,
		"TEST_BACKUP_DIR":            filepath.Join(root, "backups"),
	}
	args = []string{
		"--dir", env["TEST_BACKUP_DIR"], "--keep", "3", "--owner", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"--path", "fulcio-pki=" + filepath.Join(root, "fulcio"),
		"--path", "rekor-key=" + filepath.Join(root, "rekor"),
		"--path", "identity-secret=" + filepath.Join(root, "identity"),
		"--path", "spire-upstream-ca=" + filepath.Join(root, "spire"),
		"--path", "gateway-ca-key=" + filepath.Join(root, "gateway"),
		"--path", "trust-history=" + filepath.Join(root, "history"),
		"--mysql", "trillian-db=trillian-db:3306/test",
		"--value", "fulcio-ca-password=INNSEGL_FULCIO_CA_PASSWORD",
	}
	return env, args
}

func getenvFrom(env map[string]string) func(string) string {
	return func(k string) string { return env[k] }
}

// fakeExport stands in for the log database: it checks the credentials it
// was handed and writes an export naming the database.
func fakeExport(_ context.Context, dsn string, w io.Writer) error {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return err
	}
	if cfg.User != "test" || cfg.Passwd != "hunter2" || cfg.Addr != "trillian-db:3306" {
		return fmt.Errorf("no password for %s@%s", cfg.User, cfg.Addr)
	}
	_, err = fmt.Fprintf(w, "-- dump of %s\nCREATE TABLE Trees (id int);\n", cfg.DBName)
	return err
}

func TestTrustBackupCreateWritesOneEncryptedBundleOfEveryItem(t *testing.T) {
	env, args := trustVolumes(t)
	var out, errOut bytes.Buffer
	code := runTrustBackup(t.Context(), append([]string{"create"}, args...), &out, &errOut, trustBackupDeps{exportMySQL: fakeExport,
		getenv: getenvFrom(env), now: func() time.Time { return time.Date(2026, 10, 7, 3, 0, 0, 0, time.UTC) },
	})
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	store := &trustbackup.Store{Dir: env["TEST_BACKUP_DIR"]}
	e, err := store.Latest()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.ReadStatus()
	if err != nil || st.Error != "" || st.Latest != e.Name {
		t.Fatalf("status = %+v, %v", st, err)
	}
	// The drill opens it and names every item.
	out.Reset()
	errOut.Reset()
	code = runTrustBackup(t.Context(), []string{"drill", "--dir", env["TEST_BACKUP_DIR"],
		"--identity", env["TEST_IDENTITY_FILE"]}, &out, &errOut, trustBackupDeps{exportMySQL: fakeExport, getenv: getenvFrom(env)})
	if code != exitOK {
		t.Fatalf("drill exit %d: %s", code, errOut.String())
	}
	for _, want := range append(expectedTrustItems, e.Name, "every checksum matches", "trillian.sql") {
		if !strings.Contains(out.String(), want) {
			t.Errorf("drill output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "MISSING") {
		t.Errorf("drill reports a missing item:\n%s", out.String())
	}
	// --extract writes the files, 0600, for a restore.
	dst := filepath.Join(t.TempDir(), "restore")
	out.Reset()
	if code := runTrustBackup(t.Context(), []string{"drill", "--dir", env["TEST_BACKUP_DIR"],
		"--identity", env["TEST_IDENTITY_FILE"], "--extract", dst}, &out, &errOut,
		trustBackupDeps{exportMySQL: fakeExport, getenv: getenvFrom(env)}); code != exitOK {
		t.Fatalf("extract exit %d: %s", code, errOut.String())
	}
	b, err := os.ReadFile(filepath.Join(dst, "fulcio-pki", "ca.key"))
	if err != nil || string(b) != "CAKEY" {
		t.Fatalf("extracted CA key %q, %v", b, err)
	}
	b = must(os.ReadFile(filepath.Join(dst, "trillian-db", "trillian.sql")))(t)
	if !strings.Contains(string(b), "CREATE TABLE Trees") || !strings.Contains(string(b), "-- dump of test") {
		t.Fatalf("extracted dump %q", b)
	}
}

func TestTrustBackupCreateWithNoRecipientWritesNothingAndSaysWhy(t *testing.T) {
	env, args := trustVolumes(t)
	delete(env, trustbackup.EnvRecipients)
	var out, errOut bytes.Buffer
	code := runTrustBackup(t.Context(), append([]string{"create"}, args...), &out, &errOut,
		trustBackupDeps{exportMySQL: fakeExport, getenv: getenvFrom(env)})
	if code != exitTrustBackupFailed || !strings.Contains(errOut.String(), trustbackup.EnvRecipients) {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	store := &trustbackup.Store{Dir: env["TEST_BACKUP_DIR"]}
	if list := must(store.List())(t); len(list) != 0 {
		t.Fatalf("a bundle was written: %+v", list)
	}
	st, err := store.ReadStatus()
	if err != nil || !strings.Contains(st.Error, trustbackup.EnvRecipients) {
		t.Fatalf("status = %+v, %v", st, err)
	}
}

// stepClock answers a later second on every call.
func stepClock() func() time.Time {
	t := time.Date(2026, 10, 7, 3, 0, 0, 0, time.UTC)
	return func() time.Time {
		t = t.Add(time.Second)
		return t
	}
}

func TestTrustBackupCreateRefusesABrokenSourceAndKeepsTheLastGoodBundle(t *testing.T) {
	env, args := trustVolumes(t)
	deps := trustBackupDeps{exportMySQL: fakeExport, getenv: getenvFrom(env), now: stepClock()}
	var out, errOut bytes.Buffer
	if code := runTrustBackup(t.Context(), append([]string{"create"}, args...), &out, &errOut, deps); code != exitOK {
		t.Fatalf("first run: %s", errOut.String())
	}
	env[envTrustBackupMySQLPassword] = "wrong"
	errOut.Reset()
	if code := runTrustBackup(t.Context(), append([]string{"create"}, args...), &out, &errOut, deps); code != exitTrustBackupFailed ||
		!strings.Contains(errOut.String(), "no password for test@trillian-db:3306") {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	store := &trustbackup.Store{Dir: env["TEST_BACKUP_DIR"]}
	if list := must(store.List())(t); len(list) != 1 {
		t.Fatalf("list = %+v", list)
	}
	st := must(store.ReadStatus())(t)
	if st.Error == "" || st.LastSuccess.IsZero() {
		t.Fatalf("status = %+v", st)
	}
}

func TestTrustBackupCreateRunsOnItsSchedule(t *testing.T) {
	env, args := trustVolumes(t)
	n := 0
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	deps := trustBackupDeps{exportMySQL: fakeExport, getenv: getenvFrom(env), now: func() time.Time {
		n++
		if n >= 3 {
			cancel()
		}
		return time.Date(2026, 10, 7, 3, n, 0, 0, time.UTC)
	}}
	var out, errOut bytes.Buffer
	code := runTrustBackup(ctx, append([]string{"create", "--every", "1ms", "--retry", "1ms"}, args...), &out, &errOut, deps)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if list := must((&trustbackup.Store{Dir: env["TEST_BACKUP_DIR"]}).List())(t); len(list) < 2 {
		t.Fatalf("the loop wrote %d bundles", len(list))
	}
}

func TestTrustBackupCommandLineRefusals(t *testing.T) {
	env, args := trustVolumes(t)
	deps := trustBackupDeps{exportMySQL: fakeExport, getenv: getenvFrom(env)}
	for name, argv := range map[string][]string{
		"no step":            nil,
		"an unknown step":    {"explode"},
		"create with no dir": {"create", "--path", "a=/x"},
		"create, no item":    {"create", "--dir", t.TempDir()},
		"a malformed path":   {"create", "--dir", t.TempDir(), "--path", "noequals"},
		"a malformed mysql":  {"create", "--dir", t.TempDir(), "--mysql", "db=nohostport"},
		"a mysql, no name":   {"create", "--dir", t.TempDir(), "--mysql", "nohostport"},
		"a malformed value":  {"create", "--dir", t.TempDir(), "--value", "x"},
		"a malformed owner":  append(append([]string{"create"}, args...), "--owner", "root"),
		"an unset value":     {"create", "--dir", t.TempDir(), "--value", "x=UNSET_VAR"},
		"a stray argument":   append(append([]string{"create"}, args...), "extra"),
		"drill, extra arg":   {"drill", "extra"},
		"fetch, extra arg":   {"fetch", "extra"},
		"an unknown flag":    {"create", "--nope"},
	} {
		var out, errOut bytes.Buffer
		if code := runTrustBackup(t.Context(), argv, &out, &errOut, deps); code != exitUsage {
			t.Errorf("%s: exit %d, want %d; stderr: %s", name, code, exitUsage, errOut.String())
		}
	}
	var out, errOut bytes.Buffer
	if code := runTrustBackup(t.Context(), []string{"create", "-h"}, &out, &errOut, deps); code != exitOK {
		t.Errorf("-h: exit %d", code)
	}
}

func TestTrustBackupDrillRefusesWhatItCannotOpen(t *testing.T) {
	env, args := trustVolumes(t)
	deps := trustBackupDeps{exportMySQL: fakeExport, getenv: getenvFrom(env)}
	var out, errOut bytes.Buffer
	// Nothing kept yet.
	if code := runTrustBackup(t.Context(), []string{"drill", "--dir", env["TEST_BACKUP_DIR"],
		"--identity", env["TEST_IDENTITY_FILE"]}, &out, &errOut, deps); code != exitTrustBackupFailed {
		t.Fatalf("empty: exit %d", code)
	}
	if code := runTrustBackup(t.Context(), append([]string{"create"}, args...), &out, &errOut, deps); code != exitOK {
		t.Fatal(errOut.String())
	}
	// The wrong identity.
	other := must(age.GenerateX25519Identity())(t)
	wrong := filepath.Join(t.TempDir(), "id")
	if err := os.WriteFile(wrong, []byte(other.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runTrustBackup(t.Context(), []string{"drill", "--dir", env["TEST_BACKUP_DIR"],
		"--identity", wrong}, &out, &errOut, deps); code != exitTrustBackupFailed {
		t.Fatalf("wrong identity: exit %d", code)
	}
	// Extracting with the wrong identity leaves no directory behind.
	dst := filepath.Join(t.TempDir(), "restore")
	if code := runTrustBackup(t.Context(), []string{"drill", "--dir", env["TEST_BACKUP_DIR"],
		"--identity", wrong, "--extract", dst}, &out, &errOut, deps); code != exitTrustBackupFailed {
		t.Fatalf("wrong identity, extracting: exit %d", code)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("a failed extraction left %s: %v", dst, err)
	}
	// An extraction target that already exists is refused.
	if code := runTrustBackup(t.Context(), []string{"drill", "--dir", env["TEST_BACKUP_DIR"],
		"--identity", env["TEST_IDENTITY_FILE"], "--extract", t.TempDir()}, &out, &errOut, deps); code != exitTrustBackupFailed {
		t.Fatalf("existing target: exit %d", code)
	}
	// No identity file.
	if code := runTrustBackup(t.Context(), []string{"drill", "--dir", env["TEST_BACKUP_DIR"],
		"--identity", filepath.Join(t.TempDir(), "absent")}, &out, &errOut, deps); code != exitTrustBackupFailed {
		t.Fatalf("no identity: exit %d", code)
	}
	// Ciphertext that no longer matches its outer checksum.
	e := must((&trustbackup.Store{Dir: env["TEST_BACKUP_DIR"]}).Latest())(t)
	p := filepath.Join(env["TEST_BACKUP_DIR"], e.Name)
	b := must(os.ReadFile(p))(t)
	b = append(b, 'x')
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	errOut.Reset()
	if code := runTrustBackup(t.Context(), []string{"drill", "--dir", env["TEST_BACKUP_DIR"],
		"--identity", env["TEST_IDENTITY_FILE"]}, &out, &errOut, deps); code != exitTrustBackupFailed ||
		!strings.Contains(errOut.String(), "checksum") {
		t.Fatalf("tampered: exit %d: %s", code, errOut.String())
	}
}

func TestTrustBackupDrillNamesAMissingItem(t *testing.T) {
	env, _ := trustVolumes(t)
	id, err := trustbackup.LoadIdentities(env["TEST_IDENTITY_FILE"], nil)
	if err != nil {
		t.Fatal(err)
	}
	x, ok := id[0].(*age.X25519Identity)
	if !ok {
		t.Fatal("not x25519")
	}
	store := &trustbackup.Store{Dir: env["TEST_BACKUP_DIR"], Keep: 2}
	if _, _, err := store.Create([]age.Recipient{x.Recipient()},
		[]trustbackup.Source{trustbackup.ValueSource("fulcio-pki", "ca.key", []byte("k"))}); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := runTrustBackup(t.Context(), []string{"drill", "--dir", env["TEST_BACKUP_DIR"],
		"--identity", env["TEST_IDENTITY_FILE"]}, &out, &errOut, trustBackupDeps{exportMySQL: fakeExport, getenv: getenvFrom(env)})
	if code != exitTrustBackupFailed || !strings.Contains(out.String(), "MISSING") ||
		!strings.Contains(out.String(), "trillian-db") {
		t.Fatalf("exit %d:\n%s\n%s", code, out.String(), errOut.String())
	}
}

func TestTrustBackupFetchKeepsTheCoresNewestBundle(t *testing.T) {
	f := newConnectFixture(t)
	if code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile,
		"--managed-settings", f.settings, "--no-service"); code != exitOK {
		t.Fatalf("connect: %s", stderr)
	}
	coreDir, e := backupDirWithOne(t)
	h := trustBackupHandler(coreDir, operatorMachine(), newBackupLimiter(nil), newServeLog(os.Stderr))
	f.core.Mux.Handle(coreTrustBackupPath, withInstallation("inst-1", h))
	f.core.Mux.Handle(coreTrustBackupPath+"/", withInstallation("inst-1", h))

	var out, errOut bytes.Buffer
	deps := trustBackupDeps{getenv: func(string) string { return "" }, home: f.home}
	if code := runTrustBackup(t.Context(), []string{"fetch"}, &out, &errOut, deps); code != exitOK {
		t.Fatalf("fetch: exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), e.Name) {
		t.Fatalf("fetch output: %s", out.String())
	}
	if _, err := os.Stat(filepath.Join(client.ClientPaths(f.home).TrustBackups, e.Name)); err != nil {
		t.Fatal(err)
	}
	// Not enrolled: a clear failure.
	if code := runTrustBackup(t.Context(), []string{"fetch"}, &out, &errOut,
		trustBackupDeps{getenv: deps.getenv, home: t.TempDir()}); code != exitTrustBackupFailed {
		t.Fatalf("unenrolled: exit %d", code)
	}
}

// withInstallation stands in for the core's client guard: it names the
// installation the certificate belongs to.
func withInstallation(id string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(gateway.WithInstallation(r.Context(), id)))
	})
}

// must answers v, and ends the test on err: must(f())(t).
func must[T any](v T, err error) func(*testing.T) T {
	return func(t *testing.T) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}
