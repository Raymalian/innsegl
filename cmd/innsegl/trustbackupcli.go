// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/go-sql-driver/mysql"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/trustbackup"
)

// `innsegl trust-backup` (ADR-0074): the encrypted trust-key backup.
//
//	create   on the core: write a bundle of the trust volumes, once or on a
//	         schedule. Encrypts to INNSEGL_TRUST_BACKUP_RECIPIENTS.
//	fetch    on the operator's machine: keep the core's newest bundle now.
//	drill    on the operator's machine: open the newest kept bundle, check
//	         every checksum, and say what it holds.

// exitTrustBackupFailed is a bundle that was not written, fetched or opened.
const exitTrustBackupFailed = 26

// The log database's credentials, for --mysql. In the environment, so the
// password is never on a command line.
const (
	envTrustBackupMySQLUser     = "INNSEGL_TRUST_BACKUP_MYSQL_USER"
	envTrustBackupMySQLPassword = "INNSEGL_TRUST_BACKUP_MYSQL_PASSWORD" //nolint:gosec // G101: a variable's name, not its value
)

// expectedTrustItems are the items a deployment's bundle holds (ADR-0074).
// The drill names any one that is missing.
var expectedTrustItems = []string{
	"fulcio-pki", "fulcio-ca-password", "rekor-key", "trillian-db",
	"identity-secret", "spire-upstream-ca", "gateway-ca-key", "trust-history",
}

type trustBackupDeps struct {
	getenv func(string) string
	now    func() time.Time
	// exportMySQL is trustbackup.ExportMySQL unless a test replaces it.
	exportMySQL func(ctx context.Context, dsn string, w io.Writer) error
	// home is the operator's home, for fetch and drill's defaults.
	home string
}

func trustBackupCommand(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	home, err := os.UserHomeDir()
	if err != nil {
		fprintf(stderr, "innsegl trust-backup: %v\n", err)
		return exitUsage
	}
	return runTrustBackup(ctx, args, stdout, stderr, trustBackupDeps{getenv: os.Getenv, home: home})
}

func trustBackupUsage(w io.Writer) {
	fprintf(w, "usage: innsegl trust-backup <create|fetch|drill> [flags]\n\n"+
		"  create  write an encrypted bundle of the trust volumes (on the core)\n"+
		"  fetch   keep the core's newest bundle on this machine now\n"+
		"  drill   open the newest kept bundle, check every checksum, say what it holds\n")
}

func runTrustBackup(ctx context.Context, args []string, stdout, stderr io.Writer, deps trustBackupDeps) int {
	if deps.now == nil {
		deps.now = time.Now
	}
	if deps.exportMySQL == nil {
		deps.exportMySQL = trustbackup.ExportMySQL
	}
	if len(args) == 0 {
		trustBackupUsage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "-h", "--help", "help":
		trustBackupUsage(stdout)
		return exitOK
	case "create":
		return runTrustBackupCreate(ctx, args[1:], stdout, stderr, deps)
	case "fetch":
		return runTrustBackupFetch(ctx, args[1:], stdout, stderr, deps)
	case "drill":
		return runTrustBackupDrill(args[1:], stdout, stderr, deps)
	}
	fprintf(stderr, "innsegl trust-backup: unknown step %q\n\n", args[0])
	trustBackupUsage(stderr)
	return exitUsage
}

// multiFlag collects a repeated NAME=VALUE flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func splitPair(v string) (string, string, error) {
	name, val, ok := strings.Cut(v, "=")
	if !ok || name == "" || val == "" {
		return "", "", fmt.Errorf("%q is not NAME=VALUE", v)
	}
	return name, val, nil
}

// parseFlags parses fs and answers an exit code when the command should end.
func parseFlags(fs *flag.FlagSet, args []string) (int, bool) {
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		return exitOK, true
	} else if err != nil {
		return exitUsage, true
	}
	if fs.NArg() != 0 {
		fprintf(fs.Output(), "innsegl trust-backup %s: unexpected argument %q\n", fs.Name(), fs.Arg(0))
		return exitUsage, true
	}
	return 0, false
}

func runTrustBackupCreate(ctx context.Context, args []string, stdout, stderr io.Writer, deps trustBackupDeps) int {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "the directory bundles are kept in (required)")
	keep := fs.Int("keep", 14, "how many bundles to keep")
	every := fs.Duration("every", 0, "write a bundle at this interval until stopped; 0 writes one and exits")
	retry := fs.Duration("retry", 15*time.Minute, "after a failed run, try again this soon (never later than --every)")
	ownerFlag := fs.String("owner", "", "UID:GID to give the directory and every file to; empty leaves them as written")
	var paths, mysqls, values multiFlag
	fs.Var(&paths, "path", "NAME=PATH: a file or directory to back up (repeatable)")
	fs.Var(&mysqls, "mysql", "NAME=HOST:PORT/DATABASE: a MySQL database to export, consistently and without stopping it (repeatable)")
	fs.Var(&values, "value", "NAME=ENVVAR: a value from the environment, such as a key's password (repeatable)")
	if code, done := parseFlags(fs, args); done {
		return code
	}
	if *dir == "" {
		fprintf(stderr, "innsegl trust-backup create: --dir is required\n")
		return exitUsage
	}
	sources, err := trustBackupSources(ctx, paths, mysqls, values, deps)
	if err != nil {
		fprintf(stderr, "innsegl trust-backup create: %v\n", err)
		return exitUsage
	}
	store := &trustbackup.Store{Dir: *dir, Keep: *keep, Now: deps.now}
	if *ownerFlag != "" {
		if store.Owner, err = trustbackup.ParseOwner(*ownerFlag); err != nil {
			fprintf(stderr, "innsegl trust-backup create: %v\n", err)
			return exitUsage
		}
	}
	for {
		ok := createTrustBackupOnce(store, sources, stdout, stderr, deps)
		if *every <= 0 {
			if ok {
				return exitOK
			}
			return exitTrustBackupFailed
		}
		wait := *every
		if !ok {
			wait = min(*retry, *every)
		}
		select {
		case <-ctx.Done():
			return exitOK
		case <-time.After(wait):
		}
	}
}

// createTrustBackupOnce writes one bundle and the status beside it. The
// recipients are read on every run, so setting them needs no restart.
func createTrustBackupOnce(store *trustbackup.Store, sources []trustbackup.Source, stdout, stderr io.Writer, deps trustBackupDeps) bool {
	// The last success carries over; a first run has no status to read.
	st := trustbackup.Status{LastAttempt: deps.now().UTC()}
	if prev, perr := store.ReadStatus(); perr == nil {
		st.LastSuccess, st.Latest = prev.LastSuccess, prev.Latest
	}
	recipients, err := trustbackup.ParseRecipients(deps.getenv(trustbackup.EnvRecipients))
	var e trustbackup.Entry
	var m trustbackup.Manifest
	if err == nil {
		e, m, err = store.Create(recipients, sources)
	}
	if err != nil {
		st.Error = err.Error()
		fprintf(stderr, "innsegl trust-backup create: NO BUNDLE WRITTEN: %v\n", err)
	} else {
		st.LastSuccess, st.Latest = st.LastAttempt, e.Name
		fprintf(stdout, "innsegl trust-backup create: wrote %s: %d items, %d files, %d bytes before encryption\n",
			e.Name, len(m.Items), m.Files(), m.Bytes())
	}
	if serr := store.WriteStatus(st); serr != nil {
		fprintf(stderr, "innsegl trust-backup create: writing the status: %v\n", serr)
	}
	return err == nil
}

func trustBackupSources(ctx context.Context, paths, mysqls, values multiFlag, deps trustBackupDeps) ([]trustbackup.Source, error) {
	var out []trustbackup.Source
	for _, v := range paths {
		name, p, err := splitPair(v)
		if err != nil {
			return nil, err
		}
		out = append(out, trustbackup.PathSource(name, p))
	}
	for _, v := range mysqls {
		name, target, err := splitPair(v)
		if err != nil {
			return nil, err
		}
		hostport, db, ok := strings.Cut(target, "/")
		if _, _, herr := net.SplitHostPort(hostport); !ok || db == "" || herr != nil {
			return nil, fmt.Errorf("--mysql %q: want NAME=HOST:PORT/DATABASE", v)
		}
		cfg := mysql.NewConfig()
		cfg.Net, cfg.Addr, cfg.DBName = "tcp", hostport, db
		cfg.User, cfg.Passwd = deps.getenv(envTrustBackupMySQLUser), deps.getenv(envTrustBackupMySQLPassword)
		cfg.Timeout = 30 * time.Second
		dsn := cfg.FormatDSN()
		export := deps.exportMySQL
		out = append(out, trustbackup.StreamSource(name, "trillian.sql",
			func(w io.Writer) error { return export(ctx, dsn, w) }))
	}
	for _, v := range values {
		name, env, err := splitPair(v)
		if err != nil {
			return nil, err
		}
		val := deps.getenv(env)
		if val == "" {
			return nil, fmt.Errorf("--value %s: %s is unset", name, env)
		}
		out = append(out, trustbackup.ValueSource(name, "value", []byte(val)))
	}
	if len(out) == 0 {
		return nil, errors.New("nothing to back up: give --path, --mysql or --value")
	}
	return out, nil
}

func runTrustBackupFetch(ctx context.Context, args []string, stdout, stderr io.Writer, deps trustBackupDeps) int {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if code, done := parseFlags(fs, args); done {
		return code
	}
	paths := client.ClientPaths(deps.home)
	store := &trustbackup.Store{Dir: paths.TrustBackups, Keep: client.TrustBackupKeep}
	e, fetched, err := client.FetchTrustBackup(ctx, paths, store)
	if err != nil {
		fprintf(stderr, "innsegl trust-backup fetch: %v\n", err)
		return exitTrustBackupFailed
	}
	verb := "already kept"
	if fetched {
		verb = "kept"
	}
	fprintf(stdout, "innsegl trust-backup fetch: %s %s in %s\n", verb, e.Name, paths.TrustBackups)
	return exitOK
}

func runTrustBackupDrill(args []string, stdout, stderr io.Writer, deps trustBackupDeps) int {
	fs := flag.NewFlagSet("drill", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", client.ClientPaths(deps.home).TrustBackups, "the directory the bundles are kept in")
	identity := fs.String("identity", filepath.Join(deps.home, ".innsegl", "trust-backup", "identity.txt"),
		"the age identity file that opens the bundle (a Secure Enclave identity asks for Touch ID)")
	extract := fs.String("extract", "", "also write the files under this new directory, 0600, for a restore; "+
		"empty checks without writing anything")
	if code, done := parseFlags(fs, args); done {
		return code
	}
	fail := func(err error) int {
		fprintf(stderr, "innsegl trust-backup drill: FAILED: %v\n", err)
		return exitTrustBackupFailed
	}
	store := &trustbackup.Store{Dir: *dir}
	newest, err := store.Latest()
	if err != nil {
		return fail(err)
	}
	ids, err := trustbackup.LoadIdentities(*identity, nil)
	if err != nil {
		return fail(err)
	}
	f, e, err := store.Open(newest.Name)
	if err != nil {
		return fail(err)
	}
	defer func() { _ = f.Close() }()
	// The outer checksum first: a copy that changed since it was fetched is
	// refused before anything asks for Touch ID.
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return fail(err)
	}
	if hex.EncodeToString(h.Sum(nil)) != e.SHA256 {
		return fail(fmt.Errorf("%s does not match its outer checksum %s", e.Name, e.SHA256))
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	if *extract != "" {
		if err = os.Mkdir(*extract, 0o700); err != nil {
			return fail(err)
		}
	}
	m, err := trustbackup.ReadBundle(f, ids, *extract)
	if err != nil {
		if *extract != "" {
			_ = os.RemoveAll(*extract)
		}
		return fail(err)
	}
	return printDrill(stdout, e, m, *extract)
}

func printDrill(stdout io.Writer, e trustbackup.Entry, m trustbackup.Manifest, extracted string) int {
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "bundle\t%s\twritten %s, %d bytes encrypted\n", e.Name, m.CreatedAt.Format(time.RFC3339), e.Size)
	have := map[string]bool{}
	for _, it := range m.Items {
		have[it.Name] = true
		var n int64
		for _, f := range it.Files {
			n += f.Size
		}
		fmt.Fprintf(tw, "item\t%s\t%d files, %d bytes\n", it.Name, len(it.Files), n)
		for _, f := range it.Files {
			fmt.Fprintf(tw, "\t  %s\t%d bytes, sha256 %s\n", f.Path, f.Size, f.SHA256[:16])
		}
	}
	missing := 0
	for _, want := range expectedTrustItems {
		if !have[want] {
			missing++
			fmt.Fprintf(tw, "item\t%s\tMISSING from this bundle\n", want)
		}
	}
	fmt.Fprintf(tw, "check\tok\tevery checksum matches: %d files, %d bytes\n", m.Files(), m.Bytes())
	if extracted != "" {
		fmt.Fprintf(tw, "extracted\t\tplaintext keys in %s: remove it when the restore is done\n", extracted)
	}
	if err := tw.Flush(); err != nil || missing > 0 {
		return exitTrustBackupFailed
	}
	return exitOK
}
