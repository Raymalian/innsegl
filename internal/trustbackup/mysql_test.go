// SPDX-License-Identifier: Apache-2.0

package trustbackup

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func TestSQLValueKeepsNumbersAndHexesTheRest(t *testing.T) {
	cases := []struct {
		typ  string
		in   []byte
		want string
		bad  bool
	}{
		{"BIGINT", []byte("-42"), "-42", false},
		{"UNSIGNED BIGINT", []byte("18446744073709551615"), "18446744073709551615", false},
		{"DECIMAL", []byte("3.50"), "3.50", false},
		{"DOUBLE", []byte("1e-07"), "1e-07", false},
		{"VARCHAR", []byte("it's"), "X'69742773'", false},
		{"BLOB", []byte{0, 1, 0xff}, "X'0001ff'", false},
		{"ENUM", []byte("LOG"), "X'4c4f47'", false},
		{"VARBINARY", []byte{}, "X''", false},
		{"INT", nil, "NULL", false},
		{"BLOB", nil, "NULL", false},
		{"INT", []byte("1); DROP TABLE x; --"), "", true},
	}
	for _, c := range cases {
		got, err := sqlValue(c.typ, c.in)
		if c.bad {
			if err == nil {
				t.Errorf("%s %q: accepted", c.typ, c.in)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("sqlValue(%s, %q) = %q, %v; want %q", c.typ, c.in, got, err, c.want)
		}
	}
	if q := quoteIdent("a`b"); q != "`a``b`" {
		t.Errorf("quoteIdent = %s", q)
	}
}

func TestExportMySQLRefusesADatabaseItCannotReach(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cfg := mysql.NewConfig()
	cfg.Net, cfg.Addr, cfg.User, cfg.DBName = "tcp", "127.0.0.1:1", "u", "d"
	cfg.Timeout = time.Second
	if err := ExportMySQL(ctx, cfg.FormatDSN(), &bytes.Buffer{}); err == nil {
		t.Fatal("an export of nothing succeeded")
	}
	if err := ExportMySQL(ctx, "::not a dsn::", &bytes.Buffer{}); err == nil {
		t.Fatal("a malformed DSN was accepted")
	}
}

// trillianDBImage is the transparency log's database image, as sigstore.yml
// pins it: the export is measured against the server it will read.
const trillianDBImage = "gcr.io/trillian-opensource-ci/db_server:v1.4.0@sha256:0794abd3bdf44a567f5d6ef18a0b76802f388611b63aae33eaf28c3b0c5964d8"

func docker(ctx context.Context, stdin []byte, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// The export is consistent, restores with the stock client into an empty
// database, and the restored tables are byte-identical: CHECKSUM TABLE
// agrees for every table, Trillian's own included.
func TestExportMySQLRestoresByteIdenticalWithTheStockClient(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed; this test runs the transparency log's own database image")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	id, err := docker(ctx, nil, "run", "--detach", "--platform", "linux/amd64", "--publish", "127.0.0.1:"+port+":3306",
		"--env", "MYSQL_ROOT_PASSWORD=root-test", "--env", "MYSQL_DATABASE=test",
		"--env", "MYSQL_USER=test", "--env", "MYSQL_PASSWORD=zaphod", trillianDBImage)
	if err != nil {
		t.Fatalf("start the log database: %v", err)
	}
	t.Cleanup(func() {
		if _, rerr := docker(context.Background(), nil, "rm", "--force", "--volumes", id); rerr != nil {
			t.Error(rerr)
		}
	})

	root := mysql.NewConfig()
	root.Net, root.Addr, root.User, root.Passwd, root.DBName = "tcp", "127.0.0.1:"+port, "root", "root-test", "test"
	root.MultiStatements = true
	db, err := sql.Open("mysql", root.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	deadline := time.Now().Add(4 * time.Minute)
	for {
		// The image starts twice; the tables exist only after the second.
		var n int
		qerr := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'test'`).Scan(&n)
		if qerr == nil && n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the log database did not come up: %v (%d tables)", qerr, n)
		}
		time.Sleep(2 * time.Second)
	}
	if _, err = db.ExecContext(ctx, `
		CREATE TABLE parent (id BIGINT UNSIGNED PRIMARY KEY, note VARCHAR(64) CHARACTER SET utf8mb4, kind ENUM('LOG','MAP'));
		CREATE TABLE child (id INT PRIMARY KEY, parent BIGINT UNSIGNED, body MEDIUMBLOB, hash VARBINARY(32), score DOUBLE,
			FOREIGN KEY (parent) REFERENCES parent (id));
		INSERT INTO parent VALUES (18446744073709551615, 'it''s ä \\ "quoted"', 'LOG'), (1, NULL, NULL);
		INSERT INTO child VALUES (1, 1, X'00ff0d0a27225c', X'', 1e-7), (2, 18446744073709551615, NULL, NULL, NULL);
	`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	user := mysql.NewConfig()
	user.Net, user.Addr, user.User, user.Passwd, user.DBName = "tcp", "127.0.0.1:"+port, "test", "zaphod", "test"
	var dump bytes.Buffer
	if err = ExportMySQL(ctx, user.FormatDSN(), &dump); err != nil {
		t.Fatalf("ExportMySQL: %v", err)
	}
	if _, err = db.ExecContext(ctx, `CREATE DATABASE restored`); err != nil {
		t.Fatal(err)
	}
	if out, derr := docker(ctx, dump.Bytes(), "exec", "-i", id, "mysql", "-uroot", "-proot-test", "restored"); derr != nil {
		t.Fatalf("the stock client did not restore the export: %v\n%s", derr, out)
	}

	tables, err := tableNames(ctx, db, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(tables) < 9 {
		t.Fatalf("only %d tables: %v", len(tables), tables)
	}
	for _, tbl := range tables {
		a, aerr := checksum(ctx, db, "test", tbl)
		b, berr := checksum(ctx, db, "restored", tbl)
		if err := errors.Join(aerr, berr); err != nil || a != b {
			t.Errorf("%s: checksum %s, restored %s (%v)", tbl, a, b, err)
		}
	}
}

func tableNames(ctx context.Context, db *sql.DB, schema string) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT table_name FROM information_schema.tables
		WHERE table_schema = ? AND table_type = 'BASE TABLE' ORDER BY table_name`, schema)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func checksum(ctx context.Context, db *sql.DB, schema, table string) (string, error) {
	var name string
	var sum sql.NullString
	err := db.QueryRowContext(ctx, "CHECKSUM TABLE "+quoteIdent(schema)+"."+quoteIdent(table)).Scan(&name, &sum)
	return sum.String, err
}
