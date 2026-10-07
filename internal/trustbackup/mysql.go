// SPDX-License-Identifier: Apache-2.0

package trustbackup

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/go-sql-driver/mysql"
)

// The transparency log's database, exported the way scripts/backup-ledger.sh
// exports the ledger: over the network, from one consistent snapshot, without
// stopping the log. MySQL's InnoDB gives that with a REPEATABLE READ
// transaction started WITH CONSISTENT SNAPSHOT; the log keeps writing while
// the export reads the database as it stood at the start.
//
// The output is plain SQL that the stock `mysql` client restores into an
// empty database. It is written here, in Go, rather than by mysqldump, so the
// core's image needs no database client: the export runs in the image every
// core service already uses.

// maxInsert bounds one INSERT statement, well under the server's default
// max_allowed_packet, so a restore never meets a statement it refuses.
const maxInsert = 1 << 20

// ExportMySQL writes every base table of the DSN's database to w as SQL:
// each table's CREATE TABLE, then its rows.
func ExportMySQL(ctx context.Context, dsn string, w io.Writer) (err error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return fmt.Errorf("mysql: %w", err)
	}
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return fmt.Errorf("mysql: %w", err)
	}
	db := sql.OpenDB(connector)
	defer func() { err = errors.Join(err, db.Close()) }()
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("mysql: %w", err)
	}
	defer func() { err = errors.Join(err, conn.Close()) }()
	for _, q := range []string{
		"SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ",
		"START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY",
	} {
		if _, xerr := conn.ExecContext(ctx, q); xerr != nil {
			return fmt.Errorf("mysql: %s: %w", q, xerr)
		}
	}
	defer func() {
		_, rerr := conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
		err = errors.Join(err, rerr)
	}()
	tables, err := baseTables(ctx, conn)
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(w, 256<<10)
	if _, err := fmt.Fprintf(bw, "-- innsegl trust backup: database %s, %d tables, one consistent snapshot\n"+
		"SET NAMES utf8mb4;\nSET FOREIGN_KEY_CHECKS=0;\nSET UNIQUE_CHECKS=0;\n", cfg.DBName, len(tables)); err != nil {
		return err
	}
	for _, t := range tables {
		if err := exportTable(ctx, conn, bw, t); err != nil {
			return fmt.Errorf("mysql: table %s: %w", t, err)
		}
	}
	if _, err := io.WriteString(bw, "SET UNIQUE_CHECKS=1;\nSET FOREIGN_KEY_CHECKS=1;\n-- end\n"); err != nil {
		return err
	}
	return bw.Flush()
}

func baseTables(ctx context.Context, conn *sql.Conn) ([]string, error) {
	rows, err := conn.QueryContext(ctx, "SHOW FULL TABLES")
	if err != nil {
		return nil, fmt.Errorf("mysql: listing tables: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var name, kind string
		if err := rows.Scan(&name, &kind); err != nil {
			return nil, fmt.Errorf("mysql: listing tables: %w", err)
		}
		if kind == "BASE TABLE" {
			out = append(out, name)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mysql: listing tables: %w", err)
	}
	sort.Strings(out)
	return out, nil
}

func exportTable(ctx context.Context, conn *sql.Conn, w io.Writer, table string) error {
	var name, create string
	if err := conn.QueryRowContext(ctx, "SHOW CREATE TABLE "+quoteIdent(table)).Scan(&name, &create); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "\nDROP TABLE IF EXISTS %s;\n%s;\n", quoteIdent(table), create); err != nil {
		return err
	}
	rows, err := conn.QueryContext(ctx, "SELECT * FROM "+quoteIdent(table)) //nolint:gosec // G202: a quoted identifier the server listed, no value
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	types, err := rows.ColumnTypes()
	if err != nil {
		return err
	}
	vals := make([]sql.RawBytes, len(types))
	ptrs := make([]any, len(types))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	var stmt strings.Builder
	flush := func() error {
		if stmt.Len() == 0 {
			return nil
		}
		stmt.WriteString(";\n")
		_, werr := io.WriteString(w, stmt.String())
		stmt.Reset()
		return werr
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		row := make([]string, len(vals))
		for i, v := range vals {
			s, err := sqlValue(types[i].DatabaseTypeName(), v)
			if err != nil {
				return fmt.Errorf("column %s: %w", types[i].Name(), err)
			}
			row[i] = s
		}
		tuple := "(" + strings.Join(row, ",") + ")"
		if stmt.Len() > 0 && stmt.Len()+len(tuple) > maxInsert {
			if err := flush(); err != nil {
				return err
			}
		}
		if stmt.Len() == 0 {
			stmt.WriteString("INSERT INTO " + quoteIdent(table) + " VALUES ")
		} else {
			stmt.WriteString(",")
		}
		stmt.WriteString(tuple)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return flush()
}

var numericText = regexp.MustCompile(`^[-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?$`)

// sqlValue renders one column value as a SQL literal. A number stays a
// number, checked to be one. Everything else is a hex literal, which the
// server converts to the column's type exactly: no quoting or character set
// can change the bytes.
func sqlValue(typ string, v []byte) (string, error) {
	if v == nil {
		return "NULL", nil
	}
	for _, n := range []string{"INT", "DECIMAL", "FLOAT", "DOUBLE", "YEAR"} {
		if strings.Contains(typ, n) {
			if !numericText.Match(v) {
				return "", fmt.Errorf("%s value %q is not a number", typ, v)
			}
			return string(v), nil
		}
	}
	return "X'" + hex.EncodeToString(v) + "'", nil
}

// quoteIdent quotes a MySQL identifier.
func quoteIdent(s string) string { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }
