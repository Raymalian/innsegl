// SPDX-License-Identifier: Apache-2.0

// Package migrations carries the ledger's SQL schema as embedded files.
//
// The schema is data, not generated code: it ships in the binary so that a
// deployment cannot drift from the code that writes to it, and it is applied
// by internal/ledger's own runner rather than by a third-party migration tool.
// The runner is deliberately small — apply each file once, in name order,
// inside one transaction, and record it — because a migration framework is a
// large trusted dependency standing between the code and the one table whose
// contents can never be rewritten.
//
// Files are named NNNN_name.sql. The numeric prefix is the version and is
// never reused: a released migration is immutable, and a change to the schema
// is a new file (VERSIONING.md).
package migrations

import (
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"
)

//go:embed *.sql
var files embed.FS

// FS exposes the raw migration files.
func FS() fs.FS { return files }

// Migration is one numbered SQL file.
type Migration struct {
	// Version is the numeric prefix, e.g. "0001". Unique and never reused.
	Version string
	// Name is the file name, carried into the applied-migrations table so an
	// operator can see what ran without consulting the source tree.
	Name string
	// SQL is the file's contents.
	SQL string
}

var namePattern = regexp.MustCompile(`^(\d{4})_[a-z0-9_]+\.sql$`)

// All returns every migration in version order.
//
// A file that does not match NNNN_name.sql is an error rather than something
// skipped: a migration the runner silently ignores is a schema change that
// silently did not happen.
func All() ([]Migration, error) {
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}

	out := make([]Migration, 0, len(entries))
	seen := make(map[string]string, len(entries))
	for _, e := range entries {
		name := e.Name()
		m := namePattern.FindStringSubmatch(name)
		if m == nil {
			return nil, fmt.Errorf("migration %q is not named NNNN_name.sql", name)
		}
		if prev, dup := seen[m[1]]; dup {
			return nil, fmt.Errorf("migrations %q and %q share version %s", prev, name, m[1])
		}
		seen[m[1]] = name

		body, rerr := fs.ReadFile(files, name)
		if rerr != nil {
			return nil, fmt.Errorf("read %s: %w", name, rerr)
		}
		if strings.TrimSpace(string(body)) == "" {
			return nil, fmt.Errorf("migration %s is empty", name)
		}
		out = append(out, Migration{Version: m[1], Name: name, SQL: string(body)})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no migrations are embedded")
	}
	slices.SortFunc(out, func(a, b Migration) int { return strings.Compare(a.Version, b.Version) })
	return out, nil
}
