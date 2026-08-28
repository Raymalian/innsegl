// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// mutatingVerbs are the names a delete-or-update surface would be spelled
// with. LED-003 belongs to the storage layer (RM-009), but the API that layer
// wraps is this one: an append-only ledger cannot expose a mutating call here
// and then claim not to expose one there (I4).
var mutatingVerbs = []string{
	"Delete", "Remove", "Drop", "Truncate", "Purge", "Erase",
	"Update", "Set", "Replace", "Rewrite", "Mutate", "Overwrite", "Patch",
}

// TestNoMutatingSurface reads the package's own source and fails if any
// exported function, method or type name reads as a mutation.
func TestNoMutatingSurface(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}

	fset := token.NewFileSet()
	var (
		scanned  int
		exported []string
	)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		scanned++
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Name.IsExported() {
					exported = append(exported, d.Name.Name)
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					if ts, ok := spec.(*ast.TypeSpec); ok && ts.Name.IsExported() {
						exported = append(exported, ts.Name.Name)
					}
				}
			}
		}
	}

	if scanned == 0 {
		t.Fatal("no non-test package source found; the scan proves nothing")
	}
	if len(exported) == 0 {
		t.Fatal("the package exports nothing; the scan proves nothing")
	}

	for _, name := range exported {
		for _, verb := range mutatingVerbs {
			if strings.HasPrefix(name, verb) {
				t.Errorf("exported %s reads as a mutating call; the ledger appends and nothing else (I4)",
					name)
			}
		}
	}
	t.Logf("scanned %d source file(s), %d exported names: %v", scanned, len(exported), exported)
}
