// SPDX-License-Identifier: Apache-2.0

package client

import (
	"errors"
	"os"
	"runtime"
	"testing"
)

// ENF-011 (PROPOSED for doc 07) — the per-repository author setting.
//
// Agent commits are authored as the unlinked agent address by default. A
// repository the operator sets to `operator` is authored as the operator's own
// identity instead, which I6 allows ("the human operator or a deliberately
// unlinked address"); the agent stays in the trailers and the signature. The
// identity is stated once, and only a value the hook can single-quote safely
// is stored.

const testOperator = "Op Erator <1+op@users.noreply.github.com>"

func TestENF011NoFileMeansEveryRepositoryIsAgentMode(t *testing.T) {
	p := ClientPaths(t.TempDir())
	a, err := ReadAuthors(p)
	if err != nil {
		t.Fatalf("ReadAuthors with no file: %v", err)
	}
	if _, _, ok := a.OperatorFor("/any/repo/.git"); ok {
		t.Fatal("a repository nobody set is in operator mode")
	}
}

func TestENF011AnOperatorRepositoryCarriesTheOperatorIdentity(t *testing.T) {
	p := ClientPaths(t.TempDir())
	a, err := Authors{}.SetOperator(testOperator)
	if err != nil {
		t.Fatalf("SetOperator: %v", err)
	}
	if a, err = a.SetRepo("/r/.git", AuthorOperator); err != nil {
		t.Fatalf("SetRepo: %v", err)
	}
	if err = WriteAuthors(p, a); err != nil {
		t.Fatalf("WriteAuthors: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, serr := os.Stat(p.Authors)
		if serr != nil {
			t.Fatal(serr)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("authors file mode = %v, want 0600", info.Mode().Perm())
		}
	}
	got, err := ReadAuthors(p)
	if err != nil {
		t.Fatalf("ReadAuthors: %v", err)
	}
	name, email, ok := got.OperatorFor("/r/.git")
	if !ok || name != "Op Erator" || email != "1+op@users.noreply.github.com" {
		t.Fatalf("OperatorFor = %q %q %v, want the operator", name, email, ok)
	}
	if _, _, ok := got.OperatorFor("/other/.git"); ok {
		t.Fatal("a repository that was not set is in operator mode")
	}
	back, err := got.SetRepo("/r/.git", AuthorAgent)
	if err != nil {
		t.Fatalf("SetRepo agent: %v", err)
	}
	if _, _, ok := back.OperatorFor("/r/.git"); ok {
		t.Fatal("a repository set back to agent mode is still in operator mode")
	}
}

func TestENF011RefusesAnIdentityTheHookCannotQuote(t *testing.T) {
	for _, bad := range []string{
		"",
		"no address",
		"Name <>",
		"O'Brien <1+ob@users.noreply.github.com>",
		"Two\nLines <1+tl@users.noreply.github.com>",
		"Tab\tName <1+tn@users.noreply.github.com>",
	} {
		if _, err := (Authors{}).SetOperator(bad); !errors.Is(err, ErrAuthorIdentity) {
			t.Errorf("SetOperator(%q) = %v, want %v", bad, err, ErrAuthorIdentity)
		}
	}
}

// Operator mode needs no typed identity (#545): the hook reads the
// repository's own noreply address (ENF-013). The override stays optional.
func TestENF011OperatorModeNeedsNoTypedIdentity(t *testing.T) {
	a, err := (Authors{}).SetRepo("/r/.git", AuthorOperator)
	if err != nil {
		t.Fatalf("SetRepo operator with no typed identity = %v, want nil", err)
	}
	if !a.IsOperator("/r/.git") {
		t.Fatal("the repository is not in operator mode")
	}
	if _, _, ok := a.OperatorFor("/r/.git"); ok {
		t.Fatal("OperatorFor answered a typed identity that was never set")
	}
	if _, err := (Authors{}).SetRepo("/r/.git", "someone"); err == nil {
		t.Fatal("SetRepo accepted a mode that is neither agent nor operator")
	}
}
