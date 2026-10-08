// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// The error paths and fallbacks of the reference resources (MCP-101..105):
// every branch of reference.go is taken by a page set built for it.

// failingFS lists its pages, or refuses to, and refuses to read the ones
// named in unreadable.
type failingFS struct {
	fstest.MapFS
	listErr    error
	unreadable string
}

func (f failingFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.MapFS.ReadDir(name)
}

func (f failingFS) Open(name string) (fs.File, error) {
	if name == f.unreadable {
		return nil, errors.New("unreadable")
	}
	return f.MapFS.Open(name)
}

func (f failingFS) ReadFile(name string) ([]byte, error) {
	if name == f.unreadable {
		return nil, errors.New("unreadable")
	}
	return f.MapFS.ReadFile(name)
}

func newSDK() *sdk.Server {
	return sdk.NewServer(&sdk.Implementation{Name: "t", Version: "v0"}, nil)
}

func TestReferencePagesThatCannotBeListedRefuseTheServer(t *testing.T) {
	if err := addReference(newSDK(), failingFS{listErr: errors.New("no listing")}); err == nil {
		t.Fatal("a page set that cannot be listed was accepted")
	}
}

func TestReferenceAPageThatCannotBeReadRefusesTheServer(t *testing.T) {
	pages := failingFS{MapFS: fstest.MapFS{"a.md": {Data: []byte("# A\n")}}, unreadable: "a.md"}
	if err := addReference(newSDK(), pages); err == nil {
		t.Fatal("an unreadable page was accepted")
	}
}

func TestReferenceSkipsWhatIsNotAPage(t *testing.T) {
	pages := fstest.MapFS{
		"a.md":      {Data: []byte("# A\n")},
		"notes.txt": {Data: []byte("x")},
		"sub/b.md":  {Data: []byte("# B\n")},
	}
	if err := addReference(newSDK(), pages); err != nil {
		t.Fatal(err)
	}
}

func TestNewRefusesAReferenceSetItCannotRead(t *testing.T) {
	was := referenceFS
	t.Cleanup(func() { referenceFS = was })
	referenceFS = failingFS{listErr: errors.New("no listing")}
	if _, err := New(Config{Version: "v0.0.0-test"}); err == nil {
		t.Fatal("New started with reference pages it could not read")
	}
}

func TestPageTitle(t *testing.T) {
	for body, want := range map[string]string{
		"# Title\nx":             "Title",
		"intro\n# Later title\n": "Later title",
		"no heading at all\n":    "",
		"":                       "",
	} {
		if got := pageTitle([]byte(body)); got != want {
			t.Errorf("pageTitle(%q) = %q, want %q", body, got, want)
		}
	}
}

func TestPurposeLine(t *testing.T) {
	for body, want := range map[string]string{
		"# T\n## Purpose\n\nWhat it is.\n## Next\n": "What it is.",
		"# T\n## Purpose\n## Commands\nx\n":         "",
		"# T\n## Other\nx\n":                        "",
		"# T\n## Purpose\n":                         "",
	} {
		if got := purposeLine([]byte(body)); got != want {
			t.Errorf("purposeLine(%q) = %q, want %q", body, got, want)
		}
	}
}

func TestReferenceAPageWithoutATitleIsNamedByItsFile(t *testing.T) {
	s := newSDK()
	if err := addReference(s, fstest.MapFS{"untitled.md": {Data: []byte("no heading\n")}}); err != nil {
		t.Fatal(err)
	}
}
