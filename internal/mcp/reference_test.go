// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"io/fs"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/reference"
)

// The reference pages as MCP resources (PROPOSED for doc 07: MCP-101..105).
//
// MEASURED: an agent in another repository, connected to this system, judged
// signing "down" from ports that only exist on the core, because nothing it
// could reach said how this system works. The server now offers its own
// reference pages, read-only, from the binary, so the text matches the
// running version. Resources are not tools: the protected tool surface is
// unchanged.

// referenceDir is the reference/ directory on disk, from this package.
func referenceDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "reference"))
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// pagesOnDisk is every *.md file in reference/, sorted.
func pagesOnDisk(t *testing.T) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(referenceDir(t), "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, filepath.Base(m))
	}
	slices.Sort(out)
	if len(out) == 0 {
		t.Fatal("reference/ holds no pages")
	}
	return out
}

// MCP-101: resources/list returns one resource per reference page, under the
// innsegl://reference/ scheme, as markdown, named by its title and described
// by the first line of its Purpose section.
func TestMCP101ResourcesListEveryReferencePage(t *testing.T) {
	_, url := serveProbes(t)
	session := connect(t, url)
	listed, err := session.ListResources(t.Context(), nil)
	if err != nil {
		t.Fatalf("resources/list: %v", err)
	}
	var got []string
	for _, r := range listed.Resources {
		page, ok := strings.CutPrefix(r.URI, ReferenceURIPrefix)
		if !ok {
			t.Errorf("resource %q is outside %s", r.URI, ReferenceURIPrefix)
			continue
		}
		got = append(got, page)
		if r.MIMEType != "text/markdown" {
			t.Errorf("%s: mimeType %q, want text/markdown", r.URI, r.MIMEType)
		}
		body, err := os.ReadFile(filepath.Join(referenceDir(t), page))
		if err != nil {
			t.Fatal(err)
		}
		if want := pageTitle(body); r.Name != want || want == "" {
			t.Errorf("%s: name %q, want the page title %q", r.URI, r.Name, want)
		}
		if r.Description == "" && strings.Contains(string(body), "\n## Purpose") {
			t.Errorf("%s: no description, though the page has a Purpose section", r.URI)
		}
	}
	slices.Sort(got)
	if want := pagesOnDisk(t); !slices.Equal(got, want) {
		t.Fatalf("resources/list = %v, want every reference page %v", got, want)
	}
}

// MCP-102: resources/read returns the page's exact bytes.
func TestMCP102ReadingAPageReturnsItsExactText(t *testing.T) {
	_, url := serveProbes(t)
	session := connect(t, url)
	for _, page := range pagesOnDisk(t) {
		want, err := os.ReadFile(filepath.Join(referenceDir(t), page))
		if err != nil {
			t.Fatal(err)
		}
		res, err := session.ReadResource(t.Context(), &sdk.ReadResourceParams{URI: ReferenceURIPrefix + page})
		if err != nil {
			t.Fatalf("resources/read %s: %v", page, err)
		}
		if len(res.Contents) != 1 {
			t.Fatalf("resources/read %s: %d contents, want 1", page, len(res.Contents))
		}
		c := res.Contents[0]
		if c.Text != string(want) || c.URI != ReferenceURIPrefix+page || c.MIMEType != "text/markdown" {
			t.Fatalf("resources/read %s: uri %q, mimeType %q, %d bytes; want the page's %d bytes",
				page, c.URI, c.MIMEType, len(c.Text), len(want))
		}
	}
}

// MCP-103: a URI that names no page is the protocol's not-found error, and
// returns no content.
func TestMCP103AnUnknownPageIsNotFound(t *testing.T) {
	_, url := serveProbes(t)
	session := connect(t, url)
	for _, uri := range []string{
		ReferenceURIPrefix + "no-such-page.md",
		ReferenceURIPrefix + "../go.mod",
		"file:///etc/passwd",
	} {
		res, err := session.ReadResource(t.Context(), &sdk.ReadResourceParams{URI: uri})
		if err == nil {
			t.Errorf("resources/read %s succeeded with %d contents; want not found", uri, len(res.Contents))
			continue
		}
		if !strings.Contains(strings.ToLower(err.Error()), "not found") {
			t.Errorf("resources/read %s: %v; want the not-found error", uri, err)
		}
	}
}

// MCP-104: on a listener that requires a credential, a caller without one
// reads nothing: the credential check sits in front of the session layer, so
// it cannot open a session to list or read.
func TestMCP104NoCredentialNoPages(t *testing.T) {
	issuer := newTestIssuer(t)
	srv, err := New(Config{Version: "v0.0.0-test", AdminCredential: verifierFor(t, jwksFile(t, issuer))})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	client := sdk.NewClient(&sdk.Implementation{Name: "innsegl-contract-test", Version: "v0"}, nil)
	session, err := client.Connect(t.Context(), &sdk.StreamableClientTransport{Endpoint: httpSrv.URL}, nil)
	if err == nil {
		defer func() { _ = session.Close() }()
		if listed, lerr := session.ListResources(t.Context(), nil); lerr == nil {
			t.Fatalf("a caller with no credential listed %d resources", len(listed.Resources))
		}
	}
}

// MCP-105: the binary embeds exactly the pages in reference/, so a new page
// cannot be left out of what the server offers.
func TestMCP105TheBinaryEmbedsEveryReferencePage(t *testing.T) {
	embedded, err := fs.Glob(reference.Pages, "*.md")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(embedded)
	if want := pagesOnDisk(t); !slices.Equal(embedded, want) {
		t.Fatalf("embedded %v, want every page in reference/ %v", embedded, want)
	}
}
