// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/reference"
)

// ReferenceURIPrefix is the scheme the reference pages are offered under:
// innsegl://reference/<page>.md.
const ReferenceURIPrefix = "innsegl://reference/"

const referenceMIMEType = "text/markdown"

// The reference pages as read-only MCP resources (MCP-101..105).
//
// An agent connected to this system, in any repository, can read how the
// system works from the system itself, in the text that matches the running
// version. These are resources, not tools: the protected tool surface (IP §4,
// doc 08) is unchanged, and nothing here writes or reads state.
//
// They carry no secrets: the same pages ship in the public repository. On a
// listener that requires a credential they sit behind it like everything else.

// referenceFS is the page set New offers; a test swaps in one that fails.
var referenceFS fs.FS = reference.Pages

// addReference offers every *.md page in pages as one resource. The SDK
// routes a read to the handler of the resource whose URI it names, and
// answers any other URI with its own not-found error (MCP-103).
func addReference(s *sdk.Server, pages fs.FS) error {
	entries, err := fs.ReadDir(pages, ".")
	if err != nil {
		return fmt.Errorf("reference pages: %w", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".md") {
			continue
		}
		body, err := fs.ReadFile(pages, name)
		if err != nil {
			return fmt.Errorf("reference page %s: %w", name, err)
		}
		uri := ReferenceURIPrefix + name
		title := pageTitle(body)
		if title == "" {
			title = name
		}
		text := string(body)
		s.AddResource(&sdk.Resource{
			URI:         uri,
			Name:        title,
			Title:       title,
			Description: purposeLine(body),
			MIMEType:    referenceMIMEType,
			Size:        int64(len(body)),
		}, func(context.Context, *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
			return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{{
				URI: uri, MIMEType: referenceMIMEType, Text: text,
			}}}, nil
		})
	}
	return nil
}

// pageTitle is the text of the page's first "# " heading.
func pageTitle(body []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		if t, ok := strings.CutPrefix(sc.Text(), "# "); ok {
			return strings.TrimSpace(t)
		}
	}
	return ""
}

// purposeLine is the first non-empty line under the page's "## Purpose"
// heading, or "" when it has none.
func purposeLine(body []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(body))
	in := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "## ") {
			if in {
				return ""
			}
			in = line == "## Purpose"
			continue
		}
		if in && line != "" {
			return line
		}
	}
	return ""
}
