// SPDX-License-Identifier: Apache-2.0

// Package reference carries the reference pages inside the binary, so the
// MCP server serves the text that matches the running version: an agent in
// any repository can read how this system works from the system itself.
package reference

import "embed"

// Pages holds every reference page, one per part of the system.
//
//go:embed *.md
var Pages embed.FS
