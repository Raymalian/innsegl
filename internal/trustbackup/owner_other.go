// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package trustbackup

import "io/fs"

// fileOwner is unknown where files carry no uid.
func fileOwner(fs.FileInfo) (int, bool) { return 0, false }
