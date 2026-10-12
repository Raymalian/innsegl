// SPDX-License-Identifier: Apache-2.0

package deploytest

import (
	"strings"
)

func FirstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
