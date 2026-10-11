// SPDX-License-Identifier: Apache-2.0

package deploytest

import (
	"strings"
)

// ComposeCode is a compose file with its comment lines removed.
func ComposeCode(body string) string {
	var b strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// ServiceBlock returns one service's lines, comments removed.
func ServiceBlock(body, name string) string {
	var b strings.Builder
	in := false
	for _, line := range strings.Split(ComposeCode(body), "\n") {
		if m := ServiceLine.FindStringSubmatch(line); m != nil {
			in = m[1] == name
			continue
		}
		if line != "" && !strings.HasPrefix(line, " ") {
			in = false
		}
		if in {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
