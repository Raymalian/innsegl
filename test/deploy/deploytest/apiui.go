// SPDX-License-Identifier: Apache-2.0

package deploytest

import (
	"regexp"
	"testing"
)

// DockerfileStage is the text of one named stage: from its FROM line to
// the next FROM.
func DockerfileStage(t *testing.T, df, name string) string {
	t.Helper()
	m := regexp.MustCompile(`(?ms)^FROM [^\n]* AS ` + regexp.QuoteMeta(name) + `\n(.*?)(?:^FROM |\z)`).FindStringSubmatch(df)
	if m == nil {
		t.Fatalf("the Dockerfile has no stage named %s", name)
	}
	return m[1]
}
