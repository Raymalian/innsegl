// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// register.sh runs under `set -o pipefail`. Piping a command into `grep -q`
// (or `head`, which also stops reading early) is then wrong: grep exits at its first match, the writer dies of SIGPIPE,
// and pipefail turns a FOUND into a failure. Measured on a core host
// 2026-10-02: an existing SPIRE entry read as absent, the script tried to
// create it, SPIRE answered "similar entry already exists", and `make start`
// failed. The shape is shown failing here, then refused in the script.
func TestRegisterScriptHasNoPipeIntoGrepQ(t *testing.T) {
	demo := exec.CommandContext(t.Context(), "bash", "-c", `set -o pipefail; seq 1 200000 | grep -q '^1$'`)
	if err := demo.Run(); err == nil {
		t.Log("this machine did not reproduce SIGPIPE this run; the static check below still applies")
	}

	src, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "compose", "spire", "register.sh"))
	if err != nil {
		t.Fatal(err)
	}
	pipeIntoGrepQ := regexp.MustCompile(`\|\s*(grep\s+-q|head)\b`)
	for i, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if pipeIntoGrepQ.MatchString(line) {
			t.Errorf("register.sh:%d pipes into a reader that stops early (grep -q, head) under pipefail: %s", i+1, strings.TrimSpace(line))
		}
	}
}
