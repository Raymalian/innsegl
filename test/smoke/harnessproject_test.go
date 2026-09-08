// SPDX-License-Identifier: Apache-2.0

package smoke

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// OPS-004's harness must READ the stack in the same compose project it BOOTS
// it in (proposed for doc 07; doc 07 is not modified here).
//
// # The regression this exists to catch, which shipped and was measured
//
// #168 moved the documented commands under this harness's own project name, so
// that running the smoke test on a developer's machine would stop deleting
// their Rekor and SPIRE data. That fix set COMPOSE_PROJECT_NAME in `sh`, which
// runs the README's block — and nowhere else.
//
// `dockerIn` is how the harness READS what that block produced, and it did not
// carry the variable. So the boot created `innsegl-smoke-stack` and every read
// afterwards fell back to the file's PINNED name, `innsegl-spire` — measured by
// removing the fix and asking compose:
//
//	dockerIn acts in compose project "innsegl-spire", but the documented boot
//	block runs in "innsegl-smoke-stack"
//
// which is worse than looking nowhere. On CI that project does not exist and
// the test fails honestly; on a developer's machine it is THEIR running stack,
// and the harness would have read it and reported on it as if it were the one
// the fresh clone booted. OPS-004 failed on 2026-09-08 with:
//
//	OPS-004 boot: the README's block succeeded on attempt 1
//	the reference compose stack did not come up on a machine that has Docker:
//	docker compose -f deploy/compose/spire.yml exec -T spire-server ...:
//	service "spire-server" is not running
//
// which reads as "the stack does not boot" and was "the harness is looking in
// the wrong place". It failed four CI runs in a row and cost two jobs.
//
// # Why this asserts on the environment and not on a booted stack
//
// Booting is what OPS-004 already does, for six minutes. The defect is one
// missing variable on one code path, and a test that has to boot a stack to
// find it is a test nobody runs before pushing. `docker compose config` asks
// compose the same question without starting anything.
func TestOPS004HarnessReadsTheProjectItBoots(t *testing.T) {
	for _, env := range [][]string{stackEnv(""), stackEnv("31000")} {
		var got string
		for _, kv := range env {
			if v, ok := strings.CutPrefix(kv, "COMPOSE_PROJECT_NAME="); ok {
				got = v
			}
		}
		if got != smokeComposeProject {
			t.Fatalf("stackEnv() carries COMPOSE_PROJECT_NAME=%q, want %q — every "+
				"path that speaks to compose must name the same project, or the "+
				"harness boots one stack and reads another", got, smokeComposeProject)
		}
	}

	if err := dockerUsable(context.Background()); err != nil {
		t.Skipf("docker is not usable here: %v", err)
	}

	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	s := &stack{clone: strings.TrimSuffix(root, "/test/smoke")}

	out, err := s.dockerIn(context.Background(),
		"compose", "-f", "deploy/compose/spire.yml", "config", "--format", "json")
	if err != nil {
		t.Fatalf("asking compose which project dockerIn acts in: %v", err)
	}
	var cfg struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatalf("compose config was not JSON: %v", err)
	}
	if cfg.Name != smokeComposeProject {
		t.Errorf("dockerIn acts in compose project %q, but the documented boot block "+
			"runs in %q. Every read the harness makes would ask about a stack "+
			"nothing started.", cfg.Name, smokeComposeProject)
	}
}
