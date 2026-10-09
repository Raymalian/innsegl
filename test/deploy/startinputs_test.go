// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/dockertest"
)

// ---------------------------------------------------------------------------
// OPS-165 (PROPOSED for doc 07's TC-OPS) — a long-running service that reads
// a file at start is recreated when that file changes.
//
// MEASURED on a live core 2026-10-09 (#563): `make update` ran
// innsegl-credentials, which generated new object-store keys, and
// innsegl-s3-identities, which rewrote identities.json. innsegl-s3 had been up
// four days and its own compose definition had not changed, so compose left
// it running with the old keys. innsegl-object-init was refused, the update
// stopped, and the core stayed down until the store was restarted by hand.
//
// The mechanism (scripts/compose-up.py): every `up` the Makefile runs goes
// through it; it runs the one-shots that write a read-only input first,
// hashes every long-running service's start-read inputs, and passes each
// hash in through INNSEGL_INPUTS_<SERVICE> into the service's
// dev.innsegl.inputs label. A changed label is a changed definition.
//
// Three checks: every such service carries the label (a new service cannot
// forget it); every `up` in the Makefile goes through the mechanism; and the
// mechanism, run against a real daemon, recreates a reader whose input
// changed and leaves one whose input did not.
// ---------------------------------------------------------------------------

const inputsLabel = "dev.innsegl.inputs"

// inputsCompose is the part of `docker compose config` this test reads.
type inputsCompose struct {
	Services map[string]struct {
		Restart string            `json:"restart"`
		Labels  map[string]string `json:"labels"`
		Volumes []struct {
			Type     string `json:"type"`
			Source   string `json:"source"`
			Target   string `json:"target"`
			ReadOnly bool   `json:"read_only"`
		} `json:"volumes"`
	} `json:"services"`
}

func inputsLongRunning(restart string) bool {
	return restart == "always" || restart == "unless-stopped" || strings.HasPrefix(restart, "on-failure")
}

func inputsVar(service string) string {
	return "INNSEGL_INPUTS_" + regexp.MustCompile(`[^A-Z0-9]`).ReplaceAllString(strings.ToUpper(service), "_")
}

func inputsConfig(t *testing.T, env []string, files ...string) inputsCompose {
	t.Helper()
	root := repoRoot(t)
	args := []string{"compose", "--profile", "*"}
	for _, f := range files {
		args = append(args, "-f", filepath.Join(root, f))
	}
	args = append(args, "config", "--format", "json")
	cmd := exec.CommandContext(t.Context(), "docker", args...)
	cmd.Env = append(append(os.Environ(), env...),
		"INNSEGL_SPIRE_JWT_ISSUER="+composeJWTIssuer,
		"INNSEGL_SPIRE_PARENT_ID="+composeParentIDPlaceholder,
		"INNSEGL_OBJECT_STORE_ACCESS_KEY="+storeRootUser)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker %v: %v: %s", args, err, stderr.String())
	}
	var cfg inputsCompose
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// startReadInputs is the rule, stated a second time independently of the
// script: a read-only volume no long-running service writes, or a read-only
// bind mount of something in this repository.
func startReadInputs(cfg inputsCompose, root string) map[string][]string {
	live := map[string]bool{}
	for _, s := range cfg.Services {
		if !inputsLongRunning(s.Restart) {
			continue
		}
		for _, v := range s.Volumes {
			if v.Type == "volume" && !v.ReadOnly {
				live[v.Source] = true
			}
		}
	}
	out := map[string][]string{}
	for name, s := range cfg.Services {
		if !inputsLongRunning(s.Restart) {
			continue
		}
		for _, v := range s.Volumes {
			if !v.ReadOnly {
				continue
			}
			switch {
			case v.Type == "volume" && !live[v.Source]:
				out[name] = append(out[name], v.Source)
			case v.Type == "bind" && (v.Source == root || strings.HasPrefix(v.Source, root+string(os.PathSeparator))):
				out[name] = append(out[name], strings.TrimPrefix(v.Source, root+"/"))
			}
		}
	}
	return out
}

func TestOPS165EveryStartReadInputCarriesTheMechanism(t *testing.T) {
	root, err := filepath.EvalSymlinks(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	sets := [][]string{
		{"deploy/compose/innsegl.yml"},
		{"deploy/compose/innsegl.yml", "deploy/compose/innsegl.custody.yml"},
		{"deploy/compose/innsegl.yml", "deploy/compose/dev/innsegl.yml"},
		{"deploy/compose/sigstore.yml"},
		{"deploy/compose/sigstore.yml", "deploy/compose/sigstore.keycustody.yml"},
		{"deploy/compose/sigstore.yml", "deploy/compose/dev/sigstore.yml"},
		{"deploy/compose/spire.yml"},
		{"deploy/compose/spire.yml", "deploy/compose/dev/spire.yml"},
	}
	covered := 0
	for _, files := range sets {
		first := inputsConfig(t, nil, files...)
		var probes []string
		for name := range first.Services {
			probes = append(probes, inputsVar(name)+"=probe-"+name)
		}
		cfg := inputsConfig(t, probes, files...)
		ins := startReadInputs(cfg, root)
		names := make([]string, 0, len(ins))
		for n := range ins {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			covered++
			got := cfg.Services[name].Labels[inputsLabel]
			if got != "probe-"+name {
				t.Errorf("%v: %s reads %v at start, and its %s label is %q, not ${%s:-}. "+
					"A change to those inputs would leave it running on the old ones (OPS-165)",
					files, name, ins[name], inputsLabel, got, inputsVar(name))
			}
		}
	}
	if covered < 10 {
		t.Fatalf("found only %d services with start-read inputs; the rule has stopped seeing them", covered)
	}
}

// composeUpLine finds a compose `up` that does not go through the mechanism.
var composeUpLine = regexp.MustCompile(`(docker compose|\$\(INNSEGL_COMPOSE\))[^#]*\sup(\s|$)`)

func TestOPS165EveryMakefileUpGoesThroughTheMechanism(t *testing.T) {
	f, err := os.Open(filepath.Join(repoRoot(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n, ups := 0, 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.HasPrefix(strings.TrimSpace(line), "@#") {
			continue
		}
		if strings.Contains(line, "compose-up.py") {
			ups++
		}
		if composeUpLine.MatchString(line) {
			t.Errorf("Makefile:%d runs compose up without scripts/compose-up.py, so a service "+
				"whose start-read input changed keeps the old one:\n  %s", n, strings.TrimSpace(line))
		}
	}
	if ups == 0 {
		t.Fatal("no Makefile line uses scripts/compose-up.py")
	}
}

// opsInputsImage is a small image the test already pins elsewhere.
const opsInputsImage = "alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"

func TestOPS165ARewrittenInputRecreatesItsReader(t *testing.T) {
	ctx := t.Context()
	if err := dockertest.Usable(ctx); err != nil {
		skip, failure := dockertest.StartupOutcome(err)
		if failure != "" {
			t.Fatal(failure)
		}
		t.Skipf("skipping OPS-165: %s", skip)
	}
	root := repoRoot(t)
	dir := t.TempDir()
	project := uniqueName(t, "ops165")
	// writer: a one-shot rendering CONTENT into a volume. reader: long-running,
	// reads it read-only, carries the label. bystander: long-running, reads a
	// volume nothing rewrites.
	compose := fmt.Sprintf(`name: %[1]s
services:
  writer:
    image: %[2]s
    restart: "no"
    network_mode: none
    command: ["sh", "-c", "printf '%%s' \"$$CONTENT\" > /out/key"]
    environment:
      CONTENT: ${CONTENT:-one}
    volumes:
      - rendered:/out
  reader:
    image: %[2]s
    restart: unless-stopped
    network_mode: none
    depends_on:
      writer:
        condition: service_completed_successfully
    command: ["sleep", "3600"]
    labels:
      dev.innsegl.inputs: ${INNSEGL_INPUTS_READER:-}
    volumes:
      - rendered:/in:ro
  bystander:
    image: %[2]s
    restart: unless-stopped
    network_mode: none
    command: ["sleep", "3600"]
    labels:
      dev.innsegl.inputs: ${INNSEGL_INPUTS_BYSTANDER:-}
    volumes:
      - steady:/in:ro
volumes:
  rendered: {}
  steady: {}
`, project, opsInputsImage)
	file := filepath.Join(dir, "compose.yml")
	writeFile(t, file, compose)
	t.Cleanup(func() {
		if out, err := exec.CommandContext(context.Background(), "docker", "compose", "-f", file, "down", "-v", "--remove-orphans").CombinedOutput(); err != nil {
			t.Logf("removing the test project %s: %v\n%s", project, err, out)
		}
	})

	up := func(content string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, filepath.Join(root, "scripts", "compose-up.py"), "-f", file, "up", "-d", "--no-build")
		cmd.Env = append(os.Environ(), "CONTENT="+content)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("compose-up.py up (CONTENT=%s): %v\n%s", content, err, out)
		}
	}
	id := func(svc string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, "docker", "compose", "-f", file, "ps", "-q", svc).Output()
		if err != nil || strings.TrimSpace(string(out)) == "" {
			t.Fatalf("no running %s: %v", svc, err)
		}
		return strings.TrimSpace(string(out))
	}

	up("one")
	reader, bystander := id("reader"), id("bystander")
	up("one")
	if got := id("reader"); got != reader {
		t.Fatal("the reader was recreated though its input did not change")
	}
	up("two")
	if got := id("reader"); got == reader {
		t.Fatal("the writer rewrote the reader's input and the reader kept running on the old one — the 2026-10-09 outage")
	}
	if got := id("bystander"); got != bystander {
		t.Fatal("the bystander was recreated though nothing it reads changed")
	}
	out, err := exec.CommandContext(ctx, "docker", "compose", "-f", file, "exec", "-T", "reader", "cat", "/in/key").Output()
	if err != nil || string(out) != "two" {
		t.Fatalf("the reader sees %q (%v), want the rewritten input", out, err)
	}
}

// ---------------------------------------------------------------------------
// OPS-166 (PROPOSED for doc 07's TC-OPS) — a Make target that runs compose
// over files naming the trust volumes ensures those volumes first.
//
// MEASURED on a live core 2026-10-09: `make innsegl-backup`, taken before the
// ADR-0078 migration, failed with `external volume "innsegl-trust-credentials"
// not found`. Compose will not create an external volume, and that target was
// the one compose verb in the Makefile that did not ensure them.
// ---------------------------------------------------------------------------

var (
	makeRule       = regexp.MustCompile(`^([a-zA-Z0-9_.-]+):([^=]|$)`)
	trustCompose   = regexp.MustCompile(`\$\((INNSEGL_COMPOSE|INNSEGL_COMPOSE_UP|INNSEGL_TRUST_ENV)\)`)
	volumeVerb     = regexp.MustCompile(`\s(run|up|create)(\s|$)`)
	composeCommand = regexp.MustCompile(`docker compose|compose-up\.py`)
)

func TestOPS166EveryTrustVolumeComposeEnsuresTheVolumes(t *testing.T) {
	f, err := os.Open(filepath.Join(repoRoot(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var targets []string
	current := ""
	seen := map[string]bool{}
	for sc.Scan() {
		line := sc.Text()
		if m := makeRule.FindStringSubmatch(line); m != nil && !strings.HasPrefix(line, "\t") {
			current = m[1]
			continue
		}
		if !strings.HasPrefix(line, "\t") || current == "" || seen[current] {
			continue
		}
		if trustCompose.MatchString(line) && volumeVerb.MatchString(line) && !strings.Contains(line, " build ") {
			seen[current] = true
			targets = append(targets, current)
		}
	}
	if len(targets) < 5 {
		t.Fatalf("found only %v; the scan has stopped seeing the compose targets", targets)
	}
	for _, target := range targets {
		out := makeDryRun(t, "live", target)
		ensure := strings.Index(out, "trust-volumes.sh ensure")
		first := -1
		for _, line := range strings.Split(out, "\n") {
			if composeCommand.MatchString(line) && volumeVerb.MatchString(line) {
				first = strings.Index(out, line)
				break
			}
		}
		if first < 0 {
			continue
		}
		if ensure < 0 || ensure > first {
			t.Errorf("make %s runs compose over the trust volumes without ensuring them first; "+
				"on a host that lacks one it stops with `external volume ... not found` (OPS-166)", target)
		}
	}
}

// ---------------------------------------------------------------------------
// OPS-167 (PROPOSED for doc 07's TC-OPS) — bringing the log up again keeps
// Rekor on the host port it runs on.
//
// `make start` publishes Rekor on a port chosen at run time. rekor-log-up and
// sigstore-up did not pass that port to compose, so any update that
// recreated Rekor moved it to the compose default, 23000. MEASURED in the
// in-place rehearsal of OPS-165 on 2026-10-09: the recreate failed with
// "Bind for 127.0.0.1:23000 failed: port is already allocated".
// ---------------------------------------------------------------------------

func TestOPS167TheLogKeepsItsRekorPort(t *testing.T) {
	for _, target := range []string{"rekor-log-up", "sigstore-up"} {
		out := strings.ReplaceAll(makeDryRun(t, "live", target), "\\\n", " ")
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "sigstore.yml") && volumeVerb.MatchString(line) &&
				!strings.Contains(line, "INNSEGL_REKOR_PORT='23000'") {
				t.Errorf("make %s brings the log up without its running port (want INNSEGL_REKOR_PORT='23000' "+
					"from the environment):\n  %s", target, line)
			}
		}
	}
}
