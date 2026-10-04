// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// Several services share one image, and `docker compose build` with no
// service names builds and unpacks that image once per service: measured
// 2026-10-03 on the core host, the same image exported seven times, about
// 30s each, on every update. The Makefile builds one service per distinct
// image instead (INNSEGL_BUILD_SERVICES). This holds the list to the compose
// file: every image the file builds has exactly one service in it.
func TestEveryBuiltImageIsBuiltOnceByTheMakefile(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping: %v", err)
	}
	cfg := interpolateComposeProfiles(ctx, t, "innsegl-segments", nil, "deploy/compose/innsegl.yml")
	images := map[string]bool{}
	byService := map[string]string{}
	for name, svc := range cfg.Services {
		if svc.Build == nil {
			continue
		}
		images[svc.Image] = true
		byService[name] = svc.Image
	}

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^INNSEGL_BUILD_SERVICES\s*:?=\s*(.+)$`).FindSubmatch(mk)
	if m == nil {
		t.Fatal("the Makefile defines no INNSEGL_BUILD_SERVICES")
	}
	covered := map[string]string{}
	for _, svc := range strings.Fields(string(m[1])) {
		img, ok := byService[svc]
		if !ok {
			t.Errorf("INNSEGL_BUILD_SERVICES names %s, which builds no image", svc)
			continue
		}
		if prev, dup := covered[img]; dup {
			t.Errorf("%s and %s both build %s; one is enough", prev, svc, img)
		}
		covered[img] = svc
	}
	var missing []string
	for img := range images {
		if _, ok := covered[img]; !ok {
			missing = append(missing, img)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("images the compose file builds that INNSEGL_BUILD_SERVICES does not: %v", missing)
	}
}

// The Go image is built from the Go sources alone and stamped with the last
// commit that touched them. Built from the whole tree and stamped with HEAD,
// every commit -- a dashboard or README change too -- made a new image, and
// `make update` restarted every service running it (measured 2026-10-03).
// The Dockerfile's sources and the Makefile's GO_IMAGE_INPUTS are one list.
func TestTheGoImageIsBuiltFromTheGoSourcesAlone(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	df, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}

	m := regexp.MustCompile(`(?m)^GO_IMAGE_INPUTS := (.+)$`).FindSubmatch(mk)
	if m == nil {
		t.Fatal("the Makefile names no GO_IMAGE_INPUTS")
	}
	inputs := map[string]bool{}
	for _, f := range strings.Fields(string(m[1])) {
		inputs[f] = true
	}

	copied := map[string]bool{"Dockerfile": true}
	for _, c := range regexp.MustCompile(`(?m)^COPY (?:--[a-z]+=\S+ )*(.+) \S+$`).FindAllSubmatch(df, -1) {
		line := string(c[0])
		if strings.Contains(line, "--from=") {
			continue
		}
		for _, src := range strings.Fields(string(c[1])) {
			if src == "." {
				t.Fatalf("the Dockerfile copies the whole build context: %s", line)
			}
			copied[src] = true
		}
	}
	for src := range copied {
		if !inputs[src] {
			t.Errorf("the Dockerfile copies %s, which GO_IMAGE_INPUTS does not name", src)
		}
	}
	for in := range inputs {
		if !copied[in] {
			t.Errorf("GO_IMAGE_INPUTS names %s, which the Dockerfile does not copy", in)
		}
	}

	if strings.Contains(string(mk), "INNSEGL_COMMIT='$(DEPLOY_COMMIT)'") {
		t.Error("the Go image is still stamped with the checkout's HEAD")
	}
	// Default attestations stamp the build time, so an unchanged build had a
	// new image ID and compose restarted every service on it.
	if !regexp.MustCompile(`(?m)^export BUILDX_NO_DEFAULT_ATTESTATIONS := 1$`).Match(mk) {
		t.Error("the Makefile does not turn off the default build attestations")
	}
}

// `make update` skips when the deployed commit matches the checkout. A core
// that crash-loops on that commit is not up to date: measured 2026-10-04,
// update said "nothing to do" while innsegl-mcp restarted in a loop. It
// skips only when innsegl-mcp is also running and not restarting.
func TestUpdateSkipsOnlyWhenTheCoreIsRunning(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?ms)^update:\n(.*?)\n\n`).FindSubmatch(mk)
	if m == nil {
		t.Fatal("the Makefile has no update target")
	}
	if !strings.Contains(string(m[1]), "docker inspect") || !strings.Contains(string(m[1]), "Restarting") {
		t.Fatal("make update decides there is nothing to do without asking whether innsegl-mcp is running")
	}
}
