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
