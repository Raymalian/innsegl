// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Every named volume a runtime-image service writes as uid 1000 is created in
// the image, owned by that uid.
//
// Docker initialises an EMPTY named volume from the image's content and
// ownership at the mount path; when the image has no such directory, the
// mountpoint is created root-owned and the service cannot write it. The
// gateway's CA key directory (RM-246) was missing: on a fresh volume
// `innsegl serve` failed "chmod /run/innsegl/gateway-ca-key: operation not
// permitted" and the MCP restarted in a loop. Measured 2026-10-06 in the
// cutover rehearsal (#470); a moved volume kept its owner, so only a first
// start showed it.
func TestRuntimeImageOwnsEveryVolumeItsServicesWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping: %v", err)
	}
	runtime := dockerfileStage(t, readFile(t, filepath.Join(repoRoot(t), "Dockerfile")), "runtime")
	cfg := interpolateComposeProfiles(ctx, t, "innsegl-segments",
		[]string{"init", "separate", "demo", "canary"}, "deploy/compose/innsegl.yml")

	// Written by another stack's service, not by the one that mounts it.
	notOurs := map[string]bool{"spire-agent-socket": true}

	checked := 0
	for name, svc := range cfg.Services {
		if svc.User != "1000:1000" || !strings.HasPrefix(svc.Image, "innsegl:") && !strings.HasPrefix(svc.Image, "innsegl-api:") {
			continue
		}
		for _, v := range svc.Volumes {
			if v.Type != "volume" || v.ReadOnly || notOurs[v.Source] {
				continue
			}
			checked++
			made := regexp.MustCompile(`(?m)^RUN mkdir -p ` + regexp.QuoteMeta(v.Target) +
				` && chown 1000:1000 ` + regexp.QuoteMeta(v.Target) + `\b`)
			if !made.MatchString(runtime) {
				t.Errorf("%s writes volume %s at %s as 1000:1000, and the runtime stage does not create %s owned by 1000:1000",
					name, v.Source, v.Target, v.Target)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no runtime-image service writes a named volume; the check checked nothing")
	}

	// The CA key directory's mode is the one internal/gateway enforces
	// (caKeyDirMode, 0700); the image creates it that way.
	if !regexp.MustCompile(`(?m)^RUN mkdir -p /run/innsegl/gateway-ca-key && chown 1000:1000 /run/innsegl/gateway-ca-key && chmod 0700 /run/innsegl/gateway-ca-key$`).MatchString(runtime) {
		t.Error("the runtime stage does not create /run/innsegl/gateway-ca-key 1000:1000 mode 0700")
	}
}
