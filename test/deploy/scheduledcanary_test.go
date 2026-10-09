// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"path"
	"testing"
	"time"
)

// OPS-173 (proposed for doc 07) — the stack runs SEG-005's canary on a
// schedule (doc 05 §2), records it where innsegl-mcp reads it, and never asks
// the scoped identity for a retention it cannot set.
//
// The scoped object store identity is refused PutObjectRetention by design
// (s3-identities.sh), and that store treats retention headers on a PUT as
// that action. Measured 2026-10-09 in the in-place update rehearsal: with a
// probe retention set, every scheduled run failed probe_written with Access
// Denied. So the probe takes the bucket's default rule, and the sweep keeps
// the probe prefix to about one probe per interval inside that window.
func TestOPS173TheStackSchedulesTheCanaryWithoutAskingForRetention(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping OPS-173: %v", err)
	}
	files := []string{"deploy/compose/innsegl.yml"}
	plain := interpolateComposeProfiles(ctx, t, "innsegl-segments", nil, files...)
	separate := interpolateComposeProfiles(ctx, t, "innsegl-segments", []string{"separate"}, files...)

	for _, c := range []struct {
		cfg     composeConfig
		service string
	}{{plain, "innsegl-mcp"}, {separate, "innsegl-sealer"}} {
		if v, _ := c.cfg.env(c.service, "INNSEGL_CANARY_INTERVAL"); v == "" || v == "0" {
			t.Errorf("%s runs the sealer with no scheduled canary (INNSEGL_CANARY_INTERVAL=%q)", c.service, v)
		}
		file, _ := c.cfg.env(c.service, "INNSEGL_CANARY_STATUS_FILE")
		if file == "" {
			t.Errorf("%s records no canary result", c.service)
		}
		mounted := false
		for _, v := range c.cfg.service(t, c.service).Volumes {
			if v.Source == "innsegl-canary-status" && v.Target == path.Dir(file) && !v.ReadOnly {
				mounted = true
			}
		}
		if !mounted {
			t.Errorf("%s writes %s, which is not on the innsegl-canary-status volume", c.service, file)
		}
		for _, key := range []string{"INNSEGL_CANARY_PROBE_RETENTION", "INNSEGL_OBJECT_STORE_RETENTION"} {
			if v, ok := c.cfg.env(c.service, key); ok && v != "" && v != "0" {
				t.Errorf("%s sets %s=%s; the scoped identity cannot set a retention, so every probe write is refused", c.service, key, v)
			}
		}
	}
}
