// SPDX-License-Identifier: Apache-2.0

package deploytest

import (
	"context"
	"testing"
	"time"
)

// ObjectStoreService is the one object-store service, by its compose name.
// The name is the gateway's old one: every client addresses innsegl-s3:8333.
const ObjectStoreService = "innsegl-s3"

// ObjectStoreConfig interpolates the shipped stack, or skips when compose is
// absent (#101: an absent tool is a skip, never a pass).
func ObjectStoreConfig(t *testing.T) ComposeConfig {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := ComposeUsable(ctx); err != nil {
		t.Skipf("skipping: %v", err)
	}
	return InterpolateCompose(ctx, t, "innsegl-segments", "deploy/compose/innsegl.yml")
}
