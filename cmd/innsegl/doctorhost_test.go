// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/client/clienttest"
)

// CLI-024 (PROPOSED for doc 07, #592) — a client service doctor cannot bring
// back is pointed at its log where that OS keeps it: the user journal on
// Linux, never the macOS log folder.
func TestCLI024DoctorPointsAtTheLinuxJournal(t *testing.T) {
	f := newConnectFixture(t)
	dead := httptest.NewUnstartedServer(nil) // a listen address nothing serves
	if code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile,
		"--managed-settings", f.settings, "--no-service", "--listen", dead.Listener.Addr().String()); code != exitOK {
		t.Fatalf("connect: %s", stderr)
	}
	dead.Close()
	d := &doctorRun{f: f}
	deps := d.deps(t)
	deps.goos = "linux"
	deps.serviceWait = 100 * time.Millisecond
	var out strings.Builder
	code := runDoctor(t.Context(), []string{"--wait", "1s"}, &out, &out, deps)
	if code != exitDoctorFailing {
		t.Fatalf("doctor with a dead service: exit %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), client.LogHint("linux")) || strings.Contains(out.String(), "Library/Logs") {
		t.Fatalf("doctor on Linux did not point at the journal:\n%s", out.String())
	}
}
