// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/test/deploy/deploytest"
)

// ---------------------------------------------------------------------------
// BAK-045 (proposed for doc 07; doc 07 is not modified here) — RM-371, #623.
//
// `make innsegl-backup` is the backup an operator takes by hand. It ran the
// backup service's image as `compose run --entrypoint backup-ledger.sh
// innsegl-backup --out /backups`. The service's `command` is where the object
// store's endpoint, bucket, prefix, identity and secret-key file are, and that
// run had none of it: arguments after the service replace the command, and,
// MEASURED on a dev stack 2026-10-12, overriding the entrypoint drops it too
// (a probe with --entrypoint /bin/echo printed nothing). The manual backup read
// the store with no credential and was UNVERIFIED every time, while the
// scheduled run of the same service, on the same ledger, verified.
//
// What must hold:
//   - the target keeps the service's entrypoint and passes no command, so
//     compose hands the service's own arguments through: one credential
//     source, not two;
//   - it asks the loop for ONE run (INNSEGL_BACKUP_ONCE=1), and the loop then
//     runs the backup once with those arguments and exits with its status;
//   - that command carries the object store's identity and secret-key file.
// ---------------------------------------------------------------------------

func TestBAK045TheManualBackupUsesTheServicesObjectStoreCredential(t *testing.T) {
	for _, mode := range []string{"live", "dev"} {
		t.Run(mode, func(t *testing.T) {
			// One recipe line may be printed over several, joined with "\".
			out := strings.ReplaceAll(deploytest.MakeDryRun(t, mode, "innsegl-backup"), "\\\n", " ")
			var run string
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, " run ") && strings.Contains(line, "innsegl-backup") {
					run = line
				}
			}
			if run == "" {
				t.Fatal("make -n innsegl-backup runs no innsegl-backup through compose run")
			}
			fields := strings.Fields(run)
			if slices.Contains(fields, "--entrypoint") {
				t.Errorf("make innsegl-backup overrides the entrypoint, and compose then drops the "+
					"service's command, which holds the object store's credential:\n%s", run)
			}
			if !strings.Contains(run, "-e INNSEGL_BACKUP_ONCE=1") {
				t.Errorf("make innsegl-backup does not ask the service for one run:\n%s", run)
			}
			i := slices.Index(fields, "innsegl-backup")
			if i < 0 {
				t.Fatalf("the backup's compose run names no innsegl-backup service:\n%s", run)
			}
			if after := fields[i+1:]; len(after) > 0 {
				t.Errorf("make innsegl-backup passes %q after the service name; compose run "+
					"replaces the service's command with them:\n%s", after, run)
			}
		})
	}

	cfg := deploytest.InterpolateComposeProfiles(t.Context(), t, "innsegl-segments", nil, "deploy/compose/innsegl.yml")
	svc := cfg.Service(t, "innsegl-backup")
	for _, flag := range []string{"--object-store-access-key", "--object-store-secret-key-file"} {
		if !slices.Contains(svc.Command, flag) {
			t.Errorf("the innsegl-backup service's command %q has no %s: the manual run "+
				"takes its credential from that command, and there would be none", svc.Command, flag)
		}
	}
}

// The loop's one-shot mode runs the backup once, with the service's own
// arguments, and exits with the backup's status, writing nothing the
// healthcheck reads.
func TestBAK045TheLoopRunsOnceWithTheServicesArguments(t *testing.T) {
	root := deploytest.RepoRoot(t)
	dir := t.TempDir()
	fake := filepath.Join(dir, "backup-ledger.sh")
	deploytest.WriteFile(t, fake, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \""+dir+"/args\"\nexit 4\n")
	if err := os.Chmod(fake, 0o755); err != nil {
		t.Fatal(err)
	}
	// A loop that does not know the one-shot mode never exits; the deadline
	// turns that into a failure instead of a hung suite.
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(root, "deploy", "compose", "innsegl", "backup-loop.sh"),
		"--object-store-access-key", "innsegl-sealer",
		"--object-store-secret-key-file", "/run/innsegl/credentials/objects-sealer/secret")
	// The loop's sleep holds its output open after the loop is killed.
	cmd.WaitDelay = 2 * time.Second
	cmd.Env = append(os.Environ(),
		"INNSEGL_BACKUP_ONCE=1",
		"INNSEGL_BACKUP_SCRIPT="+fake,
		"INNSEGL_BACKUP_DIR="+dir,
		"INNSEGL_BACKUP_MARKER="+filepath.Join(dir, ".last-run"))
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 4 {
		t.Fatalf("backup-loop.sh with INNSEGL_BACKUP_ONCE=1 did not exit with the backup's own "+
			"status 4 (err %v):\n%s", err, out)
	}
	args := deploytest.ReadFile(t, filepath.Join(dir, "args"))
	for _, want := range []string{"--out\n" + dir + "\n", "--object-store-access-key\ninnsegl-sealer\n",
		"--object-store-secret-key-file\n/run/innsegl/credentials/objects-sealer/secret\n"} {
		if !strings.Contains(args, want) {
			t.Errorf("the one run was not handed %q; it got:\n%s", want, args)
		}
	}
	if _, serr := os.Stat(filepath.Join(dir, ".last-run")); serr == nil {
		t.Error("the one run wrote the marker the healthcheck reads; a manual run is not the schedule")
	}
}
