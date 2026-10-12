// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"slices"
	"strings"
	"testing"

	"innsegl.dev/innsegl/test/deploy/deploytest"
)

// ---------------------------------------------------------------------------
// BAK-045 (proposed for doc 07; doc 07 is not modified here) — RM-371, #623.
//
// `make innsegl-backup` is the backup an operator takes by hand. It runs the
// backup service's image with backup-ledger.sh as the entrypoint, and it
// passed `--out /backups` after the service name. Arguments given to
// `compose run` REPLACE the service's `command`, and that command is where
// the object store's endpoint, bucket, prefix, identity and secret-key file
// are. The manual run read the store with no credential, found no segment it
// could read, and reported every backup UNVERIFIED, while the scheduled run
// of the same service, which keeps its command, verified.
//
// What must hold:
//   - the target names no argument after the service, so compose hands the
//     script the service's own command: one credential source, not two;
//   - that command carries the object store's identity and secret-key file;
//   - the output directory the dropped `--out` used to name is the service's
//     INNSEGL_BACKUP_DIR, which the script reads when no --out is given.
// ---------------------------------------------------------------------------

func TestBAK045TheManualBackupUsesTheServicesObjectStoreCredential(t *testing.T) {
	for _, mode := range []string{"live", "dev"} {
		t.Run(mode, func(t *testing.T) {
			var run string
			// One recipe line may be printed over several, joined with "\".
			out := strings.ReplaceAll(deploytest.MakeDryRun(t, mode, "innsegl-backup"), "\\\n", " ")
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, " run ") && strings.Contains(line, "backup-ledger.sh") {
					run = line
				}
			}
			if run == "" {
				t.Fatal("make -n innsegl-backup runs no backup-ledger.sh through compose run")
			}
			fields := strings.Fields(run)
			i := slices.Index(fields, "innsegl-backup")
			if i < 0 {
				t.Fatalf("the backup's compose run names no innsegl-backup service:\n%s", run)
			}
			if after := fields[i+1:]; len(after) > 0 {
				t.Errorf("make innsegl-backup passes %q after the service name; compose run "+
					"replaces the service's command with them, and that command holds the "+
					"object store's credential, so the backup cannot read a segment:\n%s",
					after, run)
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
	if dir, ok := cfg.Env("innsegl-backup", "INNSEGL_BACKUP_DIR"); !ok || dir != "/backups" {
		t.Errorf("innsegl-backup sets INNSEGL_BACKUP_DIR=%q (set %v); the manual run writes "+
			"where it says, and the backups volume is mounted at /backups", dir, ok)
	}
}
