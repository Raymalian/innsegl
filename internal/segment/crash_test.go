// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// SEG-002, the hard version: the sealer is not aborted, it is killed.
//
// The in-process matrix in seal_test.go injects an error or a panic, which is
// a fair simulation but still leaves Go's runtime in charge. This one runs the
// sealer in a child process that calls os.Exit at the chosen step boundary —
// no deferred cleanup, no unwinding, no chance to tidy anything up — over a
// store that is a real directory on disk. Then it re-runs a fresh process
// against the same directory and requires the same segment hash.
const (
	crashDirEnv  = "INNSEGL_SEG002_DIR"
	crashStepEnv = "INNSEGL_SEG002_KILL_AFTER_STEP"
	crashExit    = 97
	idMarker     = "INNSEGL_SEGMENT_ID="
)

// TestSEG002CrashChild is the child process body, not a test in its own right.
// It seals into the directory it is given and, when asked, dies at a boundary.
func TestSEG002CrashChild(t *testing.T) {
	dir := os.Getenv(crashDirEnv)
	if dir == "" {
		t.Skip("child-process helper for TestSEG002KillTheProcessAtEveryStepBoundary")
	}

	killAfter, err := strconv.Atoi(os.Getenv(crashStepEnv))
	if err != nil {
		t.Fatalf("%s: %v", crashStepEnv, err)
	}

	sealer := &Sealer{Store: fileStore{dir: dir}}
	if killAfter > 0 {
		sealer.AfterStep = func(s Step) error {
			if int(s) == killAfter {
				// The kill. Nothing after this line in this process runs.
				os.Exit(crashExit)
			}
			return nil
		}
	}

	sealed, err := sealer.Seal(Request{Records: sealTestRecords()})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	fmt.Println(idMarker + sealed.SegmentID)
}

func TestSEG002KillTheProcessAtEveryStepBoundary(t *testing.T) {
	if os.Getenv(crashDirEnv) != "" {
		t.Skip("running as the child process")
	}

	// The reference: one uninterrupted run in a directory of its own.
	reference := runSealChild(t, t.TempDir(), 0, 0)

	for boundary := 0; boundary <= len(Steps()); boundary++ {
		name := "before_any_step"
		if boundary > 0 {
			name = "after_" + Steps()[boundary-1].String()
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if boundary > 0 {
				// The process dies here. Whatever it had written stays written.
				runSealChild(t, dir, boundary, crashExit)
			}
			got := runSealChild(t, dir, 0, 0)
			if got != reference {
				t.Errorf("after a kill at boundary %d the re-run sealed %s; the no-crash run sealed %s",
					boundary, got, reference)
			}
			assertOneObject(t, dir, reference)
		})
	}
}

// runSealChild runs the sealer in a child process and returns the segment id it
// printed. wantExit is the exit code the child is expected to die with; a
// crashing child prints nothing and returns "".
func runSealChild(t *testing.T, dir string, killAfter, wantExit int) string {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSEG002CrashChild$", "-test.v")
	cmd.Env = append(os.Environ(),
		crashDirEnv+"="+dir,
		crashStepEnv+"="+strconv.Itoa(killAfter),
	)
	out, err := cmd.CombinedOutput()

	code := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatalf("running the sealer child: %v\n%s", err, out)
	}
	if code != wantExit {
		t.Fatalf("the sealer child exited %d, want %d\n%s", code, wantExit, out)
	}
	if wantExit != 0 {
		return ""
	}

	for _, line := range strings.Split(string(out), "\n") {
		if id, ok := strings.CutPrefix(strings.TrimSpace(line), idMarker); ok {
			return id
		}
	}
	t.Fatalf("the sealer child printed no segment id\n%s", out)
	return ""
}

// assertOneObject checks that the store directory holds exactly the one sealed
// object, that it is named by its own digest, and that no half-written file was
// left behind.
func assertOneObject(t *testing.T, dir, segmentID string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var objects []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".partial-") {
			t.Errorf("a half-written object survived: %s", e.Name())
			continue
		}
		objects = append(objects, e.Name())
	}
	if len(objects) != 1 {
		t.Fatalf("store holds %d objects, want 1: %v", len(objects), objects)
	}

	raw, err := os.ReadFile(filepath.Join(dir, objects[0]))
	if err != nil {
		t.Fatalf("read the sealed object: %v", err)
	}
	if got := digestOf(raw); got != segmentID {
		t.Errorf("the stored object hashes to %s, the segment id is %s", got, segmentID)
	}
	if _, err := Open(fileStore{dir: dir}, segmentID); err != nil {
		t.Errorf("the resumed object does not open: %v", err)
	}
}
