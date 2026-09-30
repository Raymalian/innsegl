// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"innsegl.dev/innsegl/internal/event"
)

// diff.go answers GET /api/v1/runs/{run_id}/steps/{n}/diff: one step's own
// `git diff-tree -p` against the gateway's snapshot store, parsed into
// record.go's StepDiff.
//
// # Bounded, because a diff is the one thing here sized by the AGENT, not
// by this deployment
//
// Every other read in this package is sized by the ledger (a run's own
// event count) or by this process's own configuration. A diff is sized by
// however much an agent rewrote in one tool call, which this process does
// not control and must not trust to be small. boundedDiffOutput stops
// reading git's own stdout at a fixed byte bound rather than buffering
// whatever git is willing to produce, and the file being parsed when that
// bound is hit is reported Truncated — never silently dropped, and never
// padded out with content this process never read.

// maxDiffOutputBytes bounds the total bytes this handler reads from one
// `git diff-tree -p` invocation. Generous for an ordinary tool call's own
// diff, and still a bound: a public-ish read path must never hold an
// unbounded amount of an agent's own output in memory because it asked to.
const maxDiffOutputBytes = 4 << 20 // 4 MiB

// maxHunksPerFile and maxLinesPerHunk bound one file's own parsed shape,
// independent of the byte bound above — a diff that is small in bytes but
// pathological in hunk count (a file rewritten one line at a time,
// thousands of times) is bounded the same way.
const (
	maxHunksPerFile = 200
	maxLinesPerHunk = 5000
	maxFilesPerDiff = 500
)

// buildStepDiff answers one step's diff. It reuses buildRunRecord's own
// tree_before/tree_after for the step rather than re-deriving them: the
// diff route and the record route can then never disagree about which two
// trees a step's own diff is between, because they are the same two
// values computed the same way.
func (rs *recordServer) buildStepDiff(ctx context.Context, runID string, n int) (StepDiff, error) {
	rec, err := rs.buildRunRecord(ctx, runID)
	if err != nil {
		return StepDiff{}, err
	}
	if n < 1 || n > len(rec.Steps) {
		return StepDiff{}, fmt.Errorf("%w: run %q has no step %d", ErrNotFound, runID, n)
	}
	step := rec.Steps[n-1]

	if step.TreeBefore == "" || step.TreeAfter == "" || step.TreeBefore == step.TreeAfter {
		// record.go's own rule, restated for the diff route: an unknown
		// "before" is never shown as a diff of everything, and identical
		// trees have nothing to show — "a no-change step has no hunks"
		// (RPG-002), never an error.
		return StepDiff{Files: []DiffFile{}}, nil
	}
	if verr := event.ValidateGitObjectID(step.TreeBefore); verr != nil {
		return StepDiff{}, fmt.Errorf("%w: tree_before is not a git object id: %w", ErrBadRequest, verr)
	}
	if verr := event.ValidateGitObjectID(step.TreeAfter); verr != nil {
		return StepDiff{}, fmt.Errorf("%w: tree_after is not a git object id: %w", ErrBadRequest, verr)
	}

	storeDir, ok := rs.storeDirFor(ctx, rec.Run.Repo)
	if !ok {
		// No snapshot store this process can resolve for this repository.
		// Honest and empty, exactly as record.go's Files already are in
		// the same situation — never a guess at what the diff might hold.
		return StepDiff{Files: []DiffFile{}}, nil
	}

	out, truncated, err := boundedDiffTreePatch(ctx, rs.cfg, storeDir, step.TreeBefore, step.TreeAfter)
	if err != nil {
		return StepDiff{}, fmt.Errorf("api: reading the diff of %s step %d: %w", runID, n, err)
	}
	return parseDiffTreePatch(out, truncated), nil
}

// boundedDiffTreePatch runs `git diff-tree -p -M --no-color --no-ext-diff`
// between before and after, reading at most maxDiffOutputBytes of its
// stdout. truncated is true when the bound was hit — the command's own
// output kept going and this handler stopped reading it, not that git
// itself was cut off mid-write by this handler's choice to stop.
func boundedDiffTreePatch(ctx context.Context, cfg snapshotStoreConfig, storeDir, before, after string) (out []byte, truncated bool, err error) {
	gitPath := cfg.gitPath
	if gitPath == "" {
		gitPath = "git"
	}
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, gitPath,
		"diff-tree", "-p", "-M", "--no-color", "--no-ext-diff", "-r", "--end-of-options", before, after)
	cmd.Dir = storeDir
	cmd.Env = append(isolatedGitEnv(storeDir), "GIT_DIR="+storeDir)

	var buf bytes.Buffer
	writer := &boundedWriter{buf: &buf, max: maxDiffOutputBytes, cancel: cancel}
	cmd.Stdout = writer
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	// Once the bound is hit, cancel() kills the command, and whatever
	// cmd.Run() then returns — a copy error, a killed-process error, or a
	// race between the two — is expected and not a real failure: checked
	// against writer's own flag rather than against the exact error, which
	// is racy by the nature of killing a process mid-write.
	if writer.truncated {
		return buf.Bytes(), true, nil
	}
	if runErr != nil {
		return nil, false, fmt.Errorf("git diff-tree: %w: %s", runErr, strings.TrimSpace(stderr.String()))
	}
	return buf.Bytes(), false, nil
}

// boundedWriter caps how many bytes it accepts, then refuses the rest —
// the same technique that stops this handler from buffering an unbounded
// amount of an agent's own diff just because git was willing to produce
// one. cancel is called the moment the bound is hit, which stops the
// command (exec.CommandContext's own SIGKILL-on-cancel) rather than
// leaving it blocked writing to a pipe this handler has stopped reading —
// without it, a truncated command would sit for up to gitTimeout before
// this handler could return.
type boundedWriter struct {
	buf       *bytes.Buffer
	max       int
	cancel    context.CancelFunc
	truncated bool
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if w.buf.Len() >= w.max {
		w.truncated = true
		w.cancel()
		return 0, errDiffOutputTruncated
	}
	room := w.max - w.buf.Len()
	if len(p) > room {
		w.buf.Write(p[:room])
		w.truncated = true
		w.cancel()
		return len(p), errDiffOutputTruncated
	}
	return w.buf.Write(p)
}

// errDiffOutputTruncated is boundedWriter's own sentinel — its exact
// identity is not load-bearing (see boundedDiffTreePatch's own comment on
// why truncation is read off writer.truncated instead), only that Write
// returns SOME non-nil error so io.Copy stops immediately rather than
// retrying.
var errDiffOutputTruncated = errors.New("diff output exceeds this handler's bound")

// ---------------------------------------------------------------------------
// Parsing `git diff-tree -p -M` into StepDiff.
// ---------------------------------------------------------------------------

var diffGitHeader = regexp.MustCompile(`^diff --git a/(.*) b/(.*)$`)
var diffHunkHeader = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

// parseDiffTreePatch reads unified-diff text (`git diff-tree -p`'s own
// output — one or more `diff --git` sections, in git's own order) into
// StepDiff. Unrecognised lines between sections (extended header lines
// this parser does not specifically need, `index` lines, mode lines) are
// skipped rather than rejected: this parser reads only what record.go's
// DiffFile/DiffHunk/DiffLine need, the same "read what is needed, drop what
// is not" posture gatewayBody already holds for the Messages API.
func parseDiffTreePatch(out []byte, outputTruncated bool) StepDiff {
	lines := strings.Split(string(out), "\n")
	var files []DiffFile
	var cur *DiffFile
	var curHunk *DiffHunk
	oldNo, newNo := 0, 0

	flushHunk := func() {
		if cur != nil && curHunk != nil {
			cur.Hunks = append(cur.Hunks, *curHunk)
			curHunk = nil
		}
	}
	flushFile := func() {
		flushHunk()
		if cur != nil {
			if len(files) >= maxFilesPerDiff {
				// Dropped rather than appended: record.go's own Truncated
				// flag lives on a DiffFile, and a file this parser never
				// even started has nowhere honest to carry one. The LAST
				// file actually emitted is marked truncated instead — see
				// below.
				if len(files) > 0 {
					files[len(files)-1].Truncated = true
				}
			} else {
				files = append(files, *cur)
			}
			cur = nil
		}
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if m := diffGitHeader.FindStringSubmatch(line); m != nil {
			flushFile()
			cur = &DiffFile{Path: m[2], Status: "M"}
			continue
		}
		if cur == nil {
			continue
		}
		switch {
		case strings.HasPrefix(line, "new file mode"):
			cur.Status = "A"
		case strings.HasPrefix(line, "deleted file mode"):
			cur.Status = "D"
		case strings.HasPrefix(line, "rename from "):
			cur.Status = "R"
			cur.OldPath = strings.TrimPrefix(line, "rename from ")
		case strings.HasPrefix(line, "rename to "):
			cur.Status = "R"
			cur.Path = strings.TrimPrefix(line, "rename to ")
		case strings.HasPrefix(line, "Binary files ") || strings.HasPrefix(line, "GIT binary patch"):
			cur.Binary = true
			flushHunk()
		case strings.HasPrefix(line, "--- "), strings.HasPrefix(line, "+++ "):
			// Header lines this parser does not need beyond @@ itself.
		default:
			if m := diffHunkHeader.FindStringSubmatch(line); m != nil {
				flushHunk()
				oldStart, newStart := atoiOr(m[1], 0), atoiOr(m[3], 0)
				oldLines, newLines := atoiOr1(m[2]), atoiOr1(m[4])
				if len(cur.Hunks) >= maxHunksPerFile {
					cur.Truncated = true
					continue
				}
				curHunk = &DiffHunk{OldStart: oldStart, OldLines: oldLines, NewStart: newStart, NewLines: newLines}
				oldNo, newNo = oldStart, newStart
				continue
			}
			if curHunk == nil || cur.Binary {
				continue
			}
			if len(curHunk.Lines) >= maxLinesPerHunk {
				cur.Truncated = true
				continue
			}
			switch {
			case strings.HasPrefix(line, "\\ No newline"):
				// Not a content line.
			case strings.HasPrefix(line, "+"):
				curHunk.Lines = append(curHunk.Lines, DiffLine{Kind: "add", NewNo: newNo, Text: line[1:]})
				newNo++
			case strings.HasPrefix(line, "-"):
				curHunk.Lines = append(curHunk.Lines, DiffLine{Kind: "del", OldNo: oldNo, Text: line[1:]})
				oldNo++
			case strings.HasPrefix(line, " "):
				curHunk.Lines = append(curHunk.Lines, DiffLine{Kind: "context", OldNo: oldNo, NewNo: newNo, Text: line[1:]})
				oldNo++
				newNo++
			}
		}
	}
	flushFile()

	if outputTruncated && len(files) > 0 {
		files[len(files)-1].Truncated = true
	}
	if files == nil {
		files = []DiffFile{}
	}
	for i := range files {
		if files[i].Hunks == nil {
			files[i].Hunks = []DiffHunk{}
		}
		for j := range files[i].Hunks {
			if files[i].Hunks[j].Lines == nil {
				files[i].Hunks[j].Lines = []DiffLine{}
			}
		}
	}
	return StepDiff{Files: files}
}

func atoiOr(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// atoiOr1 reads a hunk header's optional line count, which git omits
// entirely when it is 1 (`@@ -5 +5,2 @@` means the old side is one line
// starting at 5).
func atoiOr1(s string) int {
	if s == "" {
		return 1
	}
	return atoiOr(s, 1)
}
