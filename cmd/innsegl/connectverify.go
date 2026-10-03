// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// errNoHarness: Claude Code is not installed here, so whether it loads the
// managed settings cannot be checked.
var errNoHarness = errors.New("claude is not on PATH")

// loadHarness has Claude Code read the managed settings and write its debug
// log to debugFile. `mcp list` reads the settings and makes no model call.
// The system path is read by the harness on its own; any other path only
// when named.
func loadHarness(settings string, named bool, debugFile, _ string) error {
	claude, err := exec.LookPath("claude")
	if err != nil {
		return errNoHarness
	}
	args := []string{"--setting-sources", "", "--debug-file", debugFile, "mcp", "list"}
	if named {
		args = append([]string{"--settings", settings}, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, claude, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, io.Discard, io.Discard
	// Its exit status says nothing about the settings; the log does. Only a
	// harness that could not be started at all is an error.
	var exitErr *exec.ExitError
	if runErr := cmd.Run(); runErr != nil && !errors.As(runErr, &exitErr) {
		return runErr
	}
	return nil
}

// verifyHarnessLoaded is ENF-006: Claude Code drops a WHOLE settings file
// when one value has the wrong type, and says nothing (measured 2026-09-30:
// the route, the hooks and the sandbox all absent, a session committing
// unrecorded). Every key loads or none does, so one is enough to tell: the
// harness's debug log names the extra CA the file's env sets.
func verifyHarnessLoaded(deps connectDeps, settings string, named bool, ca string, stdout, stderr io.Writer) int {
	load := deps.loadHarness
	if load == nil {
		load = loadHarness
	}
	log, err := os.CreateTemp("", "innsegl-connect-verify-*")
	if err != nil {
		fprintf(stderr, "innsegl connect: checking the harness loaded %s: %v\n", settings, err)
		return exitConnectFailed
	}
	path := log.Name()
	_ = log.Close()
	defer func() { _ = os.Remove(path) }()

	if lerr := load(settings, named, path, ca); errors.Is(lerr, errNoHarness) {
		fprintf(stdout, "innsegl connect: Claude Code is not installed here, so whether it loads %s "+
			"could not be checked. Run `innsegl connect --update` once it is.\n", settings)
		return exitOK
	} else if lerr != nil {
		fprintf(stderr, "innsegl connect: checking the harness loaded %s: %v\n", settings, lerr)
		return exitConnectFailed
	}
	// #nosec G304 -- the temporary file this function created.
	text, err := os.ReadFile(path)
	if err == nil && strings.Contains(string(text), "extraCertsPath="+ca) {
		fprintf(stdout, "innsegl connect: Claude Code loaded %s\n", settings)
		return exitOK
	}
	fprintf(stderr, "innsegl connect: Claude Code did NOT load %s.\n"+
		"  It drops the whole file, silently, when any one value has the wrong type,\n"+
		"  so the route, the hooks and the sandbox are all absent. Check every key\n"+
		"  in the file against the Claude Code settings reference, then run this again.\n", settings)
	return exitConnectFailed
}
