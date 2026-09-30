// SPDX-License-Identifier: Apache-2.0

// Command cmt011signclient is CMT-011's own `gpg.x509.program` (internal/mcp's
// signpayload_crash_test.go), built solely so that test can drive a REAL
// `git commit` through a real child process and observe what git itself does
// when that process fails.
//
// It reimplements cmd/innsegl's own `innsegl sign` (cmd/innsegl/sign.go)
// narrowly rather than importing it: that file lives in package main and
// cannot be imported from a test, and ADR-0059 decision 3's contract is
// small enough that a second, test-only copy is honest about what it is
// rather than a fragile reach into another package's internals.
//
// It lives under testdata/ so `go build ./...`, `go vet ./...` and
// golangci-lint's own default package discovery skip it exactly as they skip
// every other fixture in this repository; signpayload_crash_test.go builds it
// explicitly, by its own directory path, when it needs the binary.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv))
}

// run is git's own `gpg.x509.program` contract (ADR-0059 decision 3):
// invoked as `<program> --status-fd=<N> -bsau <key>` with the unsigned
// commit object on stdin, and expected to answer a detached CMS signature on
// stdout plus gpg status lines on the descriptor `--status-fd` names.
//
// FAIL CLOSED, on cmd/innsegl/sign.go's own rule: every error below writes
// its reason to stderr, nothing to stdout, and returns non-zero -- which is
// what makes git itself abort the commit before writing a ref.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	refuse := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "cmt011signclient: "+format+"\n", a...)
		return 1
	}

	fd, err := statusFD(args)
	if err != nil {
		return refuse("%v", err)
	}
	if fd != 1 && fd != 2 {
		return refuse("git asked for its status on fd %d; this helper only writes fd 1 or 2", fd)
	}

	toolUseID := getenv(commitpath.EnvToolUseID)
	if toolUseID == "" {
		return refuse("no tool call id: %s is unset", commitpath.EnvToolUseID)
	}

	const maxPayloadBytes = 8 << 20
	payload, err := io.ReadAll(io.LimitReader(stdin, maxPayloadBytes+1))
	if err != nil {
		return refuse("reading the commit object git gave on stdin: %v", err)
	}
	if len(payload) > maxPayloadBytes {
		return refuse("the commit object on stdin is larger than %d bytes", maxPayloadBytes)
	}

	client := commitpath.ClientFromEnv(getenv)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	resp, err := client.Sign(ctx, commitpath.SignRequest{
		ToolUseID: toolUseID, Args: args, Payload: payload,
	})
	if err != nil {
		// The core's own reason -- refused, or a Phase C the ledger would not
		// accept -- reaches git as this program's own non-zero exit, with
		// nothing on stdout, exactly CMT-011's own case.
		return refuse("%v", err)
	}

	if _, werr := stdout.Write(resp.Signature); werr != nil {
		return refuse("writing the signature to stdout: %v", werr)
	}
	statusOut := stderr
	if fd == 1 {
		statusOut = stdout
	}
	if _, werr := statusOut.Write(resp.Status); werr != nil {
		return refuse("writing git's status lines: %v", werr)
	}
	return 0
}

// statusFD reads `--status-fd=<N>` out of git's own argv -- the one form
// measured against real git (cmd/innsegl/sign.go's own package doc); this
// helper needs nothing more.
func statusFD(args []string) (int, error) {
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "--status-fd="); ok {
			n, err := strconv.Atoi(v)
			if err != nil {
				return 0, fmt.Errorf("--status-fd=%q is not a number", v)
			}
			return n, nil
		}
	}
	return 0, fmt.Errorf("git's arguments named no --status-fd: %v", args)
}
