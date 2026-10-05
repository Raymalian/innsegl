// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"innsegl.dev/innsegl/internal/commitpath"
)

// `innsegl sign` — git's own `gpg.x509.program` (ADR-0059 decision 3), not
// gitsign directly.
//
// Git already speaks a contract for this configuration point (ADR-0031
// decision 1, from the signer's side): it invokes the configured program as
//
//	<program> --status-fd=<N> -bsau <signing key>
//
// with the unsigned commit object on stdin, and expects a detached CMS
// signature on stdout plus gpg status lines (`[GNUPG:] SIG_CREATED ...`) on
// the file descriptor `--status-fd` names — measured against a real git by
// TestCMT013InvokedAsGitsSigningProgramSignsARealCommit, which records the
// exact argv rather than assuming it.
//
// This program is a thin client over that contract: it reads the payload,
// attaches the tool call id the harness's own `PreToolUse` hook put on this
// process's environment (ADR-0059 decision 1, commitpath.EnvToolUseID), and
// asks the core to sign it. It never runs gitsign itself and is never handed
// a credential — the core does that, inside its own single call (decision 4).
//
// # FAIL CLOSED (ADR-0059 decision 7, CMT-014)
//
// Every error below — no tool call id, an unreachable or refusing core, an
// oversized payload, an invocation this program does not recognise — takes
// the same shape: the reason goes to stderr, NOTHING goes to stdout, and
// runSign returns non-zero. `gpg.x509.program` exiting non-zero is what makes
// git itself abort the commit before writing a ref; nothing here has to ask
// git to do that separately.

// signMaxPayloadBytes bounds what this program reads from git's stdin before
// asking the core to sign it. An ordinary unsigned commit object is a few
// hundred bytes; a caller that produces gigabytes of "payload" on this fd is
// not git behaving normally, and is refused rather than forwarded.
const signMaxPayloadBytes = 8 << 20 // 8 MiB

// The two file descriptors this program can actually write to, because
// runSign is handed stdout and stderr as io.Writer and nothing else — no raw
// file descriptor table to open an arbitrary N from. Every `--status-fd` this
// program has measured git pass is 2 (see the package doc above); 1 is
// accepted too, since it is the other half of gpg's own contract. Any other
// value is refused rather than silently dropping the status lines git asked
// for, which is decision 7's fail-closed rule applied to this program's own
// narrower job.
const (
	signStatusFDStdout = 1
	signStatusFDStderr = 2
)

// signClient is what runSign asks to sign a payload. commitpath.Client
// satisfies it; tests use a double so the core's own gates are never a
// prerequisite for testing this file's argument handling.
type signClient interface {
	Sign(ctx context.Context, req commitpath.SignRequest) (commitpath.SignResponse, error)
}

// commitStager is the push half of a hosted client (commitpath.Client.Stage).
// A client without it (a test double) asks the core directly.
type commitStager interface {
	Stage(ctx context.Context, dir, toolUseID string, payload []byte) error
}

// runSign is `innsegl sign`. It is reached two ways, both through
// signCommand (commitpathcli.go): cli.go's `sign` table entry, and cli.go's
// --status-fd/--verify dispatch, which is how git calls this binary when a
// repository sets it as `gpg.x509.program` directly. Its signature takes
// stdin, stdout and stderr separately rather than the (args, stdout, stderr)
// shape every table entry uses: git's own contract hands this process a
// payload on stdin and expects two different things back on two different
// streams.
func runSign(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string, client signClient) int {
	refuse := func(format string, a ...any) int {
		fprintf(stderr, "innsegl sign: "+format+"\n", a...)
		return 1
	}

	// Verify mode: `git verify-commit` invokes the same `gpg.x509.program`
	// with `--verify`. This program only ever signs; ADR-0031's own verifier
	// is gitsign, so a caller that reaches this branch is pointed at it
	// rather than told nothing runs at all.
	for _, a := range args {
		if a == "--verify" {
			return refuse("does not verify commits; git invoked it with --verify. " +
				"Verify with gitsign, the released upstream verifier: `gitsign verify`, or " +
				"`git -c gpg.format=x509 -c gpg.x509.program=gitsign verify-commit <commit>`.")
		}
	}

	fd, err := signStatusFD(args)
	if err != nil {
		return refuse("%v", err)
	}
	if fd != signStatusFDStdout && fd != signStatusFDStderr {
		return refuse("git asked for its status on fd %d; this program only writes to fd 1 "+
			"(stdout) or fd 2 (stderr)", fd)
	}

	toolUseID := getenv(commitpath.EnvToolUseID)
	if toolUseID == "" {
		return refuse("no tool call id: this git commit was not run by an agent through the "+
			"gateway (%s is unset)", commitpath.EnvToolUseID)
	}

	// The agent's signing is for the agent's repository (envSignRepo): a
	// commit anywhere else inherited the configuration from the same
	// command, and is not the agent's to sign.
	if want := getenv(envSignRepo); want != "" {
		got, gerr := gitCommonDir(ctx, ".")
		if gerr != nil || got != want {
			return refuse("this commit is in %s, not the repository the agent's tool call works in (%s); "+
				"it is not signed under the agent's identity. A test or tool that makes its own commits "+
				"inherited the agent's signing from the same command: run it in a command of its own", orUnknown(got), want)
		}
	}

	// Bounded: read one byte past the limit so an oversized payload is
	// detected rather than silently truncated and forwarded as something
	// shorter than what git actually wrote.
	payload, err := io.ReadAll(io.LimitReader(stdin, signMaxPayloadBytes+1))
	if err != nil {
		return refuse("reading the commit object git gave on stdin: %v", err)
	}
	if len(payload) > signMaxPayloadBytes {
		return refuse("the commit object on stdin is larger than %d bytes", signMaxPayloadBytes)
	}

	// A hosted client's objects exist only here: push them to the core's
	// mirror first (#465, ADR-0065), because the core computes the change's
	// identity from them. A failed push does not end the commit here: the
	// core may already hold the objects, and when it does not, its own
	// refusal names what is missing. Both reasons reach stderr.
	if st, ok := client.(commitStager); ok {
		if serr := st.Stage(ctx, ".", toolUseID, payload); serr != nil {
			fprintf(stderr, "innsegl sign: pushing the commit's objects to the core: %v\n", serr)
		}
	}

	resp, err := client.Sign(ctx, commitpath.SignRequest{
		ToolUseID: toolUseID,
		Args:      args,
		Payload:   payload,
	})
	if err != nil {
		// The core's own reason (unreachable, refused, or anything else) —
		// nothing has been written to stdout at this point, so git aborts
		// the commit with no ref ever written (CMT-014).
		return refuse("%v", err)
	}

	if _, werr := stdout.Write(resp.Signature); werr != nil {
		return refuse("writing the signature to stdout: %v", werr)
	}
	statusOut := stderr
	if fd == signStatusFDStdout {
		statusOut = stdout
	}
	if _, werr := statusOut.Write(resp.Status); werr != nil {
		return refuse("writing git's status lines: %v", werr)
	}
	return 0
}

// signStatusFD reads `--status-fd=<N>` or `--status-fd <N>` out of git's
// arguments, alongside whatever else git passed (the combined short flags
// `-bsau <key>`, measured — see the package doc above). Both forms of the
// flag are git's own; nothing about which one is used is this program's
// choice.
func signStatusFD(args []string) (int, error) {
	for i, a := range args {
		switch {
		case a == "--status-fd":
			if i+1 >= len(args) {
				return 0, fmt.Errorf("--status-fd has no value")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil {
				return 0, fmt.Errorf("--status-fd %q is not a number", args[i+1])
			}
			return n, nil
		case strings.HasPrefix(a, "--status-fd="):
			v := strings.TrimPrefix(a, "--status-fd=")
			n, err := strconv.Atoi(v)
			if err != nil {
				return 0, fmt.Errorf("--status-fd=%q is not a number", v)
			}
			return n, nil
		}
	}
	return 0, fmt.Errorf("git's arguments named no --status-fd; not the invocation this program expects: %v", args)
}

func orUnknown(s string) string {
	if s == "" {
		return "a directory git does not name as a repository"
	}
	return s
}
