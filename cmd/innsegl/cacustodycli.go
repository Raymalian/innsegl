// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"io"
	"os"
	"os/signal"
	"syscall"

	"filippo.io/age"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/trustbackup"
)

// `innsegl ca-custody` (ADR-0076), on the operator's machine:
//
//	status   is the core's CA key store sealed?
//	unlock   if it is, open its unlock material (Touch ID) and send it back
//
// The client service does the same on its own once a minute; this is the
// terminal's way to it.

// exitCACustodySealed: status found the CA sealed, so it cannot sign.
const exitCACustodySealed = 28

const caCustodyUsage = `Usage:
  innsegl ca-custody status                 say whether the core's CA can sign
  innsegl ca-custody unlock [--identity F]  unlock it if it is sealed (asks for Touch ID)
`

func caCustodyCommand(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	home, err := os.UserHomeDir()
	if err != nil {
		fprintf(stderr, "innsegl ca-custody: %v\n", err)
		return exitCACustodyFailed
	}
	return runCACustody(ctx, args, stdout, stderr, home)
}

func runCACustody(ctx context.Context, args []string, stdout, stderr io.Writer, home string) int {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		fprintf(stderr, "%s", caCustodyUsage)
		return exitOK
	}
	if len(args) == 0 || (args[0] != "status" && args[0] != "unlock") {
		fprintf(stderr, "innsegl ca-custody: name a verb: status or unlock\n\n%s", caCustodyUsage)
		return exitUsage
	}
	paths := client.ClientPaths(home)
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	identity := fs.String("identity", paths.TrustIdentity,
		"the age identity file that opens the unlock material (a Secure Enclave identity asks for Touch ID)")
	if code, done := parseFlags(fs, args[1:]); done {
		return code
	}
	if args[0] == "status" {
		st, err := client.CAStatus(ctx, paths)
		if err != nil {
			fprintf(stderr, "innsegl ca-custody: %v\n", err)
			return exitCACustodyFailed
		}
		switch {
		case !st.Enabled:
			fprintf(stdout, "ca custody: off; this core keeps its CA key in a file\n")
		case st.Sealed:
			fprintf(stdout, "ca custody: SEALED; the CA cannot sign. Run `innsegl ca-custody unlock`, "+
				"or approve the Touch ID prompt the client service shows\n")
			if st.Error != "" {
				fprintf(stdout, "ca custody: %s\n", st.Error)
			}
			return exitCACustodySealed
		default:
			fprintf(stdout, "ca custody: unlocked; the CA can sign\n")
		}
		return exitOK
	}
	unlocked, err := client.UnlockCA(ctx, paths, func() ([]age.Identity, error) {
		return trustbackup.LoadIdentities(*identity, nil)
	})
	if err != nil {
		fprintf(stderr, "innsegl ca-custody: %v\n", err)
		return exitCACustodyFailed
	}
	if unlocked {
		fprintf(stdout, "ca custody: unlocked; the CA can sign\n")
	} else {
		fprintf(stdout, "ca custody: nothing to unlock\n")
	}
	return exitOK
}
