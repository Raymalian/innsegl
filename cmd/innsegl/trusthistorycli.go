// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"innsegl.dev/innsegl/internal/trusthistory"
)

// `innsegl trust-history` — read and end entries in the trust history
// (ADR-0073), for scripts/ca-rotate.sh (#533).
//
// The rotation runs on the host, and the history lives on a volume only the
// core mounts read-write. So the script runs this inside the core, with
// `docker exec -i`, and passes PEM material on stdin. The command is small on
// purpose: every rule about what may change is trusthistory's, and this only
// turns its answers into exit statuses a shell script can act on.
//
//	innsegl trust-history has    --kind K            < PEM
//	innsegl trust-history record --kind K            < PEM
//	innsegl trust-history end    --kind K --key-id ID --mode retire|revoke \
//	                             --at RFC3339 --reason TEXT
//
// --file names the history; the default is $INNSEGL_TRUST_HISTORY, which the
// core's own environment sets.

const trustHistoryUsage = `Usage:
  innsegl trust-history has    --kind K            < PEM
  innsegl trust-history record --kind K            < PEM
  innsegl trust-history end    --kind K --key-id ID --mode retire|revoke --at RFC3339 --reason TEXT

--file names the history; the default is $INNSEGL_TRUST_HISTORY.
`

// Exit statuses beyond exitOK and exitUsage. Part of the script contract.
const (
	// exitTrustHistoryError: the history could not be read or written, or
	// refused the change.
	exitTrustHistoryError = 3
	// exitTrustHistoryAbsent: `has` read the history and it does not hold
	// the material.
	exitTrustHistoryAbsent = 4
)

func trustHistoryCommand(args []string, stdout, stderr io.Writer) int {
	return runTrustHistory(args, os.Stdin, stdout, stderr, os.Getenv)
}

func runTrustHistory(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 {
		fprintf(stderr, "innsegl trust-history: name a verb: has, record or end\n")
		return exitUsage
	}
	verb := args[0]
	if verb == "-h" || verb == "--help" || verb == "help" {
		fprintf(stdout, "%s", trustHistoryUsage)
		return exitOK
	}
	fs := flag.NewFlagSet("innsegl trust-history "+verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", getenv(envTrustHistory), "the trust history (default $"+envTrustHistory+")")
	kind := fs.String("kind", "", "the entry's kind, e.g. fulcio_root")
	keyID := fs.String("key-id", "", "end: the entry's key id")
	mode := fs.String("mode", "", "end: retire or revoke")
	at := fs.String("at", "", "end: the end date, RFC 3339")
	reason := fs.String("reason", "", "end: why")
	switch verb {
	case "has", "record", "end":
	default:
		fprintf(stderr, "innsegl trust-history: unknown verb %q; it is has, record or end\n", verb)
		return exitUsage
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 0 || *file == "" || *kind == "" {
		fprintf(stderr, "innsegl trust-history %s: needs --kind and a history (--file or $%s), and no other arguments\n",
			verb, envTrustHistory)
		return exitUsage
	}
	k := trusthistory.Kind(*kind)
	switch verb {
	case "has":
		return trustHistoryHas(*file, k, stdin, stdout, stderr)
	case "record":
		return trustHistoryRecord(*file, k, stdin, stdout, stderr)
	}
	if *keyID == "" {
		fprintf(stderr, "innsegl trust-history end: needs --key-id\n")
		return exitUsage
	}
	when, err := time.Parse(time.RFC3339, *at)
	if err != nil {
		fprintf(stderr, "innsegl trust-history end: --at: %v\n", err)
		return exitUsage
	}
	return trustHistoryEnd(*file, k, *keyID, trusthistory.EndMode(*mode), when, *reason, stdout, stderr)
}

func trustHistoryHas(file string, kind trusthistory.Kind, stdin io.Reader, stdout, stderr io.Writer) int {
	h, err := trusthistory.Load(file)
	if err != nil {
		fprintf(stderr, "innsegl trust-history has: %v\n", err)
		return exitTrustHistoryError
	}
	_, id, err := readMaterial(stdin)
	if err != nil {
		fprintf(stderr, "innsegl trust-history has: stdin: %v\n", err)
		return exitTrustHistoryError
	}
	if _, ok := h.Lookup(kind, id); !ok {
		fprintf(stderr, "innsegl trust-history has: %s holds no %s %s\n", file, kind, id)
		return exitTrustHistoryAbsent
	}
	fprintf(stdout, "%s\n", id)
	return exitOK
}

func trustHistoryRecord(file string, kind trusthistory.Kind, stdin io.Reader, stdout, stderr io.Writer) int {
	h, err := trusthistory.Load(file)
	if errors.Is(err, os.ErrNotExist) {
		h, err = trusthistory.New(), nil
	}
	if err != nil {
		fprintf(stderr, "innsegl trust-history record: %v\n", err)
		return exitTrustHistoryError
	}
	raw, id, err := readMaterial(stdin)
	if err != nil {
		fprintf(stderr, "innsegl trust-history record: stdin: %v\n", err)
		return exitTrustHistoryError
	}
	added, err := h.Record(kind, raw, time.Now())
	if err != nil {
		fprintf(stderr, "innsegl trust-history record: %v\n", err)
		return exitTrustHistoryError
	}
	if !added {
		fprintf(stdout, "innsegl trust-history: %s already holds %s %s\n", file, kind, id)
		return exitOK
	}
	if err := trusthistory.Save(file, h); err != nil {
		fprintf(stderr, "innsegl trust-history record: %v\n", err)
		return exitTrustHistoryError
	}
	fprintf(stdout, "innsegl trust-history: recorded %s %s\n", kind, id)
	return exitOK
}

// readMaterial reads the PEM material on stdin, and its key id.
func readMaterial(stdin io.Reader) ([]byte, string, error) {
	raw, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
	if err != nil {
		return nil, "", err
	}
	id, err := trusthistory.KeyIDOf(raw)
	if err != nil {
		return nil, "", err
	}
	return raw, id, nil
}

func trustHistoryEnd(file string, kind trusthistory.Kind, keyID string, mode trusthistory.EndMode,
	at time.Time, reason string, stdout, stderr io.Writer) int {
	h, err := trusthistory.Load(file)
	if err == nil {
		err = h.End(kind, keyID, mode, at, reason)
	}
	if err == nil {
		err = trusthistory.Save(file, h)
	}
	if err != nil {
		fprintf(stderr, "innsegl trust-history end: %v\n", err)
		return exitTrustHistoryError
	}
	verb := "retired"
	if mode == trusthistory.EndRevoke {
		verb = "revoked"
	}
	fprintf(stdout, "innsegl trust-history: %s %s %s at %s (%s)\n", verb, kind, keyID,
		at.UTC().Format(time.RFC3339), reason)
	return exitOK
}
