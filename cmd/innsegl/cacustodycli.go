// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"filippo.io/age"

	"innsegl.dev/innsegl/internal/cacustody"
	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/trustbackup"
)

// `innsegl ca-custody` (ADR-0076), on the operator's machine:
//
//	status   can the core's CA sign? (sealed, or unsealed with the reason it cannot)
//	unlock   if it is, open its unlock material (Touch ID) and send it back
//	recipients  the set the unlock material is sealed to
//	reseal   re-seal the same material to a new set (ADR-0082 decision 7)
//
// The client service does the same on its own once a minute; this is the
// terminal's way to it.

// exitCACustodySealed: status found that the CA cannot sign: the store is
// sealed, or its token or key is not usable (the reason is printed).
const exitCACustodySealed = 28

const caCustodyUsage = `Usage:
  innsegl ca-custody status                 say whether the core's CA can sign
  innsegl ca-custody unlock [--identity F]  unlock it, or repair a dead token, when the CA cannot sign (asks for Touch ID)
  innsegl ca-custody recipients             list the recipients the unlock material is sealed to
  innsegl ca-custody reseal --add R | --remove R | --set FILE [--identity F] [--opener R]
                                            re-seal the same material to a new set (asks, then Touch ID twice)
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
	return runCACustodyIO(ctx, args, os.Stdin, stdout, stderr, home)
}

// runCACustodyIO is runCACustody with the terminal's input, which reseal
// reads its confirmation from.
func runCACustodyIO(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, home string) int {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		fprintf(stderr, "%s", caCustodyUsage)
		return exitOK
	}
	if len(args) == 0 || !slices.Contains([]string{"status", "unlock", "recipients", "reseal"}, args[0]) {
		fprintf(stderr, "innsegl ca-custody: name a verb: status, unlock, recipients or reseal\n\n%s", caCustodyUsage)
		return exitUsage
	}
	paths := client.ClientPaths(home)
	switch args[0] {
	case "recipients":
		return runCACustodyRecipients(ctx, args[1:], stdout, stderr, paths)
	case "reseal":
		return runCACustodyReseal(ctx, args[1:], stdin, stdout, stderr, paths)
	}
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
		case !st.CanSign:
			if st.Reason == "" {
				fprintf(stdout, "ca custody: unlocked, but the CA CANNOT sign: "+
					"the core does not say whether its CA can sign; update the core\n")
				return exitCACustodySealed
			}
			fprintf(stdout, "ca custody: unlocked, but the CA CANNOT sign: %s\n", st.Reason)
			fprintf(stdout, "ca custody: repair: run `innsegl doctor`, or `innsegl ca-custody unlock`; no restart\n")
			return exitCACustodySealed
		default:
			fprintf(stdout, "ca custody: unlocked; the CA can sign\n")
		}
		return exitOK
	}
	if st, err := client.CAStatus(ctx, paths); err == nil && st.Enabled {
		switch {
		case st.Sealed:
			fprintf(stdout, "ca custody: repairing: the store is sealed\n")
		case !st.CanSign && st.Reason != "":
			fprintf(stdout, "ca custody: repairing: %s\n", st.Reason)
		case !st.CanSign:
			fprintf(stdout, "ca custody: the core does not say whether its CA can sign; "+
				"update the core to repair an unsealed store\n")
		}
	}
	unlocked, err := client.UnlockCA(ctx, paths, operatorIdentities(*identity, stderr))
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

func runCACustodyRecipients(ctx context.Context, args []string, stdout, stderr io.Writer, paths client.Paths) int {
	fs := flag.NewFlagSet("recipients", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if code, done := parseFlags(fs, args); done {
		return code
	}
	set, err := client.CARecipients(ctx, paths)
	if err != nil {
		fprintf(stderr, "innsegl ca-custody: %v\n", err)
		return exitCACustodyFailed
	}
	printSet(stdout, "the unlock material is sealed to", set.Recipients, "")
	fprintf(stdout, "ca custody: set %s\n", set.Digest)
	if !set.Recorded {
		fprintf(stdout, "ca custody: the store predates the reseal; this is the configured set, not yet recorded by a reseal\n")
	}
	return exitOK
}

// runCACustodyReseal re-seals the CA's unlock material to a new set
// (ADR-0082 decision 7). It shows the current and the new set, asks, and
// only then opens the material. Nothing is opened for a set it refuses: an
// empty one, one without this machine, one with a member that is no
// recipient.
func runCACustodyReseal(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer,
	paths client.Paths) int {
	fs := flag.NewFlagSet("reseal", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var add, remove multiFlag
	fs.Var(&add, "add", "a recipient to add (age1…); repeatable")
	fs.Var(&remove, "remove", "a recipient to remove; repeatable")
	setFile := fs.String("set", "", "a file holding the whole new set, one recipient per line, # comments allowed")
	identity := fs.String("identity", paths.TrustIdentity,
		"the age identity file that opens the unlock material (a Secure Enclave identity asks for Touch ID)")
	openerFlag := fs.String("opener", "", "this machine's own recipient, when the identity file does not name it")
	if code, done := parseFlags(fs, args); done {
		return code
	}
	fail := func(format string, v ...any) int {
		fprintf(stderr, "innsegl ca-custody reseal: "+format+"\n", v...)
		return exitCACustodyFailed
	}
	switch {
	case *setFile != "" && len(add)+len(remove) > 0:
		fprintf(stderr, "innsegl ca-custody reseal: --set names the whole set; do not combine it with --add or --remove\n")
		return exitUsage
	case *setFile == "" && len(add)+len(remove) == 0:
		fprintf(stderr, "innsegl ca-custody reseal: name a change: --add, --remove or --set\n\n%s", caCustodyUsage)
		return exitUsage
	}
	current, err := client.CARecipients(ctx, paths)
	if err != nil {
		return fail("%v", err)
	}
	next := slices.Clone(current.Recipients)
	if *setFile != "" {
		if next, err = readRecipientSet(*setFile); err != nil {
			return fail("%v", err)
		}
	}
	for _, r := range add {
		next = append(next, r)
	}
	next = slices.DeleteFunc(canonicalRecipients(next), func(r string) bool { return slices.Contains(remove, r) })
	if len(next) == 0 {
		return fail("the new set is empty, and nobody could open the material; nothing changed")
	}
	if _, err = trustbackup.ParseRecipients(strings.Join(next, " ")); err != nil {
		return fail("%v; nothing changed", err)
	}
	digest := cacustody.SetDigest(next)
	if digest == current.Digest {
		fprintf(stdout, "ca custody: the set is unchanged (%s); nothing to reseal\n", digest)
		return exitOK
	}
	mine, err := identityRecipients(*identity)
	if err != nil {
		return fail("%v", err)
	}
	opener := strings.TrimSpace(*openerFlag)
	if opener == "" {
		for _, r := range mine {
			if slices.Contains(next, r) {
				opener = r
				break
			}
		}
	}
	switch {
	case opener == "" && len(mine) == 0:
		return fail("%s does not name its own recipient; name it with --opener; nothing changed", *identity)
	case !slices.Contains(next, opener):
		return fail("the new set does not hold this machine (%s), so it could not open the material again; "+
			"nothing changed", strings.Join(append(mine, opener), ", "))
	}

	printSet(stdout, "now sealed to", current.Recipients, opener)
	fprintf(stdout, "ca custody:   set %s\n", current.Digest)
	printSet(stdout, "reseal to", next, opener)
	for _, r := range next {
		if !slices.Contains(current.Recipients, r) {
			fprintf(stdout, "ca custody:   + %s\n", r)
		}
	}
	for _, r := range current.Recipients {
		if !slices.Contains(next, r) {
			fprintf(stdout, "ca custody:   - %s (new copies are not sealed to it; older copies and bundles still open with it)\n", r)
		}
	}
	fprintf(stdout, "ca custody:   set %s\n", digest)
	fprintf(stdout, "Reseal the CA's unlock material to this set? [y/N] ")
	// A last line without its newline still answers; any other read error
	// is no answer, and so no.
	answer, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		answer = ""
	}
	if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
		fprintf(stdout, "\nca custody: not resealed; nothing changed\n")
		return exitCACustodyFailed
	}
	fprintf(stdout, "ca custody: opening the material, then the staged copy (each may ask for Touch ID)\n")
	staged, err := client.ResealCA(ctx, paths, opener, next, operatorIdentities(*identity, stderr))
	if err != nil {
		return fail("%v", err)
	}
	fprintf(stdout, "ca custody: resealed: the unlock material is sealed to %d recipient(s), set %s\n",
		len(staged.Recipients), staged.SetDigest)
	fprintf(stdout, "ca custody: the CA key, the store and its unseal key are unchanged\n")
	fprintf(stdout, "ca custody: trust-key backups from now on encrypt to this set as well; "+
		"older bundles keep their recipients, so take and drill a new bundle now\n")
	return exitOK
}

func printSet(w io.Writer, title string, set []string, opener string) {
	fprintf(w, "ca custody: %s %d recipient(s):\n", title, len(set))
	for _, r := range set {
		if r == opener {
			fprintf(w, "ca custody:   %s (this machine)\n", r)
			continue
		}
		fprintf(w, "ca custody:   %s\n", r)
	}
}

// canonicalRecipients trims, drops empties and duplicates, and sorts: the
// form cacustody.SetDigest commits to.
func canonicalRecipients(list []string) []string {
	var out []string
	for _, r := range list {
		if r = strings.TrimSpace(r); r != "" && !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	slices.Sort(out)
	return out
}

// readRecipientSet reads a set file: one recipient per line, blank lines
// and # comments ignored.
func readRecipientSet(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var set []string
	for i, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) > 1 {
			return nil, fmt.Errorf("%s:%d: want one recipient per line, got %d", path, i+1, len(fields))
		}
		set = append(set, fields...)
	}
	return set, nil
}

// identityRecipients are the recipients an identity file names without
// running anything: each X25519 key's own, and each "# public key: age1…"
// or "# recipient: age1…" comment, as age-plugin-se and others write them.
func identityRecipients(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "AGE-SECRET-KEY-1"):
			id, err := age.ParseX25519Identity(line)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			out = append(out, id.Recipient().String())
		case strings.HasPrefix(line, "#"):
			lower := strings.ToLower(line)
			for _, key := range []string{"public key:", "recipient:"} {
				if i := strings.Index(lower, key); i >= 0 {
					if f := strings.Fields(line[i+len(key):]); len(f) > 0 && strings.HasPrefix(f[0], "age1") {
						out = append(out, f[0])
					}
				}
			}
		}
	}
	return out, sc.Err()
}
