// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"io"
	"os"
	"time"

	"innsegl.dev/innsegl/internal/api"
)

// `innsegl admin-credential enrol-code` — ADR-0062's out-of-band one-time
// enrolment code (RM-260/RM-261, #409).
//
// # Why this lives under `admin-credential`
//
// Minting the enrolment code and minting the identity-lifecycle admin
// credential are the SAME presence-gated action, per the ADR's own words:
// "minting the enrolment code and minting an admin credential are the same
// presence-gated action." Putting this verb in the same command family as
// `keygen`/`mint`/`verify` says that plainly rather than inventing a second
// tool that happens to need the same kind of access.
//
// # Why it is NOT a fourth offline-signing verb
//
// `mint` issues a JWT an operator carries to a caller that may not be this
// machine; a one-time enrolment code has no such asymmetry to exploit — it
// is looked up and consumed by the SAME database `innsegl api` already
// holds a connection to, and it needs no public/private key pair at all.
// This command writes one row (internal/api.AuthStore.CreateEnrolmentCode),
// holding the auth-writer credential (internal/api.AuthWriterRole) the
// running `innsegl api` process also holds a second pool of — never the
// ledger's appending role, and never the read-only one either.
//
// # It does not bypass the socket-denial check
//
// Minting a code here says nothing about whether E18's container-socket
// denial is in effect RIGHT NOW, on THIS machine, at the moment somebody
// tries to spend it. The enrolment endpoint (internal/api's
// handleEnrolBegin/handleEnrolFinish) reads that fact itself, every time,
// independently of this command — ADR-0062: "the enrolment endpoint asks,
// every time, rather than trusting that a denial applied once is still
// applied now."

// enrolCodeDefaultTTL and enrolCodeMaxTTL bound the code's life. Fifteen
// minutes by default — the same number admincred.go's own
// mcp.AdminCredentialMaxTTL fixes for the admin credential itself, for the
// matching reason: ADR-0062 calls this code "single-use and short-lived",
// and an operator who has not finished the ceremony in that window mints a
// fresh one rather than this command's default holding a longer-lived
// standing secret.
const (
	enrolCodeDefaultTTL = 15 * time.Minute
	enrolCodeMaxTTL     = time.Hour
)

// envAuthWriterDSN names the auth-writer credential's DSN — `innsegl api`'s
// own $INNSEGL_API_AUTH_DSN (cmd/innsegl/api.go), reused here rather than
// respelled so that an operator who already has this deployment's compose
// environment loaded can run this command with no extra configuration.
const envAuthWriterDSN = "INNSEGL_API_AUTH_DSN"

// enrolCodeMinter is the one thing this command needs of an AuthStore — an
// interface, so the flag handling and exit statuses are testable without a
// Postgres, matching resolvealert.go's own resolver seam and reap.go's
// sweeper.
type enrolCodeMinter interface {
	CreateEnrolmentCode(ctx context.Context, ttl time.Duration) (code string, expiresAt time.Time, err error)
}

// enrolCodeDeps are the seams this command's tests replace. Production
// wiring is the zero value.
type enrolCodeDeps struct {
	open func(ctx context.Context, dsn string) (enrolCodeMinter, func(), error)
}

func (d enrolCodeDeps) opener() func(context.Context, string) (enrolCodeMinter, func(), error) {
	if d.open != nil {
		return d.open
	}
	return openEnrolCodeStore
}

// openEnrolCodeStore is OpenAuthStore, which — like every AuthStore open —
// refuses a credential that can write the ledger schema, exactly as
// `innsegl api` itself would if handed the wrong DSN.
func openEnrolCodeStore(ctx context.Context, dsn string) (enrolCodeMinter, func(), error) {
	s, err := api.OpenAuthStore(ctx, dsn)
	if err != nil {
		return nil, nil, err
	}
	return s, s.Close, nil
}

// adminCredentialEnrolCode is the subcommand body, dispatched from
// admincred.go's adminCredentialCommand.
func adminCredentialEnrolCode(args []string, stdout, stderr io.Writer) int {
	return runAdminCredentialEnrolCode(args, stdout, stderr, enrolCodeDeps{})
}

func runAdminCredentialEnrolCode(args []string, stdout, stderr io.Writer, deps enrolCodeDeps) int {
	fs := flag.NewFlagSet("innsegl admin-credential enrol-code", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("dsn", os.Getenv(envAuthWriterDSN),
		"the auth-writer connection string ($"+envAuthWriterDSN+") — internal/api.AuthWriterRole, "+
			"never the ledger's appending or read-only credential")
	ttl := fs.Duration("ttl", enrolCodeDefaultTTL,
		"how long the code is valid for, bounded by (0, "+enrolCodeMaxTTL.String()+"]")
	fs.Usage = func() {
		fprintf(stderr, "innsegl admin-credential enrol-code - mint the one-time code that "+
			"completes ADR-0062's\nfirst passkey enrolment, or its recovery\n\n")
		fprintf(stderr, "Usage:\n  innsegl admin-credential enrol-code -dsn <auth-writer DSN>\n\n")
		fprintf(stderr, "The code is written to STDOUT and to nowhere else. It is single-use: "+
			"the enrolment\nendpoint consumes it atomically on the first request that presents "+
			"it, and a second\nattempt with the same code is refused.\n\n")
		fprintf(stderr, "THIS DOES NOT BYPASS THE SOCKET-DENIAL CHECK. The enrolment endpoint "+
			"asks, every\ntime, whether E18's container-socket denial is in effect on this "+
			"deployment right\nnow, independently of this command minting a code "+
			"(ADR-0062).\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if code, ok := adminCredentialParse(fs, args); !ok {
		return code
	}
	if *dsn == "" {
		fprintf(stderr, "innsegl admin-credential enrol-code: -dsn (or $"+envAuthWriterDSN+
			") is required\n")
		return exitUsage
	}
	if *ttl <= 0 || *ttl > enrolCodeMaxTTL {
		fprintf(stderr, "innsegl admin-credential enrol-code: -ttl %s is outside (0, %s]\n",
			*ttl, enrolCodeMaxTTL)
		return exitUsage
	}

	ctx := context.Background()
	store, closeAll, err := deps.opener()(ctx, *dsn)
	if err != nil {
		fprintf(stderr, "innsegl admin-credential enrol-code: %v\n", err)
		return exitCredentialUnusable
	}
	if closeAll != nil {
		defer closeAll()
	}

	code, expiresAt, err := store.CreateEnrolmentCode(ctx, *ttl)
	if err != nil {
		fprintf(stderr, "innsegl admin-credential enrol-code: %v\n", err)
		return exitCredentialUnusable
	}

	// STDOUT and nothing else, matching `mint`'s own discipline: the
	// diagnostic below names the expiry and never the code itself.
	fprintf(stdout, "%s\n", code)
	fprintf(stderr, "innsegl admin-credential enrol-code: issued, valid until %s\n",
		expiresAt.Format(time.RFC3339))
	return exitOK
}
