// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"innsegl.dev/innsegl/internal/client"
)

// `innsegl client serve` — RM-285 (#461), ADR-0063 decision 4. The
// user-level service `innsegl connect` installs: the only holder of this
// machine's key. The harness, the hooks and git talk to it over plain http
// on loopback, and it forwards every request to the core over one mutually
// authenticated connection, streaming bodies both ways. It renews the
// certificate at half-life with the same key, and once the core refuses a
// renewal it refuses everything, because the installation was revoked.

// exitClientFailed: the client service could not start or stopped on an
// error.
const exitClientFailed = 25

func clientCommand(args []string, stdout, stderr io.Writer) int {
	home, err := os.UserHomeDir()
	if err != nil {
		fprintf(stderr, "innsegl client: %v\n", err)
		return exitClientFailed
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runClientCommand(ctx, args, stdout, stderr, home)
}

func clientUsage(w io.Writer) {
	fprintf(w, "innsegl client - the enrolled machine's local endpoint (#461)\n\n"+
		"Usage:\n  innsegl client serve [--listen 127.0.0.1:28195]\n\n"+
		"Forwards the harness's, the hooks' and git's requests to the core over this\n"+
		"machine's client certificate, renewing it at half-life. GET /_client/status\n"+
		"reports the installation, the certificate's expiry and whether the core answers.\n")
}

func runClientCommand(ctx context.Context, args []string, stdout, stderr io.Writer, home string) int {
	if len(args) == 0 {
		clientUsage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "-h", "--help", "help":
		clientUsage(stderr)
		return exitOK
	case "serve":
		return runClientServe(ctx, args[1:], stdout, stderr, home)
	}
	fprintf(stderr, "innsegl client: unknown step %q\n\n", args[0])
	clientUsage(stderr)
	return exitUsage
}

func runClientServe(ctx context.Context, args []string, _, stderr io.Writer, home string) int {
	fs := flag.NewFlagSet("innsegl client serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "", "loopback address to listen on (default: the one connect wrote into the managed settings)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 0 {
		fprintf(stderr, "innsegl client serve: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	if *listen != "" {
		if err := client.CheckLoopback(*listen); err != nil {
			fprintf(stderr, "innsegl client serve: %v\n", err)
			return exitUsage
		}
	}
	paths := client.ClientPaths(home)
	srv, err := client.NewServer(paths, stderr)
	if err != nil {
		fprintf(stderr, "innsegl client serve: %v\n", err)
		if errors.Is(err, client.ErrNotEnrolled) {
			fprintf(stderr, "innsegl client serve: enrol this machine with `innsegl connect <core-url> --token …` first\n")
		}
		return exitClientFailed
	}
	addr := *listen
	if addr == "" {
		addr = client.DefaultListen
		if cfg, cerr := client.ReadCoreConfig(paths); cerr == nil && cfg.Listen != "" {
			addr = cfg.Listen
		}
		if err = client.CheckLoopback(addr); err != nil {
			fprintf(stderr, "innsegl client serve: %v\n", err)
			return exitUsage
		}
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		fprintf(stderr, "innsegl client serve: %v\n", err)
		return exitClientFailed
	}
	server := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 30 * time.Second}
	renewCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go srv.RunRenewal(renewCtx)
	// ADR-0068: what the core could not record is uploaded when it answers.
	go srv.RunJournalUpload(renewCtx)
	go func() {
		<-ctx.Done()
		shutdown, done := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer done()
		if err := server.Shutdown(shutdown); err != nil {
			fprintf(stderr, "innsegl client serve: shutting down: %v\n", err)
		}
	}()
	fprintf(stderr, "innsegl client serve: listening on http://%s\n", addr)
	if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fprintf(stderr, "innsegl client serve: %v\n", err)
		return exitClientFailed
	}
	return exitOK
}
