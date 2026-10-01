// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/gateway"
	"innsegl.dev/innsegl/internal/mcp"
)

// The host half of ADR-0059's commit path, as the harness and git invoke it:
//
//	innsegl hook pre-tool-use                     the harness's PreToolUse hook
//	innsegl git-hook prepare-commit-msg <file>…   git's prepare-commit-msg hook
//	innsegl sign <git's signing arguments>        git's gpg.x509.program
//
// Each is a client of the core at $INNSEGL_CORE_URL. These adapters only
// supply the process's own stdin and environment; the behaviour is in
// hook.go, githook.go and sign.go.

// isHelp reports whether args asks only for the usage line.
func isHelp(args []string) bool {
	return len(args) == 1 && (args[0] == "-h" || args[0] == "--help")
}

const (
	hookUsage    = "usage: innsegl hook pre-tool-use | session\n"
	gitHookUsage = "usage: innsegl git-hook prepare-commit-msg <message file> [<source> [<sha>]]\n"
	signUsage    = "usage: innsegl sign --status-fd=<fd> -bsau <key>   (run by git as gpg.x509.program)\n"
)

func hookCommand(args []string, stdout, stderr io.Writer) int {
	if isHelp(args) {
		fprintf(stdout, hookUsage)
		return exitOK
	}
	if len(args) == 1 && args[0] == "session" {
		return runHookSession(os.Stdin, stdout, stderr, os.Getenv, postToGateway(os.Getenv))
	}
	if len(args) != 1 || args[0] != "pre-tool-use" {
		fprintf(stderr, hookUsage)
		return exitUsage
	}
	return runHookPreToolUse(os.Stdin, stdout, stderr)
}

func gitHookCommand(args []string, stdout, stderr io.Writer) int {
	if isHelp(args) {
		fprintf(stdout, gitHookUsage)
		return exitOK
	}
	if len(args) < 2 || args[0] != "prepare-commit-msg" {
		fprintf(stderr, gitHookUsage)
		return exitUsage
	}
	return runGitHookPrepareCommitMsg(context.Background(), args[1:], os.Getenv, stderr, commitpath.ClientFromEnv(os.Getenv))
}

func signCommand(args []string, stdout, stderr io.Writer) int {
	if isHelp(args) {
		fprintf(stdout, signUsage)
		return exitOK
	}
	return runSign(context.Background(), args, os.Stdin, stdout, stderr, os.Getenv, commitpath.ClientFromEnv(os.Getenv))
}

// mountCommitPath serves the core's half of the commit path on the gateway's
// own listener: the trailers prepare-commit-msg asks for, and the signature
// git's signing program asks for. Both resolve the tool call id against the
// traffic this gateway relayed, so a gateway with no resolver (no identity
// stack) serves neither, and the paths fall through to the proxy's refusal.
// The signing endpoint's own resolver is the one ConfigureSignPayload holds.
func mountCommitPath(mux *http.ServeMux, resolver commitpath.Resolver) {
	if resolver == nil {
		return
	}
	mux.Handle(commitpath.TrailersPath, scopeCommitPath(resolver,
		commitTrailersHandler(resolver, mcp.CommitClaimForRun, time.Now)))
	mux.Handle(commitpath.SignPath, scopeCommitPath(resolver, commitSignHandler(mcp.SignPayloadForGateway)))
}

// scopeCommitPath scopes a commit-path request to the installation the
// client guard verified (hosted shape, ADR-0063): the request then resolves
// only tool calls that installation relayed (#489). With no installation on
// the request (single-host), it passes through unchanged.
func scopeCommitPath(resolver commitpath.Resolver, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if installation, ok := gateway.InstallationFromContext(r.Context()); ok && installation != "" {
			r = r.WithContext(commitpath.WithResolver(r.Context(), commitpath.ScopedResolver(resolver, installation)))
		}
		next.ServeHTTP(w, r)
	})
}

// mountTelemetry serves the harness's OTLP telemetry receiver (the second
// witness, #392) on the gateway's listener, keeping each tool result in the
// body store the gateway already records into. No body store, no receiver:
// there would be nowhere to keep what it hears.
func mountTelemetry(mux *http.ServeMux, bodyDir string) {
	if bodyDir == "" {
		return
	}
	mux.Handle(gateway.TelemetryLogsPath, gateway.TelemetryHandler(gateway.TelemetryConfig{Dir: bodyDir}))
}
