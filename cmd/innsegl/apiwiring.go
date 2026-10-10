// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/api"
	"innsegl.dev/innsegl/internal/mirror"
)

// The wiring for `innsegl api`: a read-only store, a proof BFF, the five
// routes, and a listener.
//
// Four constructions, in the only order they can go in, and every one of them
// belongs to `internal/api`. There is no decision left in this file except
// which errors are fatal — which is all of them — and what to do on the way
// out, which is to release what was opened in reverse.
//
// # The store is opened FIRST, and that is load-bearing
//
// `api.Open` is where the credential is probed, so opening it first means a
// deployment handed a writing credential never reaches the point of binding a
// port. A process that bound 8082, then discovered its credential could write,
// and then exited would have been reachable — briefly, and by whatever is in
// front of it — as a query API nobody had cleared. Nothing here serves a
// request before the refusal has had its chance to fire.
//
// # The prover holds no store, and cannot be given one
//
// `api.ProofConfig` has no database field: IP §6.11 and doc 06 P2 forbid a
// verdict read out of the ledger, and `internal/api` makes that structural
// rather than conventional. This file does not work around it.

// apiBootTimeout bounds construction. A replica that hangs at start-up is
// worse than one that exits: an orchestrator can restart the second.
const apiBootTimeout = 60 * time.Second

// apiReadHeaderTimeout bounds how long a client may take to send its request
// headers. A public surface with no bound is a slowloris away from holding
// every connection it has.
const apiReadHeaderTimeout = 10 * time.Second

// runningAPI is the shipped servedAPI.
type runningAPI struct {
	server *http.Server
	ln     net.Listener
	// tlsLn is the dashboard's HTTPS listener (#475); nil without
	// -tls-listen.
	tlsLn net.Listener

	readOnly api.ReadOnlyReport
	repos    []string

	shutdownTimeout time.Duration
	closers         []func()
	log             *serveLog
}

func (a *runningAPI) Addr() string { return a.ln.Addr().String() }

// TLSAddr is the bound HTTPS address, or empty when there is none.
func (a *runningAPI) TLSAddr() string {
	if a.tlsLn == nil {
		return ""
	}
	return a.tlsLn.Addr().String()
}
func (a *runningAPI) ReadOnly() api.ReadOnlyReport { return a.readOnly }
func (a *runningAPI) Repos() []string              { return a.repos }

// Serve runs the listener until ctx is done or it fails, then stops it in an
// orderly way.
func (a *runningAPI) Serve(ctx context.Context) error {
	// One server, one handler, two listeners: Shutdown stops both.
	listeners := []net.Listener{a.ln}
	if a.tlsLn != nil {
		listeners = append(listeners, tls.NewListener(a.tlsLn, a.server.TLSConfig))
	}
	failed := make(chan error, len(listeners))
	for _, ln := range listeners {
		go func() {
			err := a.server.Serve(ln)
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			failed <- err
		}()
	}

	var first error
	select {
	case <-ctx.Done():
	case first = <-failed:
	}

	// The orderly stop. Shutdown stops accepting and waits for the requests
	// already in flight; the bound is what keeps a replica from refusing to
	// leave. context.WithoutCancel, as `serve`'s does, because ctx is the
	// signal context and is already cancelled by the time we get here on the
	// ordinary path — a Shutdown handed a cancelled context severs live
	// connections instead of draining them.
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.shutdownTimeout)
	defer cancel()
	if err := a.server.Shutdown(stopCtx); err != nil && first == nil {
		a.log.warn("the query API did not drain before the shutdown bound", "err", err)
	}
	return first
}

// Close releases everything openAPI opened, in reverse.
func (a *runningAPI) Close() {
	for i := len(a.closers) - 1; i >= 0; i-- {
		a.closers[i]()
	}
}

// openAPI builds the query API, or returns the first thing that stopped it.
// Anything already opened is released before returning.
func openAPI(ctx context.Context, o apiOptions, log *serveLog) (servedAPI, error) {
	boot, cancel := context.WithTimeout(ctx, apiBootTimeout)
	defer cancel()

	var closers []func()
	unwind := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}

	// ---- the credential, and the refusal ----------------------------------
	//
	// api.Open asks the server what this credential may do and returns an
	// error wrapping api.ErrWritable if the answer is "write". runAPI turns
	// that into its own exit status; nothing here softens it.
	store, err := api.Open(boot, o.dsn)
	if err != nil {
		unwind()
		return nil, err
	}
	closers = append(closers, store.Close)

	// ---- the auth-writer credential, and the SAME refusal ------------------
	//
	// RM-260/RM-261 (ADR-0062): a SEPARATE credential and a separate pool,
	// which AssertCannotWriteLedger (reusing AssertReadOnly's own probes)
	// proves cannot write anything in the ledger schema at every open, the
	// same discipline api.Open above holds the reader to. An error here
	// wraps api.ErrWritable exactly the same way, so reportAPIStartFailure
	// needs no second branch.
	authStore, err := api.OpenAuthStore(boot, o.authDSN)
	if err != nil {
		unwind()
		return nil, err
	}
	closers = append(closers, authStore.Close)

	// ---- the accounts spine (RM-333) ---------------------------------------
	//
	// The account page's organisations, machines and repositories, and the
	// passkey-gated mint and revoke. The SAME auth-writer credential as
	// above, in a pool of its own: accounts.Open runs the same refusal, so
	// nothing here widens what this process may write.
	orgs, err := accounts.Open(boot, o.authDSN)
	if err != nil {
		unwind()
		return nil, err
	}
	closers = append(closers, orgs.Close)
	// A deployment whose users predate the operator organisation gets it now,
	// owned by its first user (accounts.FoundOperator). Not fatal: the
	// account page says what is missing.
	if _, ferr := orgs.FoundOperator(boot); ferr != nil {
		log.warn("founding the operator organisation failed", "err", ferr)
	}

	// ---- the resolver credential, optional (RM-330) -------------------------
	//
	// ADR-0044's 2026-10-03 amendment: a THIRD credential, which may insert
	// an alert resolution and nothing else. api.OpenResolver proves that at
	// every open and refuses anything wider, wrapping api.ErrWritable the
	// same way the two above do. Absent, the dashboard cannot resolve alerts.
	var resolver *api.Resolver
	if o.resolverDSN != "" {
		resolver, err = api.OpenResolver(boot, o.resolverDSN)
		if err != nil {
			unwind()
			return nil, err
		}
		closers = append(closers, resolver.Close)
	}

	// ---- the proof BFF ----------------------------------------------------
	//
	// Repositories come from the core's mirror and nowhere else (ADR-0065
	// decision 1). Opened, never created: this process reads what clients
	// pushed, from a read-only mount, and holds nothing that could add to it.
	repos, err := mirror.Open(o.mirrorDir)
	if err != nil {
		unwind()
		return nil, fmt.Errorf("open the repository mirror (-mirror-dir): %w", err)
	}
	prover, err := api.NewProver(api.ProofConfig{
		FulcioURL: o.fulcioURL,
		RekorURL:  o.rekorURL,
		Issuer:    o.issuer,
		GitPath:   o.gitPath,
		Repos:     repos,
		HTTPClient: &http.Client{
			Timeout: o.upstreamTimeout,
		},
		TrustHistoryFile: o.trustHistory,
	})
	if err != nil {
		unwind()
		return nil, fmt.Errorf("configure the proof BFF: %w", err)
	}

	// ---- the run page's own routes (E19, #395-#397) ------------------------
	//
	// Installed BEFORE NewServer, which is what makes the ordering safe
	// regardless of what NewServer itself does with it: api.Server holds no
	// field for either setting (server.go is not this issue's file to add
	// one to), so they travel through this package-level Configure/restore
	// pair instead — the same seam internal/mcp already uses for
	// observe_tool_call and the agent-message recorder. Whatever calls
	// Server.registerRecordRoutes (server.go, another issue's own edit)
	// reads this state at that point, not before.
	restoreRecordConfig := api.ConfigureRecordRoutes(api.RecordConfig{
		SnapshotDir:   o.snapshotDir,
		GitPath:       o.gitPath,
		MessageKeyDir: o.messageKeyDir,
	})
	closers = append(closers, restoreRecordConfig)

	// ---- the routes -------------------------------------------------------
	handler, err := api.NewServer(api.ServerConfig{
		Store: store, Prover: prover,
		LogDir: o.logDir, LogRetentionDays: o.logDays,
		AuthStore: authStore,
		WebAuthn: api.WebAuthnConfig{
			RPID: o.rpID, RPOrigin: o.rpOrigin, RPDisplayName: "Innsegl",
		},
		SessionLifetime:   o.sessionLifetime,
		Resolver:          resolver,
		Organisations:     orgs,
		CoreCACertFile:    o.gatewayCACert,
		UnownedRunsHidden: o.hideUnownedRuns,
	})
	if err != nil {
		unwind()
		return nil, fmt.Errorf("wire the query API routes: %w", err)
	}

	// ---- the listeners ----------------------------------------------------
	running, err := bindAPI(boot, o, handler, log)
	if err != nil {
		unwind()
		return nil, err
	}
	running.readOnly = store.ReadOnly()
	running.repos = prover.Repos()
	running.closers = append(closers, running.closers...)
	return running, nil
}

// bindAPI wraps the query API in the dashboard (#475) — the UI from
// -ui-dir and the security headers — and binds the plain listener and,
// with -tls-listen, the dashboard's HTTPS one. Both serve the same
// handler. Nothing is served until Serve.
func bindAPI(ctx context.Context, o apiOptions, apiHandler http.Handler, log *serveLog) (*runningAPI, error) {
	handler, err := api.DashboardHandler(apiHandler, o.uiDir)
	if err != nil {
		return nil, fmt.Errorf("serve the dashboard UI (-ui-dir): %w", err)
	}
	a := &runningAPI{
		server: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: apiReadHeaderTimeout,
		},
		shutdownTimeout: o.shutdownTimeout,
		log:             log,
	}
	var lc net.ListenConfig
	if a.ln, err = lc.Listen(ctx, "tcp", o.listen); err != nil {
		return nil, fmt.Errorf("listen on %s: %w", o.listen, err)
	}
	a.closers = append(a.closers, func() { discardListenerError(a.ln.Close()) })
	if o.tlsListen == "" {
		return a, nil
	}
	if a.tlsLn, err = lc.Listen(ctx, "tcp", o.tlsListen); err != nil {
		a.Close()
		return nil, fmt.Errorf("listen on %s (-tls-listen): %w", o.tlsListen, err)
	}
	a.closers = append(a.closers, func() { discardListenerError(a.tlsLn.Close()) })
	a.server.TLSConfig = api.DashboardTLSConfig(o.tlsCert)
	if _, serr := os.Stat(o.tlsCert); serr != nil {
		// Not fatal: the core writes it, and may not have yet.
		log.warn("the dashboard's certificate is not there yet; HTTPS handshakes fail until "+
			"the core writes it", "tls_cert", o.tlsCert, "err", serr)
	}
	log.info("serving the dashboard over HTTPS", "addr", a.TLSAddr(), "tls_cert", o.tlsCert,
		"ui_dir", o.uiDir)
	return a, nil
}

// discardListenerError swallows the error from closing a listener the HTTP
// server has usually already closed. errcheck runs with check-blank, so the
// discard is a named function rather than a blank assignment: a discard should
// be visible and explained.
func discardListenerError(error) {}
