// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"innsegl.dev/innsegl/internal/api"
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

	readOnly api.ReadOnlyReport
	repos    []string

	shutdownTimeout time.Duration
	closers         []func()
	log             *serveLog
}

func (a *runningAPI) Addr() string                 { return a.ln.Addr().String() }
func (a *runningAPI) ReadOnly() api.ReadOnlyReport { return a.readOnly }
func (a *runningAPI) Repos() []string              { return a.repos }

// Serve runs the listener until ctx is done or it fails, then stops it in an
// orderly way.
func (a *runningAPI) Serve(ctx context.Context) error {
	failed := make(chan error, 1)
	go func() {
		err := a.server.Serve(a.ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		failed <- err
	}()

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

	// ---- the proof BFF ----------------------------------------------------
	prover, err := api.NewProver(api.ProofConfig{
		FulcioURL: o.fulcioURL,
		RekorURL:  o.rekorURL,
		Issuer:    o.issuer,
		GitPath:   o.gitPath,
		Repos:     o.repos,
		HTTPClient: &http.Client{
			Timeout: o.upstreamTimeout,
		},
	})
	if err != nil {
		unwind()
		return nil, fmt.Errorf("configure the proof BFF: %w", err)
	}

	// ---- the routes -------------------------------------------------------
	handler, err := api.NewServer(api.ServerConfig{Store: store, Prover: prover})
	if err != nil {
		unwind()
		return nil, fmt.Errorf("wire the query API routes: %w", err)
	}

	// ---- the listener -----------------------------------------------------
	var lc net.ListenConfig
	ln, err := lc.Listen(boot, "tcp", o.listen)
	if err != nil {
		unwind()
		return nil, fmt.Errorf("listen on %s: %w", o.listen, err)
	}
	closers = append(closers, func() { discardListenerError(ln.Close()) })

	return &runningAPI{
		server: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: apiReadHeaderTimeout,
		},
		ln:              ln,
		readOnly:        store.ReadOnly(),
		repos:           sortedRepoNames(o.repos),
		shutdownTimeout: o.shutdownTimeout,
		closers:         closers,
		log:             log,
	}, nil
}

// discardListenerError swallows the error from closing a listener the HTTP
// server has usually already closed. errcheck runs with check-blank, so the
// discard is a named function rather than a blank assignment: a discard should
// be visible and explained.
func discardListenerError(error) {}
