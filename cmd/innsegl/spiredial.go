// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"innsegl.dev/innsegl/internal/spire"
)

// dialSPIREAdmin is the one way this binary reaches SPIRE's admin API: fetch
// this process's own SVID from the Workload API, then dial the admin gRPC
// endpoint with it.
//
// `innsegl reap` (openReaper, reap.go) needed exactly this first, for the
// same reason IP §1 and doc 05 §1 give: the admin credential is not a file,
// it is being the workload SPIRE attests as the identity server.conf's
// `admin_ids` names — so a caller fetches its own SVID through the Workload
// API like any other workload, and a process that cannot attest gets no
// credential and reaches nothing.
//
// #153/RM-096 pulled this out from under `reap` rather than writing a second,
// slightly different copy for `reconcile`'s identity pass: two ways to dial
// SPIRE from two subcommands is the exact divergence this project keeps
// filing issues about. `who` names the caller in every error this returns, so
// an operator reading one message can still tell which subcommand produced
// it.
func dialSPIREAdmin(
	ctx context.Context, who, address, trustDomain, serverID, workloadAPI string, timeout time.Duration,
) (*spire.Client, func(), error) {
	source, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(workloadAPI)))
	if err != nil {
		return nil, nil, fmt.Errorf(
			"no SVID from the Workload API at %s: %s is an attested workload "+
				"and without an identity it holds no SPIRE admin: %w", workloadAPI, who, err)
	}
	closers := []func(){func() { _ = source.Close() }}
	unwind := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}

	client, err := spire.Dial(ctx, spire.Config{
		Address:     address,
		TrustDomain: trustDomain,
		ServerID:    serverID,
		Source:      source,
		Timeout:     timeout,
	})
	if err != nil {
		unwind()
		return nil, nil, fmt.Errorf("dial the SPIRE admin API at %s: %w", address, err)
	}
	closers = append(closers, func() { _ = client.Close() })

	return client, unwind, nil
}
