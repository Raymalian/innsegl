// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"innsegl.dev/innsegl/internal/cacustody"
	"innsegl.dev/innsegl/internal/trustbackup"
)

// `innsegl ca-custodian` (ADR-0076) runs on the core, beside the CA key store:
//
//	init    initialise a store that never has been, once
//	serve   initialise it if it is new, then renew the CA's token and serve
//	        the core: the store's status, the sealed unlock material, and the
//	        unlock the operator's machine sends back
//	ready   the container's health: the CA can sign (Status.CanSign), which
//	        is what Fulcio's bootstrap waits for
//	restore put a backup's store snapshot into a new store, sealed under the
//	        original keys, for the operator's machine to unlock
const (
	envCAStoreAddr  = "INNSEGL_CA_STORE_ADDR"
	envCARecipients = "INNSEGL_CA_CUSTODY_RECIPIENTS"
	envCADir        = "INNSEGL_CA_CUSTODY_DIR"
	envCATokenPath  = "INNSEGL_CA_TOKEN_PATH" //nolint:gosec // G101: a variable's name, not its value
	envCAStoreKey   = "INNSEGL_CA_STORE_KEY"
	envCAListen     = "INNSEGL_CA_CUSTODIAN_LISTEN"
	envCAChainPath  = "INNSEGL_CA_CHAIN_PATH"
	// envCASignListen is where the CA's signing gateway listens (#585).
	// Unset, there is no gateway. The overlay names the custodian's alias on
	// the network it shares with the CA alone, so the listener is bound to
	// that network and the core, on the unlock network, cannot reach it.
	envCASignListen = "INNSEGL_CA_SIGN_LISTEN"
)

// exitCACustodyFailed: the custodian could not start, or init failed.
const exitCACustodyFailed = 27

const caCustodianUsage = `Usage:
  innsegl ca-custodian init     initialise a new CA key store, once
  innsegl ca-custodian serve    initialise it if new; renew the CA's token; serve the core
  innsegl ca-custodian ready    exit 0 when the CA can sign: store unlocked, token alive, key readable and matching the chain
  innsegl ca-custodian restore SNAPSHOT
                                put a backup's store into a new store (runbooks/ca-custody.md)

From the environment: ` + envCAStoreAddr + `, ` + envCARecipients + `,
` + envCADir + `, ` + envCATokenPath + `, ` + envCAStoreKey + ` (default innsegl-ca),
` + envCAListen + ` (serve; default :8210), ` + envCAChainPath + ` (the CA's chain.pem; unset skips the key match),
` + envCASignListen + ` (serve; the CA's signing gateway, which forwards only its sign and key-read
calls, with the current token; unset, no gateway).
`

func caCustodianCommand(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runCACustodian(ctx, args, stdout, stderr, os.Getenv)
}

func runCACustodian(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		fprintf(stderr, "%s", caCustodianUsage)
		return exitOK
	}
	if len(args) == 0 || (args[0] != "init" && args[0] != "serve" && args[0] != "ready" && args[0] != "restore") {
		fprintf(stderr, "innsegl ca-custodian: name a verb: init, serve, ready or restore\n\n%s", caCustodianUsage)
		return exitUsage
	}
	if args[0] == "restore" && len(args) != 2 {
		fprintf(stderr, "innsegl ca-custodian: restore takes the snapshot file, from a backup's ca-store item\n\n%s", caCustodianUsage)
		return exitUsage
	}
	c, err := custodianFromEnv(getenv, stdout)
	if err != nil {
		fprintf(stderr, "innsegl ca-custodian: %v\n", err)
		return exitCACustodyFailed
	}
	if args[0] == "ready" {
		st := c.Status(ctx)
		switch {
		case st.Error != "":
			fprintf(stderr, "innsegl ca-custodian: not ready: %s\n", st.Error)
		case !st.Initialized:
			fprintf(stderr, "innsegl ca-custodian: not ready: the store is not initialised\n")
		case st.Sealed:
			fprintf(stderr, "innsegl ca-custodian: not ready: the store is sealed; the operator's machine unlocks it\n")
		case !st.CanSign:
			fprintf(stderr, "innsegl ca-custodian: not ready: %s\n", st.Reason)
		default:
			return exitOK
		}
		return exitCACustodyFailed
	}
	if args[0] == "restore" {
		f, err := os.Open(args[1]) //nolint:gosec // G304: the operator names the snapshot to restore
		if err != nil {
			fprintf(stderr, "innsegl ca-custodian: %v\n", err)
			return exitCACustodyFailed
		}
		defer func() { _ = f.Close() }()
		if err := c.Store.Restore(ctx, f); err != nil {
			fprintf(stderr, "innsegl ca-custodian: %v\n", err)
			return exitCACustodyFailed
		}
		fprintf(stdout, "innsegl ca-custodian: restored; the store is sealed under the original keys. "+
			"Unlock it from the operator's machine: innsegl ca-custody unlock\n")
		return exitOK
	}
	if args[0] == "init" {
		if err := c.Init(ctx); err != nil {
			fprintf(stderr, "innsegl ca-custodian: %v\n", err)
			return exitCACustodyFailed
		}
		return exitOK
	}
	return serveCACustodian(ctx, c, envOrDefault(getenv, envCAListen, ":8210"), getenv(envCASignListen), stderr)
}

func custodianFromEnv(getenv func(string) string, log io.Writer) (*cacustody.Custodian, error) {
	addr := getenv(envCAStoreAddr)
	if addr == "" {
		return nil, fmt.Errorf("%s is unset: the CA key store's address", envCAStoreAddr)
	}
	recipients, err := trustbackup.ParseRecipients(getenv(envCARecipients))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envCARecipients, err)
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("%s is unset: nobody could open the store's unlock material", envCARecipients)
	}
	dir := getenv(envCADir)
	if dir == "" {
		return nil, fmt.Errorf("%s is unset: where the sealed unlock material is kept", envCADir)
	}
	tokenPath := getenv(envCATokenPath)
	if tokenPath == "" {
		return nil, fmt.Errorf("%s is unset: where the CA reads its token", envCATokenPath)
	}
	return &cacustody.Custodian{
		Store:      &cacustody.Store{Addr: addr},
		Dir:        dir,
		TokenPath:  tokenPath,
		Key:        envOrDefault(getenv, envCAStoreKey, "innsegl-ca"),
		ChainPath:  getenv(envCAChainPath),
		Recipients: recipients,
		Log:        log,
	}, nil
}

func serveCACustodian(ctx context.Context, c *cacustody.Custodian, listen, signListen string, stderr io.Writer) int {
	st, err := c.Store.SealStatus(ctx)
	if err != nil {
		fprintf(stderr, "innsegl ca-custodian: %v\n", err)
		return exitCACustodyFailed
	}
	if !st.Initialized {
		if err = c.Init(ctx); err != nil {
			fprintf(stderr, "innsegl ca-custodian: %v\n", err)
			return exitCACustodyFailed
		}
	}
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", listen)
	if err != nil {
		fprintf(stderr, "innsegl ca-custodian: listening on %s: %v\n", listen, err)
		return exitCACustodyFailed
	}
	srv := &http.Server{Handler: c.Handler(), ReadHeaderTimeout: 10 * time.Second}
	servers := []*http.Server{srv}
	if signListen != "" {
		sl, err := lc.Listen(ctx, "tcp", signListen)
		if err != nil {
			discardListenerError(l.Close())
			fprintf(stderr, "innsegl ca-custodian: the CA's signing gateway on %s: %v\n", signListen, err)
			return exitCACustodyFailed
		}
		gw := &http.Server{Handler: c.SigningGateway(), ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, gw)
		go func() {
			// A gateway that stops serving stops the custodian, so the
			// container restarts rather than run with the CA cut off.
			if err := gw.Serve(sl); err != nil && !errors.Is(err, http.ErrServerClosed) {
				fprintf(stderr, "innsegl ca-custodian: the CA's signing gateway: %v\n", err)
				discardListenerError(srv.Close())
			}
		}()
	}
	go c.RunRenewer(ctx, cacustody.RenewEvery)
	go c.RunSnapshots(ctx, cacustody.SnapshotEvery)
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		for _, s := range servers {
			discardListenerError(s.Shutdown(shut))
		}
	}()
	if s := c.Status(ctx); s.Sealed {
		fprintf(stderr, "innsegl ca-custodian: the store is sealed: the CA cannot sign until the operator's machine unlocks it\n")
	}
	if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fprintf(stderr, "innsegl ca-custodian: %v\n", err)
		return exitCACustodyFailed
	}
	return exitOK
}

func envOrDefault(getenv func(string) string, name, fallback string) string {
	if v := getenv(name); v != "" {
		return v
	}
	return fallback
}
