// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/gateway"
	"innsegl.dev/innsegl/internal/version"
)

// coreStatusPath answers an enrolled machine, over its own certificate,
// what is up on the core and what the machine may do (#472, `innsegl
// status`).
const coreStatusPath = "/_core/status"

// coreStatus is the answer of GET /_core/status.
type coreStatus struct {
	Version      string           `json:"version"`
	Components   []coreComponent  `json:"components"`
	Installation coreInstallation `json:"installation"`
}

// coreComponent is one part of the core and whether it is up.
type coreComponent struct {
	Name   string `json:"name"`
	Up     bool   `json:"up"`
	Detail string `json:"detail,omitempty"`
}

// coreInstallation is the asking machine's installation: its scope.
type coreInstallation struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	Status       string   `json:"status"`
	Organisation string   `json:"organisation"`
	Repos        []string `json:"repos"`
}

// statusStore reads what the status answer names about an installation.
type statusStore interface {
	GetInstallation(ctx context.Context, id string) (accounts.Installation, error)
	ListAccounts(ctx context.Context) ([]accounts.AccountSummary, error)
}

func statusHandler(store statusStore, log *serveLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeCoreError(w, http.StatusMethodNotAllowed, "innsegl core: status: only GET is accepted")
			return
		}
		id, ok := gateway.InstallationFromContext(r.Context())
		if !ok {
			gateway.WriteClientRefusal(w)
			return
		}
		inst, err := store.GetInstallation(r.Context(), id)
		if errors.Is(err, accounts.ErrNotFound) {
			gateway.WriteClientRefusal(w)
			return
		}
		if err != nil {
			log.warn("status: reading the installation", "installation_id", id, "err", err)
			writeCoreError(w, http.StatusServiceUnavailable, "innsegl core: status is unavailable; retry")
			return
		}
		out := coreStatus{
			Version:    version.String(),
			Components: coreReadiness(r.Context()),
			Installation: coreInstallation{ID: inst.ID, Name: inst.Name, Kind: inst.Kind,
				Status: inst.Status, Organisation: inst.AccountID, Repos: inst.Repos},
		}
		if out.Installation.Repos == nil {
			out.Installation.Repos = []string{}
		}
		if list, lerr := store.ListAccounts(r.Context()); lerr == nil {
			for _, a := range list {
				if a.ID == inst.AccountID {
					out.Installation.Organisation = a.Name
				}
			}
		}
		writeCoreJSON(w, http.StatusOK, out)
	}
}

// coreReadiness reads the core's own readiness checks (internal/mcp's
// /readyz: ledger, SPIRE, Sigstore) from its health listener in this same
// process. When they cannot be read, that is itself the answer.
func coreReadiness(ctx context.Context) []coreComponent {
	unknown := []coreComponent{{Name: "core checks", Up: false, Detail: "the core's readiness could not be read"}}
	host, port, err := net.SplitHostPort(os.Getenv(envMCPHealthListen))
	if err != nil {
		return unknown
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// The address is the deployment's own health listener, from its own
	// environment; nothing a caller sends reaches it.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(host, port)+"/readyz", http.NoBody) //nolint:gosec // G704: see above
	if err != nil {
		return unknown
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: the deployment's own health listener
	if err != nil {
		return unknown
	}
	defer func() { _ = resp.Body.Close() }()
	var ready struct {
		Dependencies []struct {
			Dependency string `json:"dependency"`
			Reachable  bool   `json:"reachable"`
		} `json:"dependencies"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ready); err != nil || len(ready.Dependencies) == 0 {
		return unknown
	}
	out := make([]coreComponent, 0, len(ready.Dependencies))
	for _, d := range ready.Dependencies {
		out = append(out, coreComponent{Name: d.Dependency, Up: d.Reachable})
	}
	return out
}
