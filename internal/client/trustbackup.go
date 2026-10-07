// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/trustbackup"
)

// ADR-0074: the operator's machine keeps copies of the core's encrypted
// trust-key backup, fetched over its own certificate. A lost host then loses
// nothing that cannot be restored.

// TrustBackupKeep is how many fetched bundles the machine keeps.
const TrustBackupKeep = 30

// TrustBackupInterval is how often the client service asks. The core writes
// one bundle a day, so an hour finds each one the same hour.
const TrustBackupInterval = time.Hour

// FetchTrustBackup asks the core for its newest bundle over this machine's
// certificate and keeps it in store, unless store already holds it. It does
// not need the client service to be running.
func FetchTrustBackup(ctx context.Context, paths Paths, store *trustbackup.Store) (trustbackup.Entry, bool, error) {
	s, err := NewServer(paths, io.Discard)
	if err != nil {
		return trustbackup.Entry{}, false, err
	}
	return s.FetchTrustBackup(ctx, store)
}

// FetchTrustBackup is FetchTrustBackup through this service's connection. It
// answers the newest bundle store holds and whether it was downloaded now.
func (s *Server) FetchTrustBackup(ctx context.Context, store *trustbackup.Store) (trustbackup.Entry, bool, error) {
	var listing trustbackup.Listing
	if err := s.coreGet(ctx, trustbackup.CorePath, 30*time.Second, func(resp *http.Response) error {
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&listing)
	}); err != nil {
		return trustbackup.Entry{}, false, err
	}
	if len(listing.Bundles) > 0 {
		newest := listing.Bundles[0]
		if kept, err := store.List(); err == nil {
			for _, k := range kept {
				if k.Name == newest.Name && k.SHA256 == newest.SHA256 {
					return k, false, nil
				}
			}
		}
	}
	var got trustbackup.Entry
	err := s.coreGet(ctx, trustbackup.CoreLatestPath, 10*time.Minute, func(resp *http.Response) error {
		var perr error
		got, perr = store.Put(resp.Header.Get(trustbackup.HeaderName), resp.Body, resp.Header.Get(trustbackup.HeaderSHA256))
		return perr
	})
	if err != nil {
		return trustbackup.Entry{}, false, err
	}
	return got, true, nil
}

// coreGet sends one GET to the core and hands a 200 to read. Any other
// status is an error carrying the core's own message.
func (s *Server) coreGet(ctx context.Context, path string, timeout time.Duration, read func(*http.Response) error) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(s.core.CoreURL, "/")+path, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := s.transport.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("trust backup: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		var body struct {
			Error string `json:"error"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body) != nil || body.Error == "" {
			body.Error = http.StatusText(resp.StatusCode)
		}
		return fmt.Errorf("trust backup: the core answered %d: %s", resp.StatusCode, body.Error)
	}
	if err := read(resp); err != nil {
		return fmt.Errorf("trust backup: %w", err)
	}
	return nil
}

// RunTrustBackupFetch fetches at once and then every interval until ctx
// ends. A failure is tried again next time and logged when it differs from
// the last one, so a machine the core does not serve says so once rather
// than every hour: `innsegl status` says when the newest copy has grown old.
func (s *Server) RunTrustBackupFetch(ctx context.Context, store *trustbackup.Store, every time.Duration) {
	last := ""
	for {
		e, fetched, err := s.FetchTrustBackup(ctx, store)
		switch {
		case err != nil && !errors.Is(err, context.Canceled):
			if err.Error() != last {
				s.log.Printf("fetching the trust backup: %v", err)
			}
			last = err.Error()
		case fetched:
			last = ""
			s.log.Printf("trust backup: kept %s", e.Name)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}
