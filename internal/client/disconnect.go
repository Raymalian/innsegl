// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DisconnectPath is where a machine revokes its own installation on the
// core, over its own certificate (#490).
const DisconnectPath = "/_core/disconnect"

// RevokeInstallation revokes this machine's installation on the core, so
// its certificate is refused from then on. `innsegl connect --disconnect`
// calls it before it deletes the key; without it, a disconnected machine
// stayed able to record until a member revoked it on the core.
func RevokeInstallation(ctx context.Context, paths Paths) error {
	s, err := NewServer(paths, io.Discard)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(s.core.CoreURL, "/")+DisconnectPath, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := s.transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if _, err = io.Copy(io.Discard, resp.Body); err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("the core answered %d", resp.StatusCode)
	}
	return nil
}

// CoreStatusPath is where the core answers an enrolled machine its status
// (#472).
const CoreStatusPath = "/_core/status"

// FetchCoreStatus asks the core, over this machine's own certificate, for
// its status: the body as the core sent it. It does not need the client
// service to be running.
func FetchCoreStatus(ctx context.Context, paths Paths) ([]byte, error) {
	s, err := NewServer(paths, io.Discard)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimSuffix(s.core.CoreURL, "/")+CoreStatusPath, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := s.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the core answered %d", resp.StatusCode)
	}
	return body, nil
}
