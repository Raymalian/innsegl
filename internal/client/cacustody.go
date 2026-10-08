// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"filippo.io/age"

	"innsegl.dev/innsegl/internal/cacustody"
)

// ADR-0076: the operator's machine unlocks the core's CA key store. The core
// holds the unlock material as ciphertext to this machine's Secure Enclave
// key; after the store restarts sealed, this machine opens it (Touch ID) and
// sends it back over its own certificate.

// CAUnlockInterval is how often the client service asks whether the store
// is sealed. Asking costs one small request; nothing is opened unless it is.
const CAUnlockInterval = time.Minute

// CAUnlockBackoff is how long the service waits after a failed unlock before
// asking for Touch ID again, so a declined prompt is not repeated every minute.
const CAUnlockBackoff = 15 * time.Minute

// UnlockCA unlocks the core's CA key store if it is sealed. identities is
// called only then, and is what asks for Touch ID. It answers whether it sent
// an unlock that the core accepted. It does not need the client service.
func UnlockCA(ctx context.Context, paths Paths, identities func() ([]age.Identity, error)) (bool, error) {
	s, err := NewServer(paths, io.Discard)
	if err != nil {
		return false, err
	}
	return s.UnlockCA(ctx, identities)
}

// CAStatus answers the core's CA custody status. It does not need the client
// service.
func CAStatus(ctx context.Context, paths Paths) (cacustody.CoreStatus, error) {
	s, err := NewServer(paths, io.Discard)
	if err != nil {
		return cacustody.CoreStatus{}, err
	}
	return s.CAStatus(ctx)
}

// CAStatus asks the core whether its CA key store is sealed.
func (s *Server) CAStatus(ctx context.Context) (cacustody.CoreStatus, error) {
	var st cacustody.CoreStatus
	err := s.custodyCall(ctx, http.MethodGet, cacustody.CorePath, nil, func(b []byte) error {
		return json.Unmarshal(b, &st)
	})
	return st, err
}

// UnlockCA is UnlockCA through this service's connection.
func (s *Server) UnlockCA(ctx context.Context, identities func() ([]age.Identity, error)) (bool, error) {
	st, err := s.CAStatus(ctx)
	if err != nil {
		return false, err
	}
	if !st.Enabled || !st.Sealed {
		return false, nil
	}
	var sealed []byte
	if err = s.custodyCall(ctx, http.MethodGet, cacustody.CoreMaterialPath, nil, func(b []byte) error {
		sealed = b
		return nil
	}); err != nil {
		return false, err
	}
	ids, err := identities()
	if err != nil {
		return false, fmt.Errorf("ca custody: %w", err)
	}
	m, err := cacustody.Open(sealed, ids)
	if err != nil {
		return false, err
	}
	body, err := json.Marshal(m)
	if err != nil {
		return false, err
	}
	if err := s.custodyCall(ctx, http.MethodPost, cacustody.CoreUnlockPath, body, nil); err != nil {
		return false, err
	}
	return true, nil
}

// RunCAUnlock checks every interval and unlocks a sealed store. After a
// failure it waits backoff before trying again: a declined Touch ID prompt
// is the operator's answer, not something to ask again in a minute.
func (s *Server) RunCAUnlock(ctx context.Context, identities func() ([]age.Identity, error), every, backoff time.Duration) {
	last := ""
	for {
		wait := every
		unlocked, err := s.UnlockCA(ctx, identities)
		switch {
		case err != nil && !errors.Is(err, context.Canceled):
			if err.Error() != last {
				s.log.Printf("unlocking the CA: %v", err)
			}
			last = err.Error()
			wait = backoff
		case unlocked:
			last = ""
			s.log.Printf("ca custody: unlocked the CA key store")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// custodyCall sends one request to the core; a 2xx body goes to read. Any
// other status is an error carrying the core's own message.
func (s *Server) custodyCall(ctx context.Context, method, path string, body []byte, read func([]byte) error) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	var reader io.Reader = http.NoBody
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(s.core.CoreURL, "/")+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.transport.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("ca custody: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("ca custody: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(payload, &e) != nil || e.Error == "" {
			e.Error = http.StatusText(resp.StatusCode)
		}
		return fmt.Errorf("ca custody: the core answered %d: %s", resp.StatusCode, e.Error)
	}
	if read == nil {
		return nil
	}
	return read(payload)
}
