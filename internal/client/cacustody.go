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

// coreConn is one way to the core: the service's own certificate, or the
// CLI's way through the service (corepass.go).
type coreConn struct {
	rt   http.RoundTripper
	base string
}

// conn is this service's own connection to the core.
func (s *Server) conn() coreConn { return coreConn{rt: s.transport, base: s.core.CoreURL} }

// cliConn is the CLI's connection: through the client service on loopback.
func cliConn(paths Paths) (coreConn, error) {
	rt, base, err := coreViaService(paths, "")
	return coreConn{rt: rt, base: base}, err
}

// UnlockCA unlocks the core's CA key store if it is sealed. identities is
// called only then, and is what asks for Touch ID. It answers whether it sent
// an unlock that the core accepted. It goes through the client service; the
// material is opened here, in this process.
func UnlockCA(ctx context.Context, paths Paths, identities func() ([]age.Identity, error)) (bool, error) {
	c, err := cliConn(paths)
	if err != nil {
		return false, err
	}
	return c.unlockCA(ctx, identities)
}

// CAStatus answers the core's CA custody status, through the client service.
func CAStatus(ctx context.Context, paths Paths) (cacustody.CoreStatus, error) {
	c, err := cliConn(paths)
	if err != nil {
		return cacustody.CoreStatus{}, err
	}
	return c.caStatus(ctx)
}

// CAStatus asks the core whether its CA key store is sealed.
func (s *Server) CAStatus(ctx context.Context) (cacustody.CoreStatus, error) {
	return s.conn().caStatus(ctx)
}

// UnlockCA is UnlockCA through this service's connection.
func (s *Server) UnlockCA(ctx context.Context, identities func() ([]age.Identity, error)) (bool, error) {
	return s.conn().unlockCA(ctx, identities)
}

func (c coreConn) caStatus(ctx context.Context) (cacustody.CoreStatus, error) {
	var st cacustody.CoreStatus
	err := c.custodyCall(ctx, http.MethodGet, cacustody.CorePath, nil, func(b []byte) error {
		return json.Unmarshal(b, &st)
	})
	return st, err
}

func (c coreConn) unlockCA(ctx context.Context, identities func() ([]age.Identity, error)) (bool, error) {
	st, err := c.caStatus(ctx)
	if err != nil {
		return false, err
	}
	if !st.Enabled || !st.Sealed {
		return false, nil
	}
	var sealed []byte
	if err = c.custodyCall(ctx, http.MethodGet, cacustody.CoreMaterialPath, nil, func(b []byte) error {
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
	if err := c.custodyCall(ctx, http.MethodPost, cacustody.CoreUnlockPath, body, nil); err != nil {
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
func (c coreConn) custodyCall(ctx context.Context, method, path string, body []byte, read func([]byte) error) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	var reader io.Reader = http.NoBody
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.base, "/")+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.rt.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("ca custody: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("ca custody: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("ca custody: %w", coreAnswerError(resp.StatusCode, payload))
	}
	if read == nil {
		return nil
	}
	return read(payload)
}
