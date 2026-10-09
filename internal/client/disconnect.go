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
)

// DisconnectPath is where a machine revokes its own installation on the
// core, over its own certificate (#490).
const DisconnectPath = "/_core/disconnect"

// RevokeInstallation revokes this machine's installation on the core, so
// its certificate is refused from then on. `innsegl connect --disconnect`
// calls it before it deletes the key; without it, a disconnected machine
// stayed able to record until a member revoked it on the core.
//
// It goes through the client service, like every CLI call to the core. When
// the service is down or older than this command it dials the core itself:
// a disconnect is the last thing this machine does with its key, and it must
// not depend on a service it is about to remove. Where the direct dial is
// refused too (macOS's Local Network permission), the caller says to revoke
// the machine from the Account page. local is the service's address; empty
// means the one the enrolment names.
func RevokeInstallation(ctx context.Context, paths Paths, local string) error {
	rt, base, err := coreViaService(paths, local)
	if err != nil {
		return err
	}
	err = revokeInstallation(ctx, rt, base)
	if !errors.Is(err, ErrClientServiceDown) && !errors.Is(err, ErrClientServiceOld) {
		return err
	}
	s, serr := NewServer(paths, io.Discard)
	if serr != nil {
		return serr
	}
	if derr := revokeInstallation(ctx, s.transport, s.core.CoreURL); derr != nil {
		return fmt.Errorf("%w; dialling the core directly: %w", err, derr)
	}
	return nil
}

func revokeInstallation(ctx context.Context, rt http.RoundTripper, base string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(base, "/")+DisconnectPath, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return coreAnswerError(resp.StatusCode, body)
	}
	return nil
}

// CoreStatusPath is where the core answers an enrolled machine its status
// (#472).
const CoreStatusPath = "/_core/status"

// FetchCoreStatus asks the core for its status through the client service
// at local (empty: the address the enrolment names): the body as the core
// sent it.
func FetchCoreStatus(ctx context.Context, paths Paths, local string) ([]byte, error) {
	rt, base, err := coreViaService(paths, local)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimSuffix(base, "/")+CoreStatusPath, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, coreAnswerError(resp.StatusCode, body)
	}
	return body, nil
}

// ErrCoreOlder is a core that does not know a route or method this client
// uses: it is older than this client, not unreachable.
var ErrCoreOlder = errors.New("the core is older than this client; update the core")

// coreAnswerError is a non-2xx answer as an error carrying the core's own
// message. A core that does not know the route is ErrCoreOlder: a method it
// does not take (405), or a path that fell through to the gateway's harness
// routes, which refuse any shape they do not recognise.
func coreAnswerError(status int, body []byte) error {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil || e.Error == "" {
		// Not the core's JSON (a proxy's page, say): its text is the message.
		e.Error = strings.TrimSpace(string(body))
	}
	if e.Error == "" {
		e.Error = http.StatusText(status)
	}
	if status == http.StatusMethodNotAllowed ||
		(status == http.StatusBadRequest && strings.Contains(e.Error, "unrecognised harness shape")) {
		return fmt.Errorf("%w (it answered %d: %s)", ErrCoreOlder, status, e.Error)
	}
	return fmt.Errorf("the core answered %d: %s", status, e.Error)
}
