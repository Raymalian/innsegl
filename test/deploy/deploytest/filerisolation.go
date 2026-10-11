// SPDX-License-Identifier: Apache-2.0

package deploytest

import (
	"context"
	"strings"
	"time"
)

// ShippedRunOptions turns the parts of a compose service that change how the
// process behaves — its environment and its host map — into `docker run`
// options, so a case can run the shipped command with everything it relies on.
func ShippedRunOptions(svc InterpolatedService) []string {
	var out []string
	for k, v := range svc.Environment {
		if v != nil {
			out = append(out, "--env", k+"="+*v)
		}
	}
	for _, h := range svc.ExtraHosts {
		out = append(out, "--add-host", strings.Replace(h, "=", ":", 1))
	}
	return out
}

// WaitForObjectStore blocks until a store answers an authenticated request.
func WaitForObjectStore(ctx context.Context, c *ObjectStoreContainer) error {
	deadline := time.Now().Add(2 * time.Minute)
	var last error
	for time.Now().Before(deadline) {
		cl, err := c.ClientAs(StoreRootUser, StoreRootPassword)
		if err == nil {
			attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
			_, err = cl.ListBuckets(attempt)
			cancel()
		}
		if err == nil {
			return nil
		}
		last = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return last
}
