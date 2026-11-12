// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// checkRequestCertificate runs before forwarding, so recovery never replays a
// model request. The renewal mutex and published retry deadline bound attempts
// shared with background recovery.
func (s *Server) checkRequestCertificate(ctx context.Context) error {
	leaf := s.Leaf()
	now := s.Now()
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("innsegl client: certificate is not yet valid (valid from %s); check the local clock (now %s)",
			leaf.NotBefore.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	if !s.revoked.Load() && now.Before(leaf.NotAfter) {
		return nil
	}
	reason := "the core refused this certificate"
	if !now.Before(leaf.NotAfter) {
		reason = "certificate expired at " + leaf.NotAfter.UTC().Format(time.RFC3339)
	}
	inProgress := !s.renewMu.TryLock()
	if !inProgress {
		func() {
			defer s.renewMu.Unlock()
			st := s.recovery.Load()
			if st != nil && now.Before(st.NextRetry) {
				return
			}
			attemptCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			if _, err := s.maybeRenewLocked(attemptCtx); err != nil {
				// maybeRenewLocked publishes the cause and next retry below.
				return
			}
		}()
	}
	leaf = s.Leaf()
	if !s.revoked.Load() && !s.Now().Before(leaf.NotBefore) && s.Now().Before(leaf.NotAfter) {
		return nil
	}
	message := "innsegl client: " + reason
	if inProgress {
		message += "; certificate recovery is in progress"
	}
	if st := s.recovery.Load(); st != nil {
		if st.Error != "" {
			message += "; recovery failed: " + st.Error
		}
		if !st.NextRetry.IsZero() {
			message += "; next automatic retry at " + st.NextRetry.UTC().Format(time.RFC3339)
		}
		if st.Action != "" {
			message += "; " + st.Action
		}
	}
	return errors.New(message)
}
