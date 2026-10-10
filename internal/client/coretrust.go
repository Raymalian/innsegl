// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Which roots the client trusts for its core (#473, ADR-0081). A core's
// server certificate comes from its own CA (the default, ADR-0066), or is
// publicly trusted, obtained through ACME. The client trusts the core's own
// CA always, and the system's roots as well only for a core recorded as
// having a public server certificate. Client certificates are unchanged:
// this machine still presents the one the deployment's own authority issued.

// ServerCertificatePublic is core.json's server_certificate for a core whose
// server certificate is publicly trusted.
const ServerCertificatePublic = "public"

var (
	systemRootsMu sync.Mutex
	systemRoots   = x509.SystemCertPool
)

// setSystemRoots replaces the system's roots (tests), answering the restore.
func setSystemRoots(f func() (*x509.CertPool, error)) func() {
	systemRootsMu.Lock()
	defer systemRootsMu.Unlock()
	prev := systemRoots
	systemRoots = f
	return func() {
		systemRootsMu.Lock()
		defer systemRootsMu.Unlock()
		systemRoots = prev
	}
}

// CoreRoots is the pool a core is verified against: its own CA, and with
// public, the system's roots too.
func CoreRoots(own *x509.Certificate, public bool) *x509.CertPool {
	pool := x509.NewCertPool()
	if public {
		systemRootsMu.Lock()
		sys, err := systemRoots()
		systemRootsMu.Unlock()
		if err == nil && sys != nil {
			pool = sys.Clone()
		}
	}
	if own != nil {
		pool.AddCert(own)
	}
	return pool
}

// PublicServer reports whether core.json records a public server
// certificate.
func (c CoreConfig) PublicServer() bool { return c.ServerCertificate == ServerCertificatePublic }

// ProbeServerCertificate connects to the core and answers whether its server
// certificate is public: it verifies against the core's own CA, or failing
// that against the system's roots. A certificate neither verifies is an
// error, and nothing is trusted.
func ProbeServerCertificate(ctx context.Context, coreURL string, own *x509.Certificate) (bool, error) {
	try := func(public bool) error {
		c := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: CoreRoots(own, public), MinVersion: tls.VersionTLS12}}}
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, strings.TrimSuffix(coreURL, "/")+"/", http.NoBody)
		if err != nil {
			return err
		}
		resp, err := c.Do(req)
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}
	ownErr := try(false)
	if ownErr == nil {
		return false, nil
	}
	var unknown x509.UnknownAuthorityError
	if !errors.As(ownErr, &unknown) {
		return false, ownErr
	}
	if err := try(true); err != nil {
		return false, fmt.Errorf("the core's server certificate chains neither to its own CA nor to a public root: %w", err)
	}
	return true, nil
}

// WriteCoreConfig replaces core.json.
func WriteCoreConfig(p Paths, cfg CoreConfig) error {
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return err
	}
	return writeFileAtomic(p.Core, append(raw, '\n'), 0o644)
}
