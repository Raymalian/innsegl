// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// DashboardTLSConfig is the TLS configuration `innsegl api` serves the
// dashboard with (#475): the certificate and key the core writes to path
// (RM-311, ADR-0066's amendment — the dashboard's own key, never the
// gateway's), in one PEM file, chain first and key after.
//
// The file is read on a handshake whenever its modification time or size
// has changed since the last read, so a certificate the core renews is
// served from the next handshake with no restart. An absent file fails the
// handshake and not the start: the core and this process start in
// parallel, and the core writes the file a moment later. A file that does
// not parse never replaces the last good certificate; the core writes by
// rename, so a bad file is a fault elsewhere, and the page keeps working
// while it is found.
//
// TLS 1.2 and 1.3, as the nginx config allowed. HTTP/1.1 only, as the nginx
// config served.
func DashboardTLSConfig(path string) *tls.Config {
	c := &dashboardCert{path: path}
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"http/1.1"},
		GetCertificate: c.get,
	}
}

type dashboardCert struct {
	path string

	mu      sync.Mutex
	modTime time.Time
	size    int64
	cert    *tls.Certificate
}

var errNoDashboardCert = errors.New("api: the dashboard's certificate has not been written yet")

func (c *dashboardCert) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	info, err := os.Stat(c.path)
	if err != nil {
		if c.cert != nil {
			return c.cert, nil
		}
		return nil, fmt.Errorf("%w (%s): %w", errNoDashboardCert, c.path, err)
	}
	if c.cert != nil && info.ModTime().Equal(c.modTime) && info.Size() == c.size {
		return c.cert, nil
	}
	data, err := os.ReadFile(c.path)
	if err == nil {
		var cert tls.Certificate
		if cert, err = tls.X509KeyPair(data, data); err == nil {
			c.cert, c.modTime, c.size = &cert, info.ModTime(), info.Size()
			return c.cert, nil
		}
	}
	if c.cert != nil {
		return c.cert, nil
	}
	return nil, fmt.Errorf("api: read the dashboard's certificate %s: %w", c.path, err)
}
