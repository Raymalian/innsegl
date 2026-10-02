// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/ecdsa"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DashboardTLSFileName is the file the dashboard's web server reads its
// certificate chain and key from (RM-311, #493). One file holds both, so a
// renewal is one rename and a handshake never pairs a new certificate with
// an old key.
const DashboardTLSFileName = "dashboard-tls.pem"

// WriteDashboardCert mints a certificate for the dashboard and writes it,
// with its key, to dir/DashboardTLSFileName (0600). It covers the same
// names as the gateway's (ADR-0066: one name), from the same CA clients
// already trust, but it has its own key: whoever can read the dashboard's
// file cannot present the gateway's certificate. It answers when the
// certificate expires, so the caller knows when to write it again.
func (ca *CA) WriteDashboardCert(dir string) (time.Time, error) {
	leaf, err := ca.issueLeaf(ca.cfg.now())
	if err != nil {
		return time.Time{}, err
	}
	key, ok := leaf.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return time.Time{}, fmt.Errorf("gateway: the dashboard key is %T, not ECDSA", leaf.PrivateKey)
	}
	keyPEM, err := encodeECKeyPEM(key)
	if err != nil {
		return time.Time{}, err
	}
	var data []byte
	for _, der := range leaf.Certificate {
		data = append(data, encodeCertPEM(der)...)
	}
	data = append(data, keyPEM...)
	if err = os.MkdirAll(dir, caPublicDirMode); err != nil {
		return time.Time{}, fmt.Errorf("gateway: create the dashboard TLS directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+DashboardTLSFileName+".*")
	if err != nil {
		return time.Time{}, fmt.Errorf("gateway: write the dashboard certificate: %w", err)
	}
	defer os.Remove(tmp.Name()) // a no-op after the rename
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return time.Time{}, fmt.Errorf("gateway: write the dashboard certificate: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return time.Time{}, fmt.Errorf("gateway: write the dashboard certificate: %w", err)
	}
	if err = os.Rename(tmp.Name(), filepath.Join(dir, DashboardTLSFileName)); err != nil {
		return time.Time{}, fmt.Errorf("gateway: write the dashboard certificate: %w", err)
	}
	return leaf.Leaf.NotAfter, nil
}

// DashboardCertRenewAt is when a dashboard certificate expiring at notAfter
// should be written again: the gateway leaf's own renewal slack.
func DashboardCertRenewAt(notAfter time.Time) time.Time { return notAfter.Add(-leafRenewBefore) }
