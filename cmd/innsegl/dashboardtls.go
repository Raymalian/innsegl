// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"time"

	"innsegl.dev/innsegl/internal/gateway"
)

// envDashboardTLSDir is where the core writes the dashboard's certificate
// and key (RM-311, #493): a volume the dashboard's web server mounts read
// only. Unset, no file is written and the dashboard serves plain HTTP alone.
const envDashboardTLSDir = "INNSEGL_DASHBOARD_TLS_DIR"

// dashboardCertRetry is how long a failed rewrite waits before the next try.
const dashboardCertRetry = time.Minute

// dashboardCert keeps the dashboard's certificate current: written at boot,
// written again before it expires. The web server reads the file on every
// handshake, so nothing has to be reloaded.
type dashboardCert struct {
	ca       *gateway.CA
	dir      string
	log      *serveLog
	notAfter time.Time
	now      func() time.Time
}

// openDashboardCert writes the first certificate. A directory the core
// cannot write is a configuration error, refused at boot like the CA's own.
func openDashboardCert(ca *gateway.CA, dir string, log *serveLog) (*dashboardCert, error) {
	notAfter, err := ca.WriteDashboardCert(dir)
	if err != nil {
		return nil, err
	}
	return &dashboardCert{ca: ca, dir: dir, log: log, notAfter: notAfter, now: time.Now}, nil
}

// run rewrites the certificate at each renewal point until ctx is done. A
// failed write is logged and tried again: the certificate on disk is still
// valid for hours. A renewal point already passed right after a write (a
// clock out of step with the CA's) waits dashboardCertRetry, never spins.
func (d *dashboardCert) run(ctx context.Context) {
	wroteNow := false
	for {
		wait := gateway.DashboardCertRenewAt(d.notAfter).Sub(d.now())
		if wait < 0 {
			wait = 0
		}
		if wroteNow && wait < dashboardCertRetry {
			wait = dashboardCertRetry
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		notAfter, err := d.ca.WriteDashboardCert(d.dir)
		if err != nil {
			d.log.warn("could not renew the dashboard certificate; trying again", "dir", d.dir, "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(dashboardCertRetry):
			}
			wroteNow = false
			continue
		}
		d.notAfter = notAfter
		wroteNow = true
		d.log.info("renewed the dashboard certificate", "expires", notAfter.UTC().Format(time.RFC3339))
	}
}
