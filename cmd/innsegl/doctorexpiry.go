// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/cacustody"
)

// The reports of #601 (CLI-048..051). All of them read; none repairs. A
// warning is a line, not a failure; only an expired certificate fails doctor
// (exit 37), because signing is about to fail or already has.

const (
	// doctorExpiryWarn is the longest a certificate is warned ahead of
	// expiry: a long-lived root is warned a week out.
	doctorExpiryWarn = 7 * 24 * time.Hour
	// doctorRenewalFraction is the part of its lifetime a self-renewing
	// certificate may have left before renewal counts as overdue. The core
	// renews its server certificate with a quarter of the lifetime left
	// (internal/gateway/tls.go), so a warning below that means the renewal
	// did not happen.
	doctorRenewalFraction = 4
	// doctorClientCertWarn is the client certificate's own threshold: it lives
	// hours and the service renews it, so seven days would always warn. Under
	// an hour left means the renewal is stuck.
	doctorClientCertWarn = time.Hour
	// doctorTokenWarn is the CA token's time left below which it is flagged.
	doctorTokenWarn = 6 * time.Hour
	// doctorBackupWarn is how old the newest backup may be.
	doctorBackupWarn = 48 * time.Hour
)

// dur is a duration in the one unit a person reads: minutes under an hour,
// hours under two days, days past that. It rounds down.
func dur(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d/time.Hour))
	}
	return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
}

// tokenLine reports the CA token's time left, from the core's custody status.
// Renewal resets the token to its full period, so the time since the last
// renewal is the period less what is left.
func (d *doctor) tokenLine(left int64) {
	const check = "ca token"
	if left <= 0 {
		d.line(check, "not reported", "the core does not say; update the core")
		return
	}
	ttl := time.Duration(left) * time.Second
	sinceRenewal := cacustody.TokenPeriod - ttl
	renewIn := cacustody.RenewEvery - sinceRenewal
	switch {
	case ttl < doctorTokenWarn:
		d.line(check, "LOW", "expires in "+dur(ttl)+"; the custodian renews it every "+cacustody.RenewEvery.String())
	case renewIn < -time.Minute:
		d.line(check, "OVERDUE", "not renewed for "+dur(sinceRenewal)+", expires in "+dur(ttl)+
			"; renewal runs every "+cacustody.RenewEvery.String())
	default:
		d.line(check, "ok", "renews in "+dur(max(renewIn, 0))+", expires in "+dur(ttl))
	}
}

// expiryWarn is how much time must be left on a certificate before it is
// warned: a quarter of its own lifetime, never more than a week. A short-lived
// certificate its owner renews warns only when renewal is overdue; a root
// that lives years warns a week out. Without a NotBefore (an older core) the
// lifetime is unknown and the week applies.
func expiryWarn(notBefore, notAfter time.Time) time.Duration {
	if notBefore.IsZero() || !notAfter.After(notBefore) {
		return doctorExpiryWarn
	}
	return min(notAfter.Sub(notBefore)/doctorRenewalFraction, doctorExpiryWarn)
}

// certLine reports one certificate. It says whether it has expired.
func (d *doctor) certLine(check string, notBefore, notAfter time.Time, note string) (expired bool) {
	warn := expiryWarn(notBefore, notAfter)
	if notAfter.IsZero() {
		d.line(check, "not reported", "the core does not say when it expires")
		return false
	}
	left := notAfter.Sub(d.now())
	switch {
	case left <= 0:
		d.line(check, "EXPIRED", "at "+notAfter.UTC().Format(time.RFC3339)+note)
		return true
	case left < warn:
		d.line(check, "EXPIRING", "expires in "+dur(left)+note)
	default:
		d.line(check, "ok", "expires in "+dur(left))
	}
	return false
}

// expiries reports the client certificate, the core's server certificate, and
// the CAs in use. It is true when one has expired.
func (d *doctor) expiries(st coreStatus) (expired bool) {
	if !d.clientCertExpiry.IsZero() {
		left := d.clientCertExpiry.Sub(d.now())
		if left < doctorClientCertWarn {
			d.line("client certificate", "EXPIRING", "expires in "+dur(max(left, 0))+
				"; the service renews it while the core answers: restart it or enrol again with `innsegl connect`")
		} else {
			d.line("client certificate", "ok", "renews itself, valid for "+dur(left))
		}
	}
	if st.ServerCertificate != nil {
		note := ""
		if st.ServerCertificate.Problem != "" {
			note = "; " + st.ServerCertificate.Problem
		}
		expired = d.certLine("server certificate", st.ServerCertificate.NotBefore, st.ServerCertificate.NotAfter, note) || expired
	}
	for _, e := range st.TrustExpiries {
		expired = d.certLine(e.Name, e.NotBefore, e.NotAfter, "; see runbooks/ca-custody.md") || expired
	}
	return expired
}

// stampedNewest is the newest file in dir whose name is prefix + a UTC stamp
// (20060102T150405Z) + suffix and for which ok is true, and the stamp's time.
func stampedNewest(dir, prefix, suffix string, ok func(name string) bool) (time.Time, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return time.Time{}, false
	}
	var newest time.Time
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) || !ok(name) {
			continue
		}
		at, perr := time.Parse("20060102T150405Z", strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix))
		if perr == nil && at.After(newest) {
			newest = at
		}
	}
	return newest, !newest.IsZero()
}

// backupLine reports the age of the newest backup.
func (d *doctor) backupLine(check, noun, dir, rerun string, newest time.Time, found bool) {
	if !found {
		d.line(check, "NONE", "no "+noun+" in "+dir+"; "+rerun)
		return
	}
	age := d.now().Sub(newest)
	if age > doctorBackupWarn {
		d.line(check, "STALE", "newest "+noun+" is "+dur(age)+" old (more than "+dur(doctorBackupWarn)+"); "+rerun)
		return
	}
	d.line(check, "ok", "newest "+noun+" is "+dur(age)+" old")
}

// backups reports the trust-key backup (the copies this machine fetched from
// the core, the same source as `innsegl status`) and the ledger backup, which
// the core reports: its backups are written there, not on this machine.
func (d *doctor) backups(st coreStatus) {
	newest, found := stampedNewest(d.paths.TrustBackups, "trust-backup-", ".tar.age", func(string) bool { return true })
	d.backupLine("trust backup", "backup", d.paths.TrustBackups,
		"run: innsegl trust-backup fetch", newest, found)
	d.ledgerBackup(st.LedgerBackup)
}

// ledgerBackup reports the backup service's last run as the core read it from
// the service's marker. The marker holds the last run, not the last good one,
// so a failed run is its own finding.
func (d *doctor) ledgerBackup(b *ledgerBackupStatus) {
	const check = "ledger backup"
	switch {
	case b == nil:
		d.line(check, "not reported", "the core does not say; update the core")
		return
	case b.LastRunAt.IsZero():
		d.line(check, "NONE", "the core reports no backup has completed")
		d.vm("docker logs --tail 50 innsegl-backup")
		return
	}
	age := d.now().Sub(b.LastRunAt)
	switch {
	case b.Verdict == "failed" || b.Verdict == "mismatch":
		d.line(check, "FAILING", "the core's last backup run "+b.Verdict+" ("+dur(age)+" ago)")
		d.vm("docker logs --tail 50 innsegl-backup")
	case age > doctorBackupWarn:
		d.line(check, "STALE", "the core's last backup ran "+dur(age)+" ago (more than "+dur(doctorBackupWarn)+")")
		d.vm("docker kill -s USR1 innsegl-backup")
	default:
		d.line(check, "ok", "the core's last backup ran "+dur(age)+" ago")
	}
}

// coreLedgerBackup reads the backup service's marker at path, one line
// "<unix seconds> <verdict>" (deploy/compose/innsegl/backup-loop.sh). An empty
// path is a core that does not mount it: nil. A missing or unreadable marker is
// an empty report: no backup has completed.
func coreLedgerBackup(path string) *ledgerBackupStatus {
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G703: the deployment's own marker path, from its environment
	if err != nil {
		return &ledgerBackupStatus{}
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 2 {
		return &ledgerBackupStatus{}
	}
	secs, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || secs <= 0 {
		return &ledgerBackupStatus{}
	}
	return &ledgerBackupStatus{LastRunAt: time.Unix(secs, 0).UTC(), Verdict: fields[1]}
}
