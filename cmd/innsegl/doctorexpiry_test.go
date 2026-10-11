// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/cacustody"
	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/trusthistory"
)

// ---------------------------------------------------------------------------
// CLI-048..051 (PROPOSED for doc 07's TC-CLI), #601 — doctor reports, and
// only reports: the CA token's time left, certificate expiry, and the age of
// the trust-key and ledger backups. None of it repairs anything.
// ---------------------------------------------------------------------------

func lineStarting(out, prefix string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	return ""
}

func (c *doctorCore) setTokenLeft(d time.Duration) {
	c.custody.TokenSecondsLeft = int64(d / time.Second)
}

// CLI-048 — the CA token line says when it renews and when it expires.
// Nothing is run to repair it.
func TestCLI048TheCATokenLineSaysWhenItRenewsAndExpires(t *testing.T) {
	core := healthyDoctorCore()
	core.setTokenLeft(cacustody.TokenPeriod - 3*time.Minute) // renewed 3 min ago
	d := newDoctorRun(t, core)
	code, out := d.run(t)
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, out)
	}
	want := "ca token: ok — renews in 12m, expires in 23h"
	if got := lineStarting(out, "ca token:"); got != want {
		t.Fatalf("token line %q, want %q\n%s", got, want, out)
	}
	if len(d.repairs()) != 0 {
		t.Errorf("reporting the token ran %q", d.repairs())
	}
}

// CLI-048 — a token with under six hours left, or one not renewed when it
// should have been, is flagged; a core that does not say is said.
func TestCLI048ALowOrOverdueTokenIsFlaggedAndAnUnreportedOneIsSaid(t *testing.T) {
	for name, tc := range map[string]struct {
		left time.Duration
		want string
	}{
		"low":        {5 * time.Hour, "ca token: LOW — expires in 5h"},
		"overdue":    {cacustody.TokenPeriod - 2*time.Hour, "ca token: OVERDUE — not renewed for 2h"},
		"unreported": {0, "ca token: not reported — the core does not say; update the core"},
	} {
		t.Run(name, func(t *testing.T) {
			core := healthyDoctorCore()
			core.setTokenLeft(tc.left)
			_, out := newDoctorRun(t, core).run(t)
			if got := lineStarting(out, "ca token:"); !strings.HasPrefix(got, tc.want) {
				t.Fatalf("token line %q, want prefix %q\n%s", got, tc.want, out)
			}
		})
	}
}

// CLI-048 (core side) — the custody status the core passes through carries
// the token's seconds left, a read-only field.
func TestCLI048TheCustodyStatusCarriesTheTokenTimeLeft(t *testing.T) {
	core := healthyDoctorCore()
	core.setTokenLeft(7 * time.Hour)
	d := newDoctorRun(t, core)
	st, err := client.CAStatus(t.Context(), client.ClientPaths(d.f.home))
	if err != nil {
		t.Fatal(err)
	}
	if st.TokenSecondsLeft != int64((7 * time.Hour).Seconds()) {
		t.Fatalf("the core's custody status passed through %d seconds, want 25200", st.TokenSecondsLeft)
	}
}

func expiryIn(name string, kind trusthistory.Kind, after time.Duration) trusthistory.Expiry {
	return trusthistory.Expiry{Name: name, Kind: kind, NotAfter: time.Now().Add(after)}
}

// CLI-049 — every certificate doctor can see is on a line: a warning under
// seven days, and exit 37 when one has expired.
func TestCLI049CertificatesAreReportedAndWarnedWithoutFailing(t *testing.T) {
	core := healthyDoctorCore()
	core.trust = []trusthistory.Expiry{
		expiryIn("Fulcio root CA", trusthistory.KindFulcioRoot, 400*24*time.Hour+time.Hour),
		expiryIn("SPIRE upstream CA", trusthistory.KindSPIREUpstreamCA, 3*24*time.Hour),
		expiryIn("gateway CA", trusthistory.KindGatewayCA, 400*24*time.Hour+time.Hour),
	}
	core.server = &serverCertStatus{Source: "own", NotAfter: time.Now().Add(60*24*time.Hour + time.Hour)}
	d := newDoctorRun(t, core)
	code, out := d.run(t)
	if code != exitOK {
		t.Fatalf("a warning must not fail doctor: exit %d\n%s", code, out)
	}
	for prefix, want := range map[string]string{
		"client certificate:": "ok — renews itself",
		"server certificate:": "ok — expires in 60d",
		"Fulcio root CA:":     "ok — expires in 400d",
		"SPIRE upstream CA:":  "EXPIRING — expires in 2d",
		"gateway CA:":         "ok — expires in 400d",
	} {
		got := lineStarting(out, prefix)
		if !strings.Contains(got, ": "+want) {
			t.Errorf("%s line %q, want %q\n%s", prefix, got, want, out)
		}
	}
	if len(d.repairs()) != 0 {
		t.Errorf("reporting certificates ran %q", d.repairs())
	}
}

func TestCLI049AnExpiredCertificateFailsDoctor(t *testing.T) {
	core := healthyDoctorCore()
	core.server = &serverCertStatus{Source: "own", NotAfter: time.Now().Add(-time.Hour)}
	code, out := newDoctorRun(t, core).run(t)
	if code != exitDoctorFailing {
		t.Fatalf("an expired server certificate: exit %d, want %d\n%s", code, exitDoctorFailing, out)
	}
	if got := lineStarting(out, "server certificate:"); !strings.Contains(got, "EXPIRED") {
		t.Fatalf("server line %q\n%s", got, out)
	}
}

// The client certificate lives hours and the service renews it, so seven days
// would always warn: it is flagged when under an hour is left, which means
// the renewal is stuck.
func TestCLI049AClientCertificateNearExpiryMeansARenewalIsStuck(t *testing.T) {
	d := newDoctorRun(t, healthyDoctorCore())
	pemBytes, err := os.ReadFile(client.ClientPaths(d.f.home).Cert)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	exp := cert.NotAfter
	d.now = func() time.Time { return exp.Add(-30 * time.Minute) }
	_, out := d.run(t)
	if got := lineStarting(out, "client certificate:"); !strings.Contains(got, "EXPIRING") {
		t.Fatalf("client certificate line %q\n%s", got, out)
	}
}

func writeStamped(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func stamp(ago time.Duration) string {
	return time.Now().Add(-ago).UTC().Format("20060102T150405Z")
}

// CLI-050 — the newest trust-key backup's age: stale past two days, and none
// at all is said. Neither fails doctor.
func TestCLI050TrustKeyBackupAge(t *testing.T) {
	for name, tc := range map[string]struct {
		ago  time.Duration // zero: no backup
		want string
	}{
		"fresh": {5 * time.Hour, "trust backup: ok — newest backup is 5h old"},
		"stale": {3 * 24 * time.Hour, "trust backup: STALE — newest backup is 3d old"},
		"none":  {0, "trust backup: NONE — no backup in "},
	} {
		t.Run(name, func(t *testing.T) {
			d := newDoctorRun(t, healthyDoctorCore())
			dir := filepath.Join(d.f.home, ".innsegl", "trust-backups")
			if tc.ago > 0 {
				writeStamped(t, dir, "trust-backup-"+stamp(30*24*time.Hour)+".tar.age")
				writeStamped(t, dir, "trust-backup-"+stamp(tc.ago)+".tar.age")
			}
			code, out := d.run(t)
			if code != exitOK {
				t.Fatalf("a backup finding must not fail doctor: exit %d\n%s", code, out)
			}
			if got := lineStarting(out, "trust backup:"); !strings.HasPrefix(got, tc.want) {
				t.Fatalf("line %q, want prefix %q\n%s", got, tc.want, out)
			}
		})
	}
}

// CLI-051 — the newest verified ledger dump's age. A dump without its
// verification report is not protection and is not counted.
func TestCLI051LedgerBackupAge(t *testing.T) {
	d := newDoctorRun(t, healthyDoctorCore())
	dir := filepath.Join(d.f.home, ".innsegl", "backups")
	old := "innsegl-" + stamp(40*time.Hour) + ".dump"
	writeStamped(t, dir, old)
	writeStamped(t, dir, old+".verify.txt")
	writeStamped(t, dir, "innsegl-"+stamp(time.Hour)+".dump") // truncated: no report
	_, out := d.run(t)
	if got := lineStarting(out, "ledger backup:"); !strings.HasPrefix(got, "ledger backup: ok — newest verified dump is 40h old") {
		t.Fatalf("line %q\n%s", got, out)
	}

	d2 := newDoctorRun(t, healthyDoctorCore())
	dir2 := filepath.Join(d2.f.home, ".innsegl", "backups")
	stale := "innsegl-" + stamp(5*24*time.Hour) + ".dump"
	writeStamped(t, dir2, stale)
	writeStamped(t, dir2, stale+".verify.txt")
	code, out := d2.run(t)
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if got := lineStarting(out, "ledger backup:"); !strings.HasPrefix(got, "ledger backup: STALE — newest verified dump is 5d old") {
		t.Fatalf("line %q\n%s", got, out)
	}
	if !strings.Contains(out, "dev.innsegl.backup-ledger") {
		t.Errorf("a stale ledger backup names no command to take one:\n%s", out)
	}
}
