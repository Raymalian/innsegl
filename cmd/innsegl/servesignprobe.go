// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"time"

	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/signprobe"
)

// The signing probe (RM-339, #583): the core asks its CA for a real
// certificate every five minutes and reports the result on /readyz, in the
// scheduled-controls slot the WORM canary uses. `innsegl status` reads it
// from there; `innsegl signing-probe` runs it once, inside the core, for
// `make update`.

const (
	// exitSigningFailing: the CA did not issue a certificate that passed.
	exitSigningFailing = 35
	// exitSigningProbeUnavailable: the probe could not be set up (no SPIRE
	// credential, a configuration it cannot use).
	exitSigningProbeUnavailable = 36
)

// newSigningProber builds the probe from the core's own settings: its Fulcio,
// its trust domain, and get_credential's minter over the one admin
// connection to SPIRE.
func newSigningProber(o serveOptions, minter mcp.CredentialMinter) (*signprobe.Prober, error) {
	return signprobe.New(signprobe.Config{
		FulcioURL:   o.fulcioURL,
		TrustDomain: o.trustDomain,
		Mint: func(ctx context.Context, id, audience string) (string, error) {
			c, err := minter.MintJWTSVID(ctx, id, audience)
			return c.Token, err
		},
	})
}

// signingHealthReports is the probe's line in /readyz's reports. A report,
// never a reason to be unready: the core still records when it cannot sign.
func signingHealthReports(m *signprobe.Monitor) func() []mcp.HealthReport {
	return func() []mcp.HealthReport {
		st := m.State()
		return []mcp.HealthReport{{Name: signprobe.ReportName, OK: st.OK, Detail: st.Detail()}}
	}
}

// joinHealthReports is every scheduled control's report, in order. A nil
// source reports nothing.
func joinHealthReports(sources ...func() []mcp.HealthReport) func() []mcp.HealthReport {
	return func() []mcp.HealthReport {
		var out []mcp.HealthReport
		for _, s := range sources {
			if s != nil {
				out = append(out, s()...)
			}
		}
		return out
	}
}

// openSigningProbe is the production way into the probe for the one-shot
// command: the serve settings, the admin credential, the SVID API.
func openSigningProbe(ctx context.Context, o serveOptions) (signprobe.Probe, func(), error) {
	source, closeSource, _, err := openCredentialSource(ctx, o)
	if err != nil {
		return nil, nil, err
	}
	conn, err := dialSVIDAPI(o, source)
	if err != nil {
		closeSource()
		return nil, nil, err
	}
	closeAll := func() { _ = conn.Close(); closeSource() }
	p, err := newSigningProber(o, mcp.NewSPIREMinter(conn))
	if err != nil {
		closeAll()
		return nil, nil, err
	}
	return p, closeAll, nil
}

func signingProbeCommand(args []string, stdout, stderr io.Writer) int {
	return runSigningProbe(context.Background(), args, stdout, stderr, openSigningProbe)
}

func signingProbeUsage(w io.Writer) {
	fprintf(w, "usage: innsegl signing-probe [serve flags]\n\n"+
		"Ask the CA for one certificate under the probe identity, now, and say whether it\n"+
		"passed. Run inside the core: it reads the same settings as `innsegl serve`.\n"+
		"Exits 0 on a pass, %d when the CA did not issue a certificate that passed,\n"+
		"%d when the probe could not be set up.\n", exitSigningFailing, exitSigningProbeUnavailable)
}

// runSigningProbe runs the probe once. open is the way in; tests replace it.
func runSigningProbe(ctx context.Context, args []string, stdout, stderr io.Writer,
	open func(context.Context, serveOptions) (signprobe.Probe, func(), error)) int {
	for _, a := range args {
		if a == "-h" || a == "-help" || a == "--help" {
			signingProbeUsage(stderr)
			return exitOK
		}
	}
	o, code, ok := parseServeFlags(args, stderr)
	if !ok {
		return code
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	p, closeProbe, err := open(ctx, o)
	if err != nil {
		fprintf(stderr, "innsegl signing-probe: the probe could not be set up: %v\n", err)
		return exitSigningProbeUnavailable
	}
	defer closeProbe()
	r := p.Probe(ctx)
	if !r.OK {
		fprintf(stdout, "%s: FAILING — %s\n", signprobe.ReportName, r.Reason)
		return exitSigningFailing
	}
	fprintf(stdout, "%s: ok — the CA issued a certificate at %s\n", signprobe.ReportName,
		r.At.UTC().Format(time.RFC3339))
	return exitOK
}
