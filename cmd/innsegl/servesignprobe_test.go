// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/signprobe"
)

// SIG-015 (RM-339, #583), the core's half: the probe's result is a report on
// /readyz in the scheduled-controls slot, failed with the time and the
// reason; `innsegl signing-probe` runs it once with an exit status a script
// reads. The probe itself, against a real SPIRE and Fulcio, is
// internal/signprobe's.

type answer struct{ r signprobe.Result }

func (a answer) Probe(context.Context) signprobe.Result { return a.r }

type readyFakes struct{}

func (readyFakes) AttestedNodes(context.Context) ([]string, error) { return nil, nil }
func (readyFakes) Head(context.Context) (ledger.Head, error)       { return ledger.Head{}, nil }
func (readyFakes) ProbeSigning(context.Context) error              { return nil }
func (readyFakes) ProbeTransparency(context.Context) error         { return nil }

func TestSIG015ReadyzReportsTheSigningProbeFailed(t *testing.T) {
	m := signprobe.NewMonitor(answer{signprobe.Result{Reason: "the CA refused the certificate: HTTP 500: " +
		"error communicating with CA backend"}}, time.Minute, nil)
	m.Check(t.Context())

	canary := func() []mcp.HealthReport { return []mcp.HealthReport{{Name: canaryComponent, OK: true}} }
	h, err := mcp.NewHealth(mcp.HealthConfig{Identities: readyFakes{}, Ledger: readyFakes{}, Sigstore: readyFakes{},
		Reports: joinHealthReports(canary, nil, signingHealthReports(m))})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, mcp.ReadyPath, nil))
	var got struct {
		Ready   bool               `json:"ready"`
		Reports []mcp.HealthReport `json:"reports"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Reports) != 2 || got.Reports[0].Name != canaryComponent || got.Reports[1].Name != "signing" {
		t.Fatalf("reports %+v; want the canary, then signing", got.Reports)
	}
	sig := got.Reports[1]
	if sig.OK || !strings.HasPrefix(sig.Detail, "FAILING since ") ||
		!strings.HasSuffix(sig.Detail, "— the CA refused the certificate: HTTP 500: error communicating with CA backend") {
		t.Fatalf("the signing report %+v", sig)
	}
	if !got.Ready || rec.Code != http.StatusOK {
		t.Fatalf("a failed report made the core unready (%d): a report never gates traffic", rec.Code)
	}
}

func TestSIG015SigningProbeCommandRunsTheProbeOnce(t *testing.T) {
	clearServeEnv(t)
	args := completeServeArgs()[1:]
	open := func(r signprobe.Result, err error) func(context.Context, serveOptions) (signprobe.Probe, func(), error) {
		return func(_ context.Context, o serveOptions) (signprobe.Probe, func(), error) {
			if o.fulcioURL != "http://127.0.0.1:5555" || o.trustDomain != "innsegl.dev" {
				t.Errorf("the probe was opened with %q, %q; want the serve settings", o.fulcioURL, o.trustDomain)
			}
			if err != nil {
				return nil, nil, err
			}
			return answer{r}, func() {}, nil
		}
	}
	at := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		r         signprobe.Result
		err       error
		code      int
		out, err2 string
	}{
		{"a pass", signprobe.Result{OK: true, At: at}, nil, exitOK, "signing: ok — the CA issued a certificate at 2026-10-11T09:00:00Z", ""},
		{"a failure", signprobe.Result{Reason: "the CA refused the certificate: HTTP 500: x"}, nil, exitSigningFailing,
			"signing: FAILING — the CA refused the certificate: HTTP 500: x", ""},
		{"no way in", signprobe.Result{}, errors.New("no SVID"), exitSigningProbeUnavailable, "", "the probe could not be set up: no SVID"},
	} {
		var out, errOut bytes.Buffer
		if code := runSigningProbe(t.Context(), args, &out, &errOut, open(tc.r, tc.err)); code != tc.code {
			t.Errorf("%s: exit %d, want %d; stderr %s", tc.name, code, tc.code, errOut.String())
		}
		if !strings.Contains(out.String(), tc.out) || !strings.Contains(errOut.String(), tc.err2) {
			t.Errorf("%s: stdout %q stderr %q", tc.name, out.String(), errOut.String())
		}
	}

	var out, errOut bytes.Buffer
	if code := runSigningProbe(t.Context(), []string{"-h"}, &out, &errOut, nil); code != exitOK ||
		!strings.Contains(errOut.String(), "usage: innsegl signing-probe") {
		t.Fatalf("-h: %d %q", code, errOut.String())
	}
	errOut.Reset()
	if code := runSigningProbe(t.Context(), nil, &out, &errOut, nil); code != exitUsage {
		t.Fatalf("no settings: exit %d, want %d", code, exitUsage)
	}
}
