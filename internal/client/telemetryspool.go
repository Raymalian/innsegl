// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// telemetry spool: the harness's OTLP log exports, held while the core does
// not answer and delivered once it does. Telemetry is the harness's own
// witness of each tool call (internal/gateway/witness.go); an export lost in
// an outage made every tool call in it a "no telemetry" drift alert, and
// Claude Code does not resend one.

// TelemetryLogsPath is where the harness exports its log records.
const TelemetryLogsPath = "/v1/logs"

const (
	// maxTelemetryExportBytes bounds one held export.
	maxTelemetryExportBytes = 4 << 20
	// maxTelemetrySpoolFiles bounds the spool; past it, an export is
	// answered as failed and not kept.
	maxTelemetrySpoolFiles = 4096
	// telemetryReplayInterval is how often held exports are retried.
	telemetryReplayInterval = 15 * time.Second
)

func (s *Server) telemetrySpoolDir() string { return filepath.Join(s.paths.Dir, "telemetry-spool") }

// telemetrySpoolDepth is how many exports are held.
func (s *Server) telemetrySpoolDepth() int {
	entries, err := os.ReadDir(s.telemetrySpoolDir())
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			n++
		}
	}
	return n
}

// serveTelemetry forwards an export to the core, and holds it when the core
// does not answer, answering the harness as an OTLP success either way.
func (s *Server) serveTelemetry(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxTelemetryExportBytes+1))
	if err != nil || len(body) > maxTelemetryExportBytes {
		http.Error(w, "innsegl client: the telemetry export could not be read", http.StatusBadRequest)
		return
	}
	if s.deliverTelemetry(r.Context(), body, r.Header.Get("Content-Type")) == nil {
		s.kickTelemetryReplay()
		writeOTLPSuccess(w)
		return
	}
	if err := s.holdTelemetry(body); err != nil {
		s.log.Printf("the core did not take a telemetry export and it could not be held: %v", err)
		http.Error(w, "innsegl client: the telemetry export could not be delivered or held", http.StatusServiceUnavailable)
		return
	}
	writeOTLPSuccess(w)
}

func writeOTLPSuccess(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("{}")); err != nil {
		return
	}
}

// deliverTelemetry posts one export to the core over the client certificate.
func (s *Server) deliverTelemetry(ctx context.Context, body []byte, contentType string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(s.core.CoreURL, "/")+TelemetryLogsPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if contentType == "" {
		contentType = "application/json"
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := s.transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if _, err = io.Copy(io.Discard, resp.Body); err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("the core answered %d", resp.StatusCode)
	}
	return nil
}

// holdTelemetry writes one export to the spool, named by arrival so replay
// keeps the order.
func (s *Server) holdTelemetry(body []byte) error {
	dir := s.telemetrySpoolDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if s.telemetrySpoolDepth() >= maxTelemetrySpoolFiles {
		return errors.New("the telemetry spool is full")
	}
	name := strconv.FormatInt(s.Now().UnixNano(), 10) + ".json"
	return writeFileAtomic(filepath.Join(dir, name), body, 0o600)
}

// ReplayTelemetry delivers held exports, oldest first, and stops at the
// first the core does not take.
func (s *Server) ReplayTelemetry(ctx context.Context) error {
	dir := s.telemetrySpoolDir()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		p := filepath.Join(dir, n)
		// #nosec G304 -- a file this service wrote in its own spool.
		body, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if derr := s.deliverTelemetry(ctx, body, "application/json"); derr != nil {
			return derr
		}
		if rmErr := os.Remove(p); rmErr != nil {
			return rmErr
		}
	}
	return nil
}

func (s *Server) kickTelemetryReplay() {
	if s.telemetryKick == nil {
		return
	}
	select {
	case s.telemetryKick <- struct{}{}:
	default:
	}
}

// RunTelemetryReplay retries held exports until ctx ends: at once when the
// core takes a live export, and every telemetryReplayInterval.
func (s *Server) RunTelemetryReplay(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(telemetryReplayInterval):
		case <-s.telemetryKick:
		}
		if s.telemetrySpoolDepth() == 0 {
			continue
		}
		if err := s.ReplayTelemetry(ctx); err != nil {
			s.log.Printf("delivering held telemetry: %v", err)
		}
	}
}
