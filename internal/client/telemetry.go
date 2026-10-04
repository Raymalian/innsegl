// SPDX-License-Identifier: Apache-2.0

package client

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Telemetry: the harness's OTLP log exports. Telemetry is the harness's own
// witness of each tool call (internal/gateway/witness.go); an export lost in
// an outage made every tool call in it a "no telemetry" drift alert, and
// Claude Code does not resend one. An export the core does not take is held
// in the outbox (outbox.go) and delivered once it answers.

// TelemetryLogsPath is where the harness exports its log records.
const TelemetryLogsPath = "/v1/logs"

// maxTelemetryExportBytes bounds one export.
const maxTelemetryExportBytes = 4 << 20

// serveTelemetry forwards an export to the core, and holds it when the core
// does not take it now, answering the harness as an OTLP success either way.
func (s *Server) serveTelemetry(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxTelemetryExportBytes+1))
	if err != nil || len(body) > maxTelemetryExportBytes {
		http.Error(w, "innsegl client: the telemetry export could not be read", http.StatusBadRequest)
		return
	}
	status, err := s.liveToCore(r, TelemetryLogsPath, body)
	switch {
	case err == nil && status/100 == 2:
		writeOTLPSuccess(w)
		return
	case err == nil && refusedForGood(status):
		s.log.Printf("the core refused a telemetry export (%d); it is not held", status)
		http.Error(w, fmt.Sprintf("innsegl client: the core refused the telemetry export (%d)", status), status)
		return
	}
	if herr := s.outbox.hold(KindTelemetry, body); herr != nil {
		s.log.Printf("the core did not take a telemetry export and it could not be held: %v", herr)
		http.Error(w, "innsegl client: the telemetry export could not be delivered or held", http.StatusServiceUnavailable)
		return
	}
	writeOTLPSuccess(w)
}

// liveToCore sends a live telemetry export or end to the core, unless the
// core is known to be down: a live request is never held up by a core that
// does not answer. When the core takes it, the delivery loop is woken.
func (s *Server) liveToCore(r *http.Request, path string, body []byte) (int, error) {
	if s.coreDown() {
		return 0, errors.New("the core did not answer a moment ago")
	}
	status, err := s.sendToCore(r.Context(), path, body, r.Header.Get("Content-Type"))
	if err == nil && status/100 == 2 {
		s.kickOutbox()
	}
	return status, err
}

func writeOTLPSuccess(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("{}")); err != nil {
		return
	}
}
