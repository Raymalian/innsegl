// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/gateway"
)

// The core's half of the unrouted-session detector (RM-319, #579): an
// enrolled machine reports a session whose model traffic bypassed innsegl,
// and the core keeps it for the dashboard. Behind the client guard, like
// every hosted route but enrolment: the machine is the verified installation,
// never a field of the body.

// unroutedReporter keeps a report.
type unroutedReporter interface {
	Report(ctx context.Context, installation, session string, lastActivity time.Time) error
}

// unroutedClockSkew is how far ahead of the core's clock a machine's last
// activity may be.
const unroutedClockSkew = 10 * time.Minute

func unroutedHandler(store unroutedReporter, log *serveLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeCoreError(w, http.StatusMethodNotAllowed, "innsegl core: unrouted session: only POST is accepted")
			return
		}
		id, ok := gateway.InstallationFromContext(r.Context())
		if !ok {
			gateway.WriteClientRefusal(w)
			return
		}
		var rep client.UnroutedReport
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&rep); err != nil ||
			rep.SessionID == "" || len(rep.SessionID) > 256 || strings.ContainsAny(rep.SessionID, " \t\r\n") ||
			rep.LastActivityAt.IsZero() || rep.LastActivityAt.After(time.Now().Add(unroutedClockSkew)) {
			writeCoreError(w, http.StatusBadRequest, "innsegl core: unrouted session: the body is not a report")
			return
		}
		if err := store.Report(r.Context(), id, rep.SessionID, rep.LastActivityAt); err != nil {
			log.warn("unrouted session: keeping the report", "installation_id", id, "err", err)
			writeCoreError(w, http.StatusServiceUnavailable, "innsegl core: unrouted session: not kept; retry")
			return
		}
		log.warn("an enrolled machine reports a session whose model traffic bypassed innsegl",
			"installation_id", id, "session_id", rep.SessionID, "last_activity_at", rep.LastActivityAt)
		w.WriteHeader(http.StatusNoContent)
	}
}

// coreUnroutedPath is client.UnroutedPath, the route a machine reports to.
const coreUnroutedPath = client.UnroutedPath
