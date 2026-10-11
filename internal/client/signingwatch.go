// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"innsegl.dev/innsegl/internal/signprobe"
)

// RM-339 (#583): the core probes its CA every five minutes and reports the
// result in its status. The client service reads it every minute and tells
// the operator on the first failure, so a CA that cannot sign is news in
// minutes, not hours. One notification per outage: it says nothing more
// until signing has worked again.

// SigningWatchInterval is how often the client service reads the probe.
const SigningWatchInterval = time.Minute

// Notify shows the operator one message.
type Notify func(ctx context.Context, title, body string) error

// signingWatch remembers whether the current outage has been told, and the
// last reading, for GET /_client/status.
type signingWatch struct {
	notified atomic.Bool
	last     atomic.Pointer[SigningStatus]
}

// SigningStatus is the core's signing probe as the client service last read
// it: the `signing` part of GET /_client/status. The hook reads it to say,
// in a refusal, since when signing is down (JRN-011).
type SigningStatus struct {
	Up     bool   `json:"up"`
	Detail string `json:"detail"`
	// Since and Reason are the outage's, read from Detail; absent while
	// signing works.
	Since  time.Time `json:"since,omitzero"`
	Reason string    `json:"reason,omitempty"`
}

// CheckSigning reads the core's signing probe once and notifies on the
// first failure. A core that does not answer, an answer it cannot read, or a
// core with no probe says nothing about signing, so it changes nothing but
// the last reading, which it drops.
func (s *Server) CheckSigning(ctx context.Context, notify Notify) {
	up, detail, ok := s.signingState(ctx)
	if !ok {
		s.signing.last.Store(nil)
		return
	}
	reading := &SigningStatus{Up: up, Detail: detail}
	if !up {
		reading.Since, reading.Reason, _ = signprobe.ParseFailing(detail)
	}
	s.signing.last.Store(reading)
	if up {
		if s.signing.notified.Swap(false) {
			s.log.Printf("signing works again")
		}
		return
	}
	if s.signing.notified.Swap(true) {
		return
	}
	line := signprobe.ReportName + ": " + detail
	s.log.Printf("%s", line)
	if err := notify(ctx, "innsegl: signing is failing", line); err != nil {
		s.log.Printf("showing the signing notification: %v", err)
	}
}

// RunSigningWatch checks every interval until ctx ends.
func (s *Server) RunSigningWatch(ctx context.Context, every time.Duration, notify Notify) {
	for {
		s.CheckSigning(ctx, notify)
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// signingState reads the "signing" component of the core's status.
func (s *Server) signingState(ctx context.Context) (up bool, detail string, ok bool) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimSuffix(s.core.CoreURL, "/")+CoreStatusPath, http.NoBody)
	if err != nil {
		return false, "", false
	}
	resp, err := s.transport.RoundTrip(req)
	if err != nil {
		return false, "", false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, "", false
	}
	var st struct {
		Components []struct {
			Name   string `json:"name"`
			Up     bool   `json:"up"`
			Detail string `json:"detail"`
		} `json:"components"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&st); err != nil {
		return false, "", false
	}
	for _, c := range st.Components {
		if c.Name == signprobe.ReportName {
			return c.Up, c.Detail, true
		}
	}
	return false, "", false
}

// signingOutageTimeout bounds the hook's question: a refusal waits on it.
const signingOutageTimeout = 2 * time.Second

// SigningOutage asks this machine's client service, at the address
// core.json names, whether the core's signing is down: since when and why.
// Anything that keeps it from knowing -- no enrolment, no service, an
// address that is not loopback, an older service, a reading without a time
// -- is "not known to be down".
func SigningOutage(ctx context.Context, paths Paths) (since time.Time, reason string, down bool) {
	cfg, err := ReadCoreConfig(paths)
	if err != nil {
		return time.Time{}, "", false
	}
	listen := cfg.Listen
	if listen == "" {
		listen = DefaultListen
	}
	if CheckLoopback(listen) != nil {
		return time.Time{}, "", false
	}
	ctx, cancel := context.WithTimeout(ctx, signingOutageTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+listen+StatusPath, http.NoBody)
	if err != nil {
		return time.Time{}, "", false
	}
	// Never through a proxy: a shell inside a harness carries HTTPS_PROXY
	// pointing at this same service.
	rt := &http.Transport{Proxy: nil}
	defer rt.CloseIdleConnections()
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return time.Time{}, "", false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, "", false
	}
	var st struct {
		Signing *SigningStatus `json:"signing"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&st); err != nil || st.Signing == nil ||
		st.Signing.Up || st.Signing.Since.IsZero() {
		return time.Time{}, "", false
	}
	return st.Signing.Since, st.Signing.Reason, true
}

// DesktopNotifier is the operator's desktop notification: Notification
// Centre on macOS, nothing elsewhere (the service's log still has it).
func DesktopNotifier(goos string) Notify {
	return desktopNotifier(goos, func(ctx context.Context, name string, args ...string) error {
		return exec.CommandContext(ctx, name, args...).Run()
	})
}

func desktopNotifier(goos string, run func(ctx context.Context, name string, args ...string) error) Notify {
	return func(ctx context.Context, title, body string) error {
		if goos != "darwin" {
			return nil
		}
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		// The text goes in as arguments, never into the script: what the
		// core says is shown, not run.
		return run(ctx, "osascript",
			"-e", "on run argv",
			"-e", "display notification (item 2 of argv) with title (item 1 of argv)",
			"-e", "end run",
			title, body)
	}
}
