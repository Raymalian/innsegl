// SPDX-License-Identifier: Apache-2.0

package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func responsesPath(path string) bool {
	return path == "/v1/responses" || path == "/backend-api/codex/responses"
}
func responsesModelsPath(path string) bool {
	return path == "/v1/models" || path == "/backend-api/codex/models"
}

func requestSession(r *http.Request) string {
	if responsesPath(r.URL.Path) {
		session, _ := codexRequestThread(r)
		return session
	}
	return r.Header.Get("X-Claude-Code-Session-Id")
}
func requestAgent(r *http.Request) string {
	if responsesPath(r.URL.Path) {
		session, thread := codexRequestThread(r)
		if thread != session {
			return thread
		}
		return ""
	}
	return r.Header.Get("X-Claude-Code-Agent-Id")
}

// codexRequestThread reads routing keys only; the core independently validates
// the full harness contract and observed parent association.
func codexRequestThread(r *http.Request) (string, string) {
	session, thread := r.Header.Get("Session-Id"), r.Header.Get("Thread-Id")
	if raw := r.Header.Get("X-Codex-Turn-Metadata"); raw != "" {
		var m struct {
			Session string `json:"session_id"`
			Thread  string `json:"thread_id"`
		}
		if len(raw) > 16384 || json.Unmarshal([]byte(raw), &m) != nil || m.Session == "" || m.Thread == "" || (session != "" && session != m.Session) || (thread != "" && thread != m.Thread) {
			return "", ""
		}
		return m.Session, m.Thread
	}
	if thread == "" {
		thread = session
	}
	return session, thread
}

func (s *Server) providerForPath(path string) *url.URL {
	switch path {
	case "/v1/responses", "/v1/models":
		return &url.URL{Scheme: "https", Host: "api.openai.com"}
	case "/backend-api/codex/responses", "/backend-api/codex/models":
		return &url.URL{Scheme: "https", Host: "chatgpt.com"}
	default:
		return s.provider
	}
}

// responsesAvailable is negotiated over the enrolled channel. It sends no
// provider credentials. An old/unreachable core is not support for capture.
func (s *Server) responsesAvailable(r *http.Request) bool {
	s.responsesMu.Lock()
	defer s.responsesMu.Unlock()
	if s.Now().Before(s.responsesUntil) {
		return s.responsesSupported
	}
	target := *s.target
	target.Path = strings.TrimSuffix(target.Path, "/") + "/_gateway/capabilities"
	target.RawQuery = ""
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target.String(), nil)
	if err != nil {
		return s.responsesSupported
	}
	client := &http.Client{Transport: s.transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		// A previously advertised format remains a valid route during a
		// transient capability-check outage. The actual model request still
		// goes through the normal core path, whose outage handling journals
		// and forwards it; an installation with no prior positive answer
		// stays fail-closed.
		return s.responsesSupported
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusInternalServerError {
		return s.responsesSupported
	}
	var capabilities struct {
		Formats     []string `json:"formats"`
		Signing     bool     `json:"signing"`
		SigningMode string   `json:"signing_mode"`
		Agents      string   `json:"agents"`
	}
	s.responsesSupported = false
	s.responsesSigning = false
	s.responsesAgents = "root-only"
	if resp.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&capabilities) == nil {
		if capabilities.Agents == "linked-threads" {
			s.responsesAgents = capabilities.Agents
		}
		s.responsesSigning = capabilities.Signing && capabilities.SigningMode == "structured"
		for _, format := range capabilities.Formats {
			if format == "responses-http" {
				s.responsesSupported = true
			}
		}
	}
	// Cache only a positive capability; a just-upgraded core can be retried.
	if s.responsesSupported {
		s.responsesUntil = s.Now().Add(time.Minute)
	}
	return s.responsesSupported
}

func (s *Server) responsesSigningAvailable() bool {
	s.responsesMu.Lock()
	defer s.responsesMu.Unlock()
	return s.responsesSupported && s.responsesSigning
}

func (s *Server) responsesAgentMode() string {
	s.responsesMu.Lock()
	defer s.responsesMu.Unlock()
	if s.responsesSupported && s.responsesAgents == "linked-threads" {
		return s.responsesAgents
	}
	return "root-only"
}
