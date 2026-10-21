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
		return r.Header.Get("Session-Id")
	}
	return r.Header.Get("X-Claude-Code-Session-Id")
}
func requestAgent(r *http.Request) string {
	if responsesPath(r.URL.Path) {
		return ""
	} // Only measured root sessions are currently supported.
	return r.Header.Get("X-Claude-Code-Agent-Id")
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
		return false
	}
	client := &http.Client{Transport: s.transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var capabilities struct {
		Formats []string `json:"formats"`
	}
	s.responsesSupported = false
	if resp.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&capabilities) == nil {
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
