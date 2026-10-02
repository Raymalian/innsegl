// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// RM-313: the client service remembers the newest statement per (session,
// agent) the hook sent through it, and attaches it to every model request it
// forwards, so a core that restarted mid-turn loses nothing.

const (
	scSession  = "11111111-1111-4111-8111-111111111111"
	scSubagent = "aa328d4891c7406b1"
)

func scPost(t *testing.T, url string, body string, header map[string]string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func decodeStatementHeader(t *testing.T, v string) map[string]string {
	t.Helper()
	if v == "" {
		return nil
	}
	b, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		t.Fatalf("the header is not base64url: %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("the header is not a JSON statement: %v", err)
	}
	return m
}

func TestRM313TheClientAttachesTheCachedStatement(t *testing.T) {
	core, paths := enrolled(t)
	statementStatus := http.StatusNoContent
	core.Mux.HandleFunc(SessionStatementPath, func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
		}
		w.WriteHeader(statementStatus)
	})
	seen := make(chan string, 8)
	core.Mux.HandleFunc("/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get(StatementHeader)
		w.WriteHeader(http.StatusOK)
	})
	_, front, _ := startClient(t, paths)

	mainStatement := `{"session_id":"` + scSession + `","cwd":"/w/app","repo":"github.com/acme/app","branch":"main","task":"t1"}`
	if got := scPost(t, front.URL+SessionStatementPath, mainStatement, nil); got != http.StatusNoContent {
		t.Fatalf("statement: %d", got)
	}
	// The main agent's request carries the session's statement.
	scPost(t, front.URL+"/v1/messages", `{}`, map[string]string{"X-Claude-Code-Session-Id": scSession})
	if m := decodeStatementHeader(t, <-seen); m["session_id"] != scSession || m["repo"] != "github.com/acme/app" {
		t.Fatalf("the main agent's request carried %v", m)
	}
	// A subagent with no statement of its own carries the session's.
	scPost(t, front.URL+"/v1/messages", `{}`, map[string]string{
		"X-Claude-Code-Session-Id": scSession, "X-Claude-Code-Agent-Id": scSubagent})
	if m := decodeStatementHeader(t, <-seen); m["cwd"] != "/w/app" || m["agent_id"] != "" {
		t.Fatalf("a subagent with none of its own carried %v", m)
	}
	// Its own, once it states one. Even when the core refused it: the core
	// decides again on every request.
	statementStatus = http.StatusUnauthorized
	scPost(t, front.URL+SessionStatementPath,
		`{"session_id":"`+scSession+`","agent_id":"`+scSubagent+`","cwd":"/w/sub"}`, nil)
	scPost(t, front.URL+"/v1/messages", `{}`, map[string]string{
		"X-Claude-Code-Session-Id": scSession, "X-Claude-Code-Agent-Id": scSubagent})
	if m := decodeStatementHeader(t, <-seen); m["cwd"] != "/w/sub" || m["agent_id"] != scSubagent {
		t.Fatalf("a subagent with its own statement carried %v", m)
	}
	// A session the hook never stated carries nothing, and a header the
	// harness sent itself never reaches the core.
	scPost(t, front.URL+"/v1/messages", `{}`, map[string]string{
		"X-Claude-Code-Session-Id": "22222222-2222-4222-8222-222222222222", StatementHeader: "forged"})
	if v := <-seen; v != "" {
		t.Fatalf("an unstated session carried %q", v)
	}
}

// A refused statement is logged with the session and the reason class.
func TestRM313TheClientLogsARefusedStatement(t *testing.T) {
	core, paths := enrolled(t)
	core.Mux.HandleFunc(SessionStatementPath, func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"innsegl core: request refused"}`)
	})
	_, front, logs := startClient(t, paths)
	body := `{"session_id":"` + scSession + `","cwd":"/w/held","repo":"github.com/rival/held","branch":"main","task":"t1"}`
	if got := scPost(t, front.URL+SessionStatementPath, body, nil); got != http.StatusUnauthorized {
		t.Fatalf("status %d, want the core's 401 unchanged", got)
	}
	for _, want := range []string{scSession, "refused", "scope", "unrecorded"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("the log %q does not say %q", logs.String(), want)
		}
	}
}

func TestRM313TheStatementTableIsBounded(t *testing.T) {
	c := newStatementCache(2)
	for i := range 3 {
		c.remember([]byte(fmt.Sprintf(`{"session_id":"s%d","cwd":"/w"}`, i)))
	}
	if _, ok := c.lookup("s0", ""); ok {
		t.Fatal("the oldest statement was kept past the bound")
	}
	for _, s := range []string{"s1", "s2"} {
		if _, ok := c.lookup(s, ""); !ok {
			t.Fatalf("%s was dropped", s)
		}
	}
	// A newer statement for a known key replaces it in place.
	c.remember([]byte(`{"session_id":"s1","cwd":"/w/new"}`))
	if c.len() != 2 {
		t.Fatalf("len = %d, want 2", c.len())
	}
	// Nothing without a session id is kept.
	c.remember([]byte(`{"cwd":"/w"}`))
	c.remember([]byte(`not json`))
	if c.len() != 2 {
		t.Fatalf("len = %d after unusable statements, want 2", c.len())
	}
}

// SER-021 (RM-314): the subagent's agent_type, stated by the SubagentStart
// hook, rides on its model requests unchanged, so a core that restarted
// still records the harness's own name for the type.
func TestSER021TheCachedStatementCarriesAgentType(t *testing.T) {
	core, paths := enrolled(t)
	core.Mux.HandleFunc(SessionStatementPath, func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	seen := make(chan string, 2)
	core.Mux.HandleFunc("/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get(StatementHeader)
		w.WriteHeader(http.StatusOK)
	})
	_, front, _ := startClient(t, paths)

	const agentType = "flutter-all:flutter-architect"
	scPost(t, front.URL+SessionStatementPath,
		`{"session_id":"`+scSession+`","agent_id":"`+scSubagent+`","cwd":"/w/sub","agent_type":"`+agentType+`"}`, nil)
	scPost(t, front.URL+"/v1/messages", `{}`, map[string]string{
		"X-Claude-Code-Session-Id": scSession, "X-Claude-Code-Agent-Id": scSubagent})
	if m := decodeStatementHeader(t, <-seen); m["agent_type"] != agentType {
		t.Fatalf("the subagent's request carried %v, want its agent_type verbatim", m)
	}
}
