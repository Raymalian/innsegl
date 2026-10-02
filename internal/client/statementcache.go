// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"sync"
)

// The statement cache (RM-313). The session hook states each session's
// workspace to INNSEGL_CORE_URL, which is this service, so every statement
// passes through here on its way to the core. The newest one per (session,
// agent) is kept and attached to every model request of that session, in
// StatementHeader. The core keeps statements in memory only; with the
// statement on the request, a core restart mid-turn loses nothing.
//
// The core validates and admits a header statement exactly as it does the
// endpoint's body, so this cache only remembers: it keeps a statement the
// core refused too, and the core decides again.

// DefaultMaxStatements bounds the cache: one entry per (session, agent).
const DefaultMaxStatements = 4096

// maxStatementBytes bounds one cached statement, the core's own bound on the
// endpoint's body.
const maxStatementBytes = 16 << 10

type statementKey struct{ sessionID, agentID string }

// statementCache is the bounded table; the oldest key goes first.
type statementCache struct {
	mu    sync.Mutex
	max   int
	order []statementKey
	byKey map[statementKey]string // the header value
}

func newStatementCache(capacity int) *statementCache {
	if capacity <= 0 {
		capacity = DefaultMaxStatements
	}
	return &statementCache{max: capacity, byKey: make(map[statementKey]string)}
}

// remember keeps body, a statement as the hook posted it, under its session
// and agent. A body that is not a JSON statement naming a session is not kept.
func (c *statementCache) remember(body []byte) (sessionID string) {
	if len(body) > maxStatementBytes {
		return ""
	}
	var in struct {
		SessionID string `json:"session_id"`
		AgentID   string `json:"agent_id"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.SessionID == "" {
		return ""
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, body); err != nil {
		return ""
	}
	value := base64.RawURLEncoding.EncodeToString(compact.Bytes())
	key := statementKey{in.SessionID, in.AgentID}

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, known := c.byKey[key]; !known {
		if len(c.order) >= c.max && len(c.order) > 0 {
			delete(c.byKey, c.order[0])
			c.order = c.order[1:]
		}
		c.order = append(c.order, key)
	}
	c.byKey[key] = value
	return in.SessionID
}

// lookup answers the header value for a request of agentID ("" for the main
// agent) in sessionID: the agent's own statement, else the session's.
func (c *statementCache) lookup(sessionID, agentID string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.byKey[statementKey{sessionID, agentID}]; ok {
		return v, true
	}
	v, ok := c.byKey[statementKey{sessionID, ""}]
	return v, ok
}

func (c *statementCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.byKey)
}
