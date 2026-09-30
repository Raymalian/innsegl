// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"innsegl.dev/innsegl/internal/event"
)

// recordmessagekey.go is the operator's own decision on top of E19
// (#395-#397): the API gets a CHECK-ONLY key derived from the identity
// secret (cmd/innsegl/gateway.go's own writeMessageKeyFile), never the
// secret itself, and uses it to VERIFY — never mint — an agent_message's
// own keyed digest (ADR-0061 decision 2), the same way readBody
// (runlog.go) and stepBody (recordbody.go) verify a tool_call's plain one.
//
// # Why brute force over the run's own bodies, and why that is still honest
//
// The chain holds only the KEYED digest; the body on disk is addressed by
// a DIFFERENT, plain one (internal/mcp/agentmessage.go's own doc comment:
// "the plain one is never written to the ledger for this type"), so there
// is no direct lookup from one to the other. What there is, once this
// process holds the derived key, is a small, closed set of candidates — a
// run's own retained bodies, bounded by doc 05 §4's ~20 events per run —
// and an exact cryptographic check against each one. A match is not a
// guess: it is the SAME HMAC-SHA256 construction
// internal/mcp/agentmessage.go's own keyedDigest computes, over content
// this process read itself, equal to the value the chain recorded. Nothing
// here trusts a filename, a role, or an order — only the digest.

// parseKeyedDigest splits a ledger agent_message.payload_digest
// ("hmac-sha256:<key-id>:<64 lowercase hex>", ADR-0061 decision 2) into its
// key id and hex halves, after checking it against event.ValidateKeyedDigest
// — the one place this package trusts the shape before touching it.
func parseKeyedDigest(digest string) (keyID, hexDigest string, ok bool) {
	if event.ValidateKeyedDigest(digest) != nil {
		return "", "", false
	}
	parts := strings.SplitN(digest, ":", 3)
	if len(parts) != 3 {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// readMessageKey reads the derived agent-message key
// (cmd/innsegl/gateway.go's own writeMessageKeyFile) for keyID, exactly as
// it was written: no trimming, no re-encoding. The bytes on disk ARE the
// HMAC-SHA256 key, used as-is — the same way
// (*agentMessageService).keyedDigest (internal/mcp/agentmessage.go) uses
// DeriveAgentMessageKey's own hex-STRING return value directly as
// []byte(key) rather than decoding it further. A key id the chain names
// that has no file here — never rotated to this deployment's key
// directory, or simply not yet written — answers not found, never a
// guess at what the key might be.
func readMessageKey(dir, keyID string) (string, bool) {
	if dir == "" || keyID == "" {
		return "", false
	}
	raw, err := os.ReadFile(filepath.Join(dir, filepath.Base(keyID)))
	if err != nil {
		return "", false
	}
	return string(raw), true
}

// keyedDigestOf restates internal/mcp/agentmessage.go's own keyedDigest —
// unexported to its own package — over body, under key and keyID: the
// IDENTICAL construction, so a match here is never a coincidence of
// similar-but-different math.
func keyedDigestOf(key, keyID string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(body)
	return "hmac-sha256:" + keyID + ":" + hex.EncodeToString(mac.Sum(nil))
}

// verifyAgentMessage checks digest (the ledger's own keyed payload_digest)
// against every candidate body, answering the one whose keyed digest
// matches exactly. Every reason this can fail — a digest this process
// cannot even parse, a key id with no key file, or a digest that matches
// none of the candidates — answers available=false, text="": the three
// are indistinguishable to a caller for the same reason record.go's own
// contract already treats "unavailable" as one state, not three.
func verifyAgentMessage(messageKeyDir, digest string, candidates [][]byte) (text string, available bool) {
	keyID, _, ok := parseKeyedDigest(digest)
	if !ok {
		return "", false
	}
	key, ok := readMessageKey(messageKeyDir, keyID)
	if !ok {
		return "", false
	}
	for _, body := range candidates {
		if keyedDigestOf(key, keyID, body) == digest {
			return string(body), true
		}
	}
	return "", false
}

// runBodyCandidates reads every retained body under dir/runID — tool_call
// bodies included, which simply never produce a match, since a digest
// computed over a JSON tool_call body under an agent-message key answers
// something other than what the chain recorded — for verifyAgentMessage to
// check each of the run's own agent_message events against. A missing or
// unreadable directory answers no candidates, never an error: this mirrors
// stepBody's own "a body store this process cannot read is unavailable,
// not a fault" posture.
func runBodyCandidates(dir, runID string) [][]byte {
	if dir == "" || runID == "" {
		return nil
	}
	runDir := filepath.Join(dir, filepath.Base(runID))
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return nil
	}
	var out [][]byte
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		raw, rerr := os.ReadFile(filepath.Join(runDir, e.Name()))
		if rerr != nil {
			continue
		}
		out = append(out, raw)
	}
	return out
}
