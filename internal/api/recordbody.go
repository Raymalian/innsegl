// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// recordbody.go reads the two kinds of retained body this record needs — a
// gateway-recorded tool_call body, and (for spawn linking only, see below) a
// content-addressed agent_message body — and extracts the parts
// record.go's own RunRecord needs from each. Every read goes through
// readBody (runlog.go), which already refuses a body whose bytes do not
// hash to the digest the chain recorded: nothing here trusts a body past
// that check, and record.go's own contract is explicit that an unverified
// body is never shown as the record.

// gatewayBody mirrors internal/gateway/record.go's own gatewayToolCallBody,
// restated here rather than imported — that type is unexported to its own
// package, the same reason internal/reconciler's commitwatch.go and
// witness.go restate it for their own narrower reads.
type gatewayBody struct {
	Tool            string          `json:"tool"`
	ToolUseID       string          `json:"tool_use_id"`
	Input           json.RawMessage `json:"input"`
	InputTruncated  bool            `json:"input_truncated"`
	ResultObserved  bool            `json:"result_observed"`
	Result          json.RawMessage `json:"result"`
	IsError         bool            `json:"is_error"`
	ResultTruncated bool            `json:"result_truncated"`
	Note            string          `json:"note"`
}

// stepBody reads and verifies one tool_call's retained body. ok is false for
// every reason the body cannot be shown as the record: missing, a digest
// mismatch, or bytes that do not parse as a gateway-recorded tool_call at
// all — record.go's own "a missing body → unavailable; a digest mismatch →
// not verified, never shown" rule, extended to "does not parse" for the same
// reason: bytes this handler cannot read as the shape it expects are bytes
// it must not guess the meaning of.
func stepBody(dir, runID, digest string) (gatewayBody, bool) {
	if dir == "" || digest == "" {
		return gatewayBody{}, false
	}
	raw, ok := readBody(dir, runID, digest)
	if !ok {
		return gatewayBody{}, false
	}
	// readBody (runlog.go) only opens the file the digest names; it is
	// bodyMatches, the SAME function BuildRunLog itself calls before ever
	// showing a body, that actually checks the bytes read still hash to
	// the digest the chain recorded. Skipping this call would make a
	// TAMPERED body — present on disk, wrong content — read as available,
	// which is exactly what record.go's own "a digest mismatch → not
	// verified, never shown" rule forbids.
	if !bodyMatches(raw, digest) {
		return gatewayBody{}, false
	}
	var b gatewayBody
	if err := json.Unmarshal(raw, &b); err != nil {
		return gatewayBody{}, false
	}
	return b, true
}

// resultText reads a tool_result's own `content` field: a plain string (the
// ordinary shape for a Bash result) or an array of content blocks, of which
// only `{"type":"text",...}` ones contribute — internal/reconciler's own
// commitwatch.go resultText, restated for the same reason gatewayBody is.
func resultText(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, true
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &blocks); err == nil {
		var b strings.Builder
		for _, blk := range blocks {
			if blk.Type == "text" {
				b.WriteString(blk.Text)
			}
		}
		return b.String(), true
	}
	return "", false
}

// commitSummaryLine is git's own commit-summary format (builtin/commit.c's
// print_summary), anchored to the start of a line so an agent's own commit
// message can never be mistaken for it — internal/reconciler's own
// commitwatch.go commitSummaryLine, restated for the identical reason (that
// pattern is unexported to its own package) and matched on the SAME grammar
// so the run page's commit_sha and the reconciler's own commit watch can
// never disagree about which line in a Bash result names a commit.
var commitSummaryLine = regexp.MustCompile(`(?m)^\[\S+ (?:\(root-commit\) )?([0-9a-f]{4,40})\]`)

// commitShortSHA reports the abbreviated commit id git's own summary line
// names in text, and whether text holds one at all.
func commitShortSHA(text string) (string, bool) {
	m := commitSummaryLine.FindStringSubmatch(text)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// exitCodeLine recognises an explicit "Exit code: N" (or "Exit code N")
// marker in a Bash result's own text — the one other source record.go's
// Outcome.ExitCode rule reads from, beside a zero for an observed success.
// Case-insensitive and tolerant of the colon Claude Code's own harness
// sometimes omits; anchored to a line start for commitSummaryLine's own
// reason, so an agent's own printed text ("echo Exit code 1 means failure")
// deep inside a multi-line result is not mistaken for the harness's marker
// UNLESS it too starts a line — a known, disclosed limit of a textual
// signal, not a structural one.
var exitCodeLine = regexp.MustCompile(`(?mi)^Exit code:?\s+(-?\d+)\s*$`)

// exitCodeFrom reads an explicit exit code out of a Bash result's text.
func exitCodeFrom(text string) (int, bool) {
	m := exitCodeLine.FindStringSubmatch(text)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// ---------------------------------------------------------------------------
// Spawn linking: matching a child run to the step that spawned it, without
// the deployment's identity secret (see recordbuild.go's own package
// comment for why agent_message bodies are otherwise unavailable to this
// process).
// ---------------------------------------------------------------------------

// spawnBodyMatches reports whether runID's own retained bodies hold EXACTLY
// prompt, content-addressed: prompt's plain sha256 digest names the file
// (the SAME layout internal/mcp/agentmessage.go writes a brief's body
// under — one file per run, one file per PLAIN digest, never the KEYED
// digest ADR-0061 puts on the chain), and the file's own bytes are read
// back and compared to prompt BYTE FOR BYTE rather than merely trusted for
// having the right name.
//
// This is how ADR-0058 decision 3 itself links a child to its spawning tool
// call — EXACT EQUALITY between the spawn prompt and the child's own
// brief — re-derived from what is on disk rather than read off the
// gateway's in-memory linker (which is long gone by the time this handler
// runs) or off the chain (which carries only the KEYED digest this process
// has no secret to derive — see recordbuild.go). It needs no secret because
// it never computes or checks the keyed grammar at all: a byte-for-byte
// match against content this process read itself is its own verification.
func spawnBodyMatches(dir, runID, prompt string) bool {
	if dir == "" || runID == "" || prompt == "" {
		return false
	}
	sum := sha256.Sum256([]byte(prompt))
	path := filepath.Join(dir, filepath.Base(runID), hex.EncodeToString(sum[:])+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return string(raw) == prompt
}

// agentToolInput is the one member record.go's SpawnedRunID rule needs out
// of an Agent-tool step's own input: the exact prompt the spawn named
// (ADR-0058 decision 3). A narrow struct, on writes.go's own hookBody
// reasoning: everything else in this input is the operator's own text.
type agentToolInput struct {
	Prompt string `json:"prompt"`
}

// agentPromptOf reads the spawn prompt out of an Agent-tool step's own
// input. ok is false when input does not parse or names no prompt at all —
// never a reason to guess one.
func agentPromptOf(input json.RawMessage) (string, bool) {
	var in agentToolInput
	if err := json.Unmarshal(input, &in); err != nil || in.Prompt == "" {
		return "", false
	}
	return in.Prompt, true
}
