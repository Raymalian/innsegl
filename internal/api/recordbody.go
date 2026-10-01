// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

	// hookShape and hookOutcome are this process's own classification of a
	// retained body, set only by hookBodyAsGateway (RM-273) while mapping a
	// harness PostToolUse payload onto this struct's other fields — never a
	// member a body on disk carries (json:"-"), and never a field
	// record.go's own JSON contract serializes (RunRecord never marshals a
	// gatewayBody at all, only the RecordStep fields outcomeOf and
	// summaryOf derive from it). outcomeOf reads hookOutcome instead of its
	// own ResultObserved/IsError fold whenever hookShape is true, because
	// nothing in the harness's own payload is a single error boolean the
	// way the gateway's is_error is — see hookOutcomeOf.
	hookShape   bool
	hookOutcome RecordOutcome
}

// isError reports whether this body's own outcome counts as a failure —
// the gateway's own is_error flag, or, for a hook-shape body, the outcome
// RM-273's own mapping already derived from the harness's own payload. The
// one signal recordbuild.go's commit-SHA search and recordlanding.go's
// ref-lock scan both need, so neither reads IsError directly and risks
// treating every hook-shape body (IsError always false; it carries no such
// field) as unconditionally successful.
func (b gatewayBody) isError() bool {
	if b.hookShape {
		return b.hookOutcome.Kind == "error"
	}
	return b.IsError
}

// stepBody reads and verifies one tool_call's retained body. ok is false for
// every reason the body cannot be shown as the record: missing, a digest
// mismatch, or bytes that do not parse as a gateway-recorded tool_call at
// all — record.go's own "a missing body → unavailable; a digest mismatch →
// not verified, never shown" rule, extended to "does not parse" for the same
// reason: bytes this handler cannot read as the shape it expects are bytes
// it must not guess the meaning of.
// bodyFileReads counts stored bodies opened by stepBody, so a test can see
// the cache at work (#442).
var bodyFileReads atomic.Int64

func stepBody(dir, runID, digest string) (gatewayBody, bool) {
	if dir == "" || digest == "" {
		return gatewayBody{}, false
	}
	// A verified body is reused while its file is unchanged (#442). The key
	// carries the file's size and modification time, so a body changed or
	// removed after it was cached misses here and is read and checked again.
	key, keyed := bodyCacheKey(dir, runID, digest)
	if keyed {
		if b, ok := bodyCache.get(key); ok {
			return b, true
		}
	}
	b, ok := readStepBody(dir, runID, digest)
	if ok && keyed {
		bodyCache.put(key, b)
	}
	return b, ok
}

// bodyCacheKey names one stored body as it is on disk now: false when the
// file cannot be found, which leaves nothing to reuse.
func bodyCacheKey(dir, runID, digest string) (string, bool) {
	hexPart, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || len(hexPart) != 64 {
		return "", false
	}
	path := filepath.Join(dir, filepath.Base(runID), hexPart+".json")
	info, err := os.Stat(path)
	if err != nil {
		return "", false
	}
	return fmt.Sprintf("%s|%d|%d", path, info.Size(), info.ModTime().UnixNano()), true
}

// bodyCacheLimit bounds the cache: a few thousand parsed bodies, each at
// most a stored body's size.
const bodyCacheLimit = 20000

// stepBodyCache is a small bounded map; when full it is emptied rather than
// tracking use, since a run page re-reads all of a run's bodies together.
type stepBodyCache struct {
	mu sync.Mutex
	m  map[string]gatewayBody
}

var bodyCache = &stepBodyCache{m: map[string]gatewayBody{}}

func (c *stepBodyCache) get(key string) (gatewayBody, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, ok := c.m[key]
	return b, ok
}

func (c *stepBodyCache) put(key string, b gatewayBody) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= bodyCacheLimit {
		c.m = map[string]gatewayBody{}
	}
	c.m[key] = b
}

// readStepBody opens, verifies and parses one stored body.
func readStepBody(dir, runID, digest string) (gatewayBody, bool) {
	bodyFileReads.Add(1)
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
	if isHookBody(raw) {
		var h hookBody
		if err := json.Unmarshal(raw, &h); err != nil {
			return gatewayBody{}, false
		}
		return hookBodyAsGateway(h), true
	}
	var b gatewayBody
	if err := json.Unmarshal(raw, &b); err != nil {
		return gatewayBody{}, false
	}
	return b, true
}

// ---------------------------------------------------------------------------
// RM-273: the hook path's own retained-body shape.
//
// A run recorded through the PreToolUse/PostToolUse hook, rather than the
// gateway, retains the harness's own PostToolUse payload instead of a
// gatewayBody — both shapes are on disk until the hook path is retired
// (E20). hookBody reads the members this package's own RecordStep fields
// need out of that payload; everything else measured across 145 bodies of
// one real run (session_id, transcript_path, cwd, scratchpad_dir,
// prompt_id, permission_mode, agent_id, agent_type, effort, duration_ms) is
// the harness's own bookkeeping, not this record's concern.
// ---------------------------------------------------------------------------

type hookBody struct {
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolUseID     string          `json:"tool_use_id"`
	ToolInput     json.RawMessage `json:"tool_input"`
	ToolResponse  json.RawMessage `json:"tool_response"`
}

// isHookBody reports whether raw looks like the harness's own PostToolUse
// payload rather than a gateway-recorded tool_call body: hook_event_name
// says PostToolUse, or the harness's own tool_name/tool_response members
// are present at all. A gateway body (gatewayBody, above) never carries any
// of these three keys, so this can never misclassify one — raw that fails
// to parse even as the probe below answers false, same as every other
// "cannot read it, must not guess" rule in this file.
func isHookBody(raw []byte) bool {
	var probe struct {
		HookEventName string          `json:"hook_event_name"`
		ToolName      string          `json:"tool_name"`
		ToolResponse  json.RawMessage `json:"tool_response"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	return probe.HookEventName == "PostToolUse" || probe.ToolName != "" || len(probe.ToolResponse) > 0
}

// hookBodyAsGateway maps a harness PostToolUse payload onto the SAME
// fields buildSteps, outcomeOf and summaryOf already read off a
// gateway-recorded tool_call body: tool ← tool_name, input ← tool_input,
// tool_use_id ← tool_use_id, result ← a text rendering of tool_response
// (hookResultText), result_observed ← true — a hook body, unlike a
// gateway one that can go unobserved mid-call, is only ever retained once
// the harness's own PostToolUse fired, which means the tool call already
// finished. is_error is deliberately left unset: see hookOutcomeOf and
// gatewayBody.isError for why outcomeOf reads hookOutcome instead whenever
// hookShape is true.
func hookBodyAsGateway(h hookBody) gatewayBody {
	text := hookResultText(h.ToolName, h.ToolResponse)
	// A Go string always marshals without error; Marshal on this type can
	// only fail for a cyclic value or an unsupported type, neither possible
	// here, so the error is deliberately discarded rather than silently
	// ignored via `_`.
	resultJSON, err := json.Marshal(text)
	if err != nil {
		resultJSON = []byte(`""`)
	}
	return gatewayBody{
		Tool:           h.ToolName,
		ToolUseID:      h.ToolUseID,
		Input:          h.ToolInput,
		ResultObserved: true,
		Result:         resultJSON,
		hookShape:      true,
		hookOutcome:    hookOutcomeOf(h.ToolName, h.ToolResponse),
	}
}

// hookResultText renders a harness tool_response as the plain text
// record.go's own Output shows, "a sensible text rendering" (RM-273): for
// Bash, stdout plus stderr when there is any; otherwise the response's own
// string when it is simply one, else its compact JSON — never losing a
// response this function does not specifically recognise.
func hookResultText(toolName string, raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	if toolName == "Bash" {
		var tr struct {
			Stdout string `json:"stdout"`
			Stderr string `json:"stderr"`
		}
		if json.Unmarshal(raw, &tr) == nil {
			if tr.Stderr == "" {
				return tr.Stdout
			}
			if tr.Stdout == "" {
				return tr.Stderr
			}
			return tr.Stdout + "\n" + tr.Stderr
		}
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	// Not a string, and (for Bash) not an object with stdout/stderr either:
	// render it compactly rather than keep the harness's own formatting
	// (which may itself be pretty-printed) or drop it.
	var v any
	if json.Unmarshal(raw, &v) == nil {
		if compact, err := json.Marshal(v); err == nil {
			return string(compact)
		}
	}
	return string(raw)
}

// hookToolResponseShape is every member hookOutcomeOf reads to decide
// whether a harness tool_response shows success, across the shapes RM-273
// measured: Bash's own interrupted flag, the few tools that answer
// success/message directly, and Edit/Write's own successful shape
// (filePath alongside oldString, structuredPatch or type — present only
// once the write actually happened; nothing in the harness's own payload
// marks an Edit/Write failure any other way).
type hookToolResponseShape struct {
	Interrupted     *bool           `json:"interrupted"`
	Success         *bool           `json:"success"`
	FilePath        string          `json:"filePath"`
	OldString       *string         `json:"oldString"`
	StructuredPatch json.RawMessage `json:"structuredPatch"`
	Type            string          `json:"type"`
	Content         *string         `json:"content"`
}

// hookOutcomeOf is outcomeOf's own counterpart for a hook-shape body: the
// one place RM-273's "never mark a step failed just because a field is
// absent" rule lives. Bash's interrupted flag is the one explicit failure
// signal the harness's own payload carries; absent that, a shape that
// positively shows success (an explicit success:true, or Edit/Write's own
// post-write shape) answers ok, and everything this function cannot read a
// clear signal from — including a bare string response — answers unknown,
// never a guessed failure.
func hookOutcomeOf(toolName string, raw json.RawMessage) RecordOutcome {
	if len(raw) == 0 || string(raw) == "null" {
		return RecordOutcome{Kind: "unknown"}
	}
	var shape hookToolResponseShape
	structured := json.Unmarshal(raw, &shape) == nil

	if toolName == "Bash" {
		// The hook payload carries no exit code, so none is shown: an
		// interrupted command failed, and any other ran to completion.
		if structured && shape.Interrupted != nil && *shape.Interrupted {
			return RecordOutcome{Kind: "error"}
		}
		return RecordOutcome{Kind: "ok"}
	}

	if !structured {
		return RecordOutcome{Kind: "unknown"}
	}
	if shape.Success != nil {
		if *shape.Success {
			return RecordOutcome{Kind: "ok"}
		}
		return RecordOutcome{Kind: "error"}
	}
	if shape.FilePath != "" && (shape.OldString != nil || len(shape.StructuredPatch) > 0 || shape.Type != "" || shape.Content != nil) {
		return RecordOutcome{Kind: "ok"}
	}
	return RecordOutcome{Kind: "unknown"}
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
