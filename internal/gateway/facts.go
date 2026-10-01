// SPDX-License-Identifier: Apache-2.0

package gateway

// facts.go is #377 (RM-232): RequestFacts extraction (lifecycle_contract.go)
// -- what one model request says about its agent, read ONCE from the
// request body and shared through the request's context by every later
// guard and observer, exactly as harness.go's Identification already is
// (WithIdentification). Nothing downstream of ExtractRequestFacts reads the
// body a second way.
//
// # Shape read
//
// The Anthropic Messages API request body: a "messages" array, each entry a
// role and a content field that is either a bare string or an array of
// typed content blocks. Claude Code resends the whole conversation history
// on every request (docs/decisions/model-gateway-spike.md: "every request
// resends the whole history"), so:
//
//   - Brief is the FIRST user message's text, with every <system-reminder>
//     block stripped out -- the harness wraps a subagent's own spawn
//     prompt in reminders too, and stripping them is what recovers the
//     byte-for-byte original text ADR-0058 decision 3's exact-equality
//     link needs (tree.go).
//   - WorkingDirectory is NOT read from the body: the conversation's prose
//     is not a structured channel, and reading it broke whenever the
//     harness moved the statement (a session resumed after a summary
//     states it only mid-conversation). The identity guard sets it from
//     the session hook's own report (workspaceregistry.go).
//   - FirstAssistant is the first assistant message's content, canonically
//     encoded (internal/event.Canonicalize, RFC 8785) so two requests
//     carrying the same first turn -- the same conversation, replayed --
//     fingerprint identically (ComputeFingerprint, below).
//   - ToolResultIDs is every tool_result block's tool_use_id, in the order
//     the messages carrying them appear.
//
// # Bounded, read once, and never a reason to refuse
//
// maxRequestFactsBodyBytes bounds how much of the body this extractor ever
// holds in memory, the same shape sse.go's own buffers are bounded (GW-014,
// #405). Past it, RequestFacts is left entirely empty -- this package never
// guesses at a partial brief -- and the request is still forwarded exactly
// as it arrived: deciding whether an agent may proceed without usable facts
// is the identity guard's job (E15, #380), never this file's. The body
// itself is always restored for forwarding, whether or not it was over the
// bound, so GW-001's byte-for-byte contract holds regardless of what this
// extractor found.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"innsegl.dev/innsegl/internal/event"
)

const (
	// maxRequestFactsBodyBytes bounds how much of one request's body this
	// extractor reads looking for its facts. Claude Code resends the whole
	// conversation history on every request, so a long-running session's
	// body grows well past what a single tool call's input ever does
	// (sse.go's maxToolUseInputBytes is 8 MiB, for ONE block); this is sized
	// generously above that for a whole request's history while still
	// bounding memory the same way -- past it, RequestFacts is left empty
	// rather than reassembled from a prefix and guessed at.
	maxRequestFactsBodyBytes = 32 << 20 // 32 MiB

	systemReminderOpen  = "<system-reminder>"
	systemReminderClose = "</system-reminder>"
)

// ExtractRequestFacts reads r's body ONCE, bounded by
// maxRequestFactsBodyBytes, and returns the RequestFacts it found -- empty,
// never an error, if the body is absent, malformed, not JSON, or over the
// bound. r.Body is always replaced with a fresh reader over exactly the
// same bytes before this function returns, so the request forwards
// unchanged (GW-001) no matter what was found. r itself is not otherwise
// modified.
func ExtractRequestFacts(r *http.Request) RequestFacts {
	if r.Body == nil {
		return RequestFacts{}
	}

	orig := r.Body
	limited := io.LimitReader(orig, maxRequestFactsBodyBytes+1)
	buf, readErr := io.ReadAll(limited)

	// Restored regardless of what follows: the bytes already read, then
	// whatever is still unread on the original body -- read once, from the
	// wire's own point of view, whether this function or the eventual
	// forwarding copy is the one to read a given byte.
	r.Body = &restoredBody{Reader: io.MultiReader(bytes.NewReader(buf), orig), closer: orig}

	if readErr != nil || len(buf) > maxRequestFactsBodyBytes {
		return RequestFacts{}
	}
	return parseRequestFacts(buf)
}

// restoredBody is an io.ReadCloser that reads from Reader (a replay of what
// ExtractRequestFacts already consumed, followed by whatever the original
// body had left) but closes the ORIGINAL body -- never a no-op close --
// so the connection this request arrived on is released exactly as it
// would have been had this extractor never run.
type restoredBody struct {
	io.Reader
	closer io.Closer
}

func (b *restoredBody) Close() error { return b.closer.Close() }

// rawMessage is one Anthropic Messages API message, read loosely: Content
// is decoded further by contentBlocks, which accepts either shape the API
// allows.
type rawMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// rawContentBlock is one content block. Only the fields this extractor
// uses are read; an unrecognised block type is kept (for FirstAssistant's
// canonical encoding, which re-serializes the whole content value) but
// contributes nothing to Brief or ToolResultIDs.
type rawContentBlock struct {
	Type      string `json:"type"`
	Text      string `json:"text"`
	ToolUseID string `json:"tool_use_id"`
}

// contentBlocks decodes one message's content field, which the Anthropic
// Messages API allows as either a bare string (one implicit text block) or
// an array of typed content blocks. ok is false if content is neither --
// malformed input this extractor does not guess at.
func contentBlocks(content json.RawMessage) (blocks []rawContentBlock, ok bool) {
	var asString string
	if err := json.Unmarshal(content, &asString); err == nil {
		return []rawContentBlock{{Type: "text", Text: asString}}, true
	}
	var asBlocks []rawContentBlock
	if err := json.Unmarshal(content, &asBlocks); err == nil {
		return asBlocks, true
	}
	return nil, false
}

// joinText concatenates every text-type block's own text, in order. Used
// BEFORE reminder-stripping, so a caller can still search the raw text for
// the environment statement that lives inside a <system-reminder> block.
func joinText(blocks []rawContentBlock) string {
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" && b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n\n")
}

// parseRequestFacts is ExtractRequestFacts' pure core: buf in, RequestFacts
// out, no I/O. A body that is not a JSON object, or whose shape this
// extractor does not recognise, yields an empty RequestFacts rather than an
// error -- the same "drop what cannot be parsed" posture sse.go's own
// scanner takes.
func parseRequestFacts(buf []byte) RequestFacts {
	var body struct {
		Messages []rawMessage `json:"messages"`
	}
	if err := json.Unmarshal(buf, &body); err != nil {
		return RequestFacts{}
	}

	var facts RequestFacts

	for _, m := range body.Messages {
		if m.Role != "user" {
			continue
		}
		if blocks, ok := contentBlocks(m.Content); ok {
			facts.Brief = stripSystemReminders(joinText(blocks))
		}
		break // only the FIRST user message names the brief.
	}

	for _, m := range body.Messages {
		if m.Role != "assistant" {
			continue
		}
		if canon, ok := canonicalizeContent(m.Content); ok {
			facts.FirstAssistant = canon
		}
		break // only the FIRST assistant turn.
	}

	for _, m := range body.Messages {
		blocks, ok := contentBlocks(m.Content)
		if !ok {
			continue
		}
		for _, b := range blocks {
			if b.Type == "tool_result" && b.ToolUseID != "" {
				facts.ToolResultIDs = append(facts.ToolResultIDs, b.ToolUseID)
			}
		}
	}

	return facts
}

// canonicalizeContent decodes content generically and re-encodes it with
// internal/event.Canonicalize (RFC 8785), so the identical first assistant
// turn always produces the identical bytes regardless of how the harness
// happened to order or space its own JSON.
func canonicalizeContent(content json.RawMessage) ([]byte, bool) {
	var v any
	if err := json.Unmarshal(content, &v); err != nil {
		return nil, false
	}
	canon, err := event.Canonicalize(v)
	if err != nil {
		return nil, false
	}
	return canon, true
}

// stripSystemReminders removes every <system-reminder>...</system-reminder>
// span from s, then trims what is left. An opening tag with no matching
// close is dropped along with everything after it, rather than guessed at
// -- the same "abandon rather than reassemble a partial fragment" posture
// sse.go's scanner already takes on its own malformed input.
func stripSystemReminders(s string) string {
	for {
		start := strings.Index(s, systemReminderOpen)
		if start < 0 {
			break
		}
		closeIdx := strings.Index(s[start:], systemReminderClose)
		if closeIdx < 0 {
			s = s[:start]
			break
		}
		end := start + closeIdx + len(systemReminderClose)
		s = s[:start] + s[end:]
	}
	return strings.TrimSpace(s)
}

// ---------------------------------------------------------------------------
// Context helpers -- the same shape harness.go's WithIdentification and
// IdentificationFromContext already give Identification.
// ---------------------------------------------------------------------------

// requestFactsContextKey is an unexported type so a value stored under it
// can never collide with a context key another package defines.
type requestFactsContextKey struct{}

// WithRequestFacts returns a copy of ctx carrying facts, retrievable with
// RequestFactsFromContext.
func WithRequestFacts(ctx context.Context, facts RequestFacts) context.Context {
	return context.WithValue(ctx, requestFactsContextKey{}, facts)
}

// RequestFactsFromContext returns the RequestFacts a RequestFactsGuard
// attached to ctx, and whether one was found.
func RequestFactsFromContext(ctx context.Context) (RequestFacts, bool) {
	facts, ok := ctx.Value(requestFactsContextKey{}).(RequestFacts)
	return facts, ok
}

// ---------------------------------------------------------------------------
// The Guard.
// ---------------------------------------------------------------------------

// RequestFactsGuard extracts RequestFacts once per request and attaches
// them to the request's context before returning it. It never refuses:
// whatever ExtractRequestFacts found -- including nothing at all -- is
// forwarded to the next Guard or observer, and to the upstream, exactly the
// same way either way. Deciding whether a request may proceed without
// usable facts is the identity guard's job (E15, #380), not this one's; add
// this guard to the chain Guards builds (guard.go), never wire it in here.
type RequestFactsGuard struct{}

// NewRequestFactsGuard returns the request-facts guard.
func NewRequestFactsGuard() *RequestFactsGuard { return &RequestFactsGuard{} }

// Check implements Guard.
func (*RequestFactsGuard) Check(r *http.Request) (*http.Request, *Refusal) {
	facts := ExtractRequestFacts(r)
	return r.WithContext(WithRequestFacts(r.Context(), facts)), nil
}

// ---------------------------------------------------------------------------
// Fingerprint (lifecycle_contract.go).
// ---------------------------------------------------------------------------

// ComputeFingerprint derives facts' Fingerprint (ADR-0058 decision 4):
// sha256 over Brief and FirstAssistant, empty until FirstAssistant is
// non-empty -- Fingerprint's own doc comment: "empty until the conversation
// has a first assistant turn". Brief alone is not enough to fingerprint a
// conversation: two different conversations can share an opening line, and
// only diverge once the model has answered.
func ComputeFingerprint(facts RequestFacts) Fingerprint {
	if len(facts.FirstAssistant) == 0 {
		return ""
	}
	h := sha256.New()
	writeFingerprintPart(h, []byte(facts.Brief))
	writeFingerprintPart(h, facts.FirstAssistant)
	return Fingerprint(hex.EncodeToString(h.Sum(nil)))
}

// writeFingerprintPart writes p to h prefixed by its own length (8 bytes,
// big-endian), so two parts hashed back to back can never be confused with
// a different split of the same total bytes.
func writeFingerprintPart(h io.Writer, p []byte) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(p)))
	// Discarded deliberately, the same named-discard pattern proxy.go's own
	// discardWriteError uses: hash.Hash.Write never errors (io.Writer's own
	// doc comment), so there is nothing a caller here could do with one.
	discardWriteError(h.Write(lenBuf[:]))
	discardWriteError(h.Write(p))
}
