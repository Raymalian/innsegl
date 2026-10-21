// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// wireFormat interprets a copy of traffic; the forwarding path owns the
// original bytes. Route selection never sniffs the body for another format.
type wireFormat interface {
	facts([]byte) RequestFacts
	results([]byte) []observedToolResult
	texts([]byte) []string
}

type messagesFormat struct{}

func (messagesFormat) facts(b []byte) RequestFacts           { return parseRequestFacts(b) }
func (messagesFormat) results(b []byte) []observedToolResult { return parseToolResults(b) }
func (messagesFormat) texts(b []byte) []string               { return parseAssistantTexts(b) }

func isResponsesPath(path string) bool {
	return path == "/v1/responses" || path == "/backend-api/codex/responses"
}

func requestFormat(r *http.Request) wireFormat {
	if isResponsesPath(r.URL.Path) {
		return responsesFormat{}
	}
	return messagesFormat{}
}

type wireBodyKey struct{}
type wireBody struct {
	decoded []byte
	problem string
}

// observationBody caches a bounded decoded copy across the witnesses on this
// request. Restoring the original reader also preserves an oversized body.
func observationBody(r *http.Request) wireBody {
	if cached, ok := r.Context().Value(wireBodyKey{}).(wireBody); ok {
		return cached
	}
	result := wireBody{}
	if r.Body != nil {
		original := r.Body
		raw, err := io.ReadAll(io.LimitReader(original, maxRequestFactsBodyBytes+1))
		r.Body = &restoredBody{Reader: io.MultiReader(bytes.NewReader(raw), original), closer: original}
		switch {
		case err != nil:
			result.problem = "request body could not be observed"
		case len(raw) > maxRequestFactsBodyBytes:
			result.problem = "request body exceeds observation limit"
		default:
			switch strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))) {
			case "", "identity":
				result.decoded = raw
			case "zstd":
				decoder, e := zstd.NewReader(bytes.NewReader(raw), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(64<<20))
				if e == nil {
					result.decoded, e = io.ReadAll(io.LimitReader(decoder, maxRequestFactsBodyBytes+1))
					decoder.Close()
				}
				if e != nil || len(result.decoded) > maxRequestFactsBodyBytes {
					result.decoded = nil
					result.problem = "compressed request could not be observed within limits"
				}
			default:
				result.problem = "unsupported request content encoding"
			}
		}
	}
	if result.problem == "" && isResponsesPath(r.URL.Path) {
		if _, err := responseItems(result.decoded); err != nil {
			result.problem = "Responses input shape could not be observed"
		}
	}
	*r = *r.WithContext(context.WithValue(r.Context(), wireBodyKey{}, result))
	return result
}

func observationProblem(ctx context.Context) string {
	if b, ok := ctx.Value(wireBodyKey{}).(wireBody); ok {
		return b.problem
	}
	return ""
}

var errResponsesShape = errors.New("unrecognised Responses input")
