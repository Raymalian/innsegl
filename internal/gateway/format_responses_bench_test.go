// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// BenchmarkResponsesObservation measures all request consumers together,
// including restoring and draining the original wire body.
func BenchmarkResponsesObservation(b *testing.B) {
	for _, size := range []int{1024, 64 << 10, 1 << 20} {
		for _, compressed := range []bool{false, true} {
			b.Run(fmt.Sprintf("bytes=%d/zstd=%v", size, compressed), func(b *testing.B) {
				body, err := json.Marshal(map[string]any{"input": []any{map[string]any{"role": "user", "content": strings.Repeat("a", size)}}})
				if err != nil {
					b.Fatal(err)
				}
				wire := body
				if compressed {
					encoder, e := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
					if e != nil {
						b.Fatal(e)
					}
					wire = encoder.EncodeAll(body, nil)
					encoder.Close()
				}
				b.ReportAllocs()
				b.SetBytes(int64(len(body)))
				b.ResetTimer()
				for b.Loop() {
					r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/responses", bytes.NewReader(wire))
					if compressed {
						r.Header.Set("Content-Encoding", "zstd")
					}
					if f := ExtractRequestFacts(r); len(f.Brief) != size {
						b.Fatal("brief lost")
					}
					extractToolResults(r)
					extractAssistantTexts(r)
					if _, e := io.Copy(io.Discard, r.Body); e != nil {
						b.Fatal(e)
					}
					if e := r.Body.Close(); e != nil {
						b.Fatal(e)
					}
				}
			})
		}
	}
}

func BenchmarkResponsesSSE(b *testing.B) {
	event := []byte("data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"call_id\":\"call_bench\",\"name\":\"read\",\"arguments\":\"{}\"}}\n\n")
	for _, chunk := range []int{1, 128, len(event)} {
		b.Run(fmt.Sprintf("chunk=%d", chunk), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(event)))
			for b.Loop() {
				calls := 0
				observer := newResponsesInterpreter(ToolUseObserverFunc(func(ToolUse) { calls++ }))
				for offset := 0; offset < len(event); offset += chunk {
					if _, err := observer.Write(event[offset:min(offset+chunk, len(event))]); err != nil {
						b.Fatal(err)
					}
				}
				if calls != 1 {
					b.Fatal("call lost")
				}
			}
		})
	}
}

// BenchmarkResponsesHTTP includes the real route, harness guard, TLS upstream,
// streamed reply copy and call observer. Identity/ledger services are excluded.
func BenchmarkResponsesHTTP(b *testing.B) {
	event := "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"call_id\":\"call_bench\",\"name\":\"read\",\"arguments\":\"{}\"}}\n\n"
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			b.Error(err)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if _, err := io.WriteString(w, event); err != nil {
			b.Error(err)
		}
	}))
	defer provider.Close()
	upstream, err := NewUpstream(provider.URL, provider.Client())
	if err != nil {
		b.Fatal(err)
	}
	var calls atomic.Int64
	// Isolate transport cost from the deliberately low production runaway limit.
	limiter, limitErr := NewSessionRateLimiter(SessionRateLimit{Rate: 1000000, Burst: 1000000})
	if limitErr != nil {
		b.Fatal(limitErr)
	}
	proxy := &Proxy{Guards: Guards(limiter, nil), Upstream: upstream, ToolUse: ToolUseObserverFunc(func(ToolUse) { calls.Add(1) })}
	front := httptest.NewServer(ResponsesRoutes(proxy, upstream, upstream))
	defer front.Close()
	client := front.Client()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req, e := http.NewRequestWithContext(context.Background(), http.MethodPost, front.URL+"/backend-api/codex/responses", strings.NewReader(`{"input":"benchmark"}`))
		if e != nil {
			b.Fatal(e)
		}
		req.Header.Set("User-Agent", "codex_exec/0.163.0")
		req.Header.Set("Session-Id", "550e8400-e29b-41d4-a716-446655440000")
		req.Header.Set("Thread-Id", "550e8400-e29b-41d4-a716-446655440000")
		resp, e := client.Do(req)
		if e != nil {
			b.Fatal(e)
		}
		if _, e = io.Copy(io.Discard, resp.Body); e != nil {
			b.Fatal(e)
		}
		if e = resp.Body.Close(); e != nil {
			b.Fatal(e)
		}
		if resp.StatusCode != http.StatusOK {
			b.Fatalf("status %d", resp.StatusCode)
		}
	}
	b.StopTimer()
	if calls.Load() != int64(b.N) {
		b.Fatalf("calls %d requests %d", calls.Load(), b.N)
	}
}
