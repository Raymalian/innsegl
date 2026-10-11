// SPDX-License-Identifier: Apache-2.0

package cacustody

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

// FulcioPlaceholderToken is the token the CA's KMS client is configured
// with under custody (#585). It is not a credential: the pinned client
// refuses to start without some token ("no Vault token found in env,
// helper, or ~/.vault-token"), and the signing gateway drops whatever token
// a request carries and supplies the current one itself. The store has never
// issued this string and never will.
const FulcioPlaceholderToken = "innsegl-ca-custodian-supplies-the-token" //nolint:gosec // G101: a fixed non-credential, by design

// maxGatewayBody bounds what the gateway reads from the CA and from the
// store. A sign request is one digest; a key read is one public key.
const maxGatewayBody = 64 << 10

// gatewayTimeout bounds one forwarded call.
const gatewayTimeout = 30 * time.Second

// SigningGateway is the CA's way to the store (#585). It forwards exactly the
// CA's two calls, as the pinned KMS client makes them:
//
//	PUT or POST /v1/transit/sign/<key>[/sha2-256]   sign with the CA key
//	GET         /v1/transit/keys/<key>              the CA key's public half
//
// with the CA's current token, read from TokenPath at each call: an unlock
// that replaces the token reaches the CA's next call with nothing restarted,
// and the token it revokes was never in the CA. Every other method or path is
// 403 and reaches nothing. No answer carries the token: one that would is
// withheld (502).
func (c *Custodian) SigningGateway() http.Handler {
	client := c.Store.HTTP
	if client == nil {
		client = &http.Client{Timeout: gatewayTimeout}
	}
	sign := "/v1/transit/sign/" + c.Key
	allowed := map[string][]string{
		sign:                        {http.MethodPut, http.MethodPost},
		sign + "/sha2-256":          {http.MethodPut, http.MethodPost},
		"/v1/transit/keys/" + c.Key: {http.MethodGet},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The path as sent: an escaped or doubled path is not one of the
		// two, whatever it decodes to.
		path := r.URL.EscapedPath()
		methods, ok := allowed[path]
		if !ok || r.URL.RawPath != "" || !slices.Contains(methods, r.Method) {
			writeError(w, http.StatusForbidden, "ca custody: the CA's gateway forwards only its sign and key-read calls")
			return
		}
		tok, err := os.ReadFile(c.TokenPath)
		if err != nil || len(tok) == 0 {
			writeError(w, http.StatusServiceUnavailable,
				"ca custody: the CA has no token: the store is sealed or has not been unlocked since it started")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxGatewayBody+1))
		if err != nil || len(body) > maxGatewayBody {
			writeError(w, http.StatusBadRequest, "ca custody: the request is not a sign or key-read call")
			return
		}
		code, header, answer, err := c.forward(r.Context(), client, r.Method, path, body, string(tok))
		if err != nil {
			c.logf("the CA's gateway: the store did not answer: %v", err)
			writeError(w, http.StatusBadGateway, "ca custody: the store did not answer")
			return
		}
		if bytes.Contains(answer, tok) || strings.Contains(headerValues(header), string(tok)) {
			c.logf("the CA's gateway: withheld a store answer that carried the CA's token")
			writeError(w, http.StatusBadGateway, "ca custody: the store's answer was withheld")
			return
		}
		if ct := header.Get("Content-Type"); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.WriteHeader(code)
		discardWrite(w.Write(answer)) //nolint:gosec // G705: the store's JSON answer to the CA, never rendered as a page
	})
}

// forward makes one call to the store with the CA's token, and nothing of
// the caller's but the method, the path and the body.
func (c *Custodian) forward(ctx context.Context, client *http.Client, method, path string, body []byte,
	token string) (int, http.Header, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, gatewayTimeout)
	defer cancel()
	var rd io.Reader = http.NoBody
	if len(body) > 0 {
		rd = bytes.NewReader(body)
	}
	//nolint:gosec // G704: the store's configured address and one of three allowlisted paths
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Store.Addr, "/")+path, rd)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("X-Vault-Token", token)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req) //nolint:gosec // G704: see the request above
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { discardClose(resp.Body.Close()) }()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, maxGatewayBody))
	if err != nil {
		return 0, nil, nil, err
	}
	return resp.StatusCode, resp.Header, answer, nil
}

func headerValues(h http.Header) string {
	var b strings.Builder
	for _, vs := range h {
		for _, v := range vs {
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
