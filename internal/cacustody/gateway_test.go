// SPDX-License-Identifier: Apache-2.0

package cacustody

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// OPS-187..OPS-189 (PROPOSED for doc 07's TC-OPS) — the CA holds no store
// token (#585). The custodian is the CA's signing gateway: it forwards the
// two store calls the CA's KMS client makes, and supplies the current token
// itself, so a new token never has to reach the CA and the CA's container
// holds none.
// ---------------------------------------------------------------------------

// seenRequest is what the fake store was asked.
type seenRequest struct {
	method, path, query, token string
}

// fakeStore records every request and answers 200. echo makes it put the
// token it was sent into its answer, the worst a store could do.
type fakeStore struct {
	mu   sync.Mutex
	seen []seenRequest
	echo bool
}

func (f *fakeStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.seen = append(f.seen, seenRequest{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("X-Vault-Token")})
	echo := f.echo
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if echo {
		w.Header().Set("X-Echo", r.Header.Get("X-Vault-Token"))
		discardWrite(io.WriteString(w, `{"data":{"token":"`+r.Header.Get("X-Vault-Token")+`"}}`))
		return
	}
	discardWrite(io.WriteString(w, `{"data":{"signature":"vault:v1:AAAA"}}`))
}

func (f *fakeStore) requests() []seenRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]seenRequest(nil), f.seen...)
}

func gatewayFixture(t *testing.T, token string) (*Custodian, *fakeStore, *httptest.Server) {
	t.Helper()
	fs := &fakeStore{}
	store := httptest.NewServer(fs)
	t.Cleanup(store.Close)
	c := &Custodian{
		Store:     &Store{Addr: store.URL},
		TokenPath: filepath.Join(t.TempDir(), ".vault-token"),
		Key:       "innsegl-ca",
	}
	if token != "" {
		if err := os.WriteFile(c.TokenPath, []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gw := httptest.NewServer(c.SigningGateway())
	t.Cleanup(gw.Close)
	return c, fs, gw
}

// ask sends what the CA's KMS client sends: its own token header, which is
// the placeholder, never a credential.
func ask(t *testing.T, base, method, path, body string) (int, http.Header, string) {
	t.Helper()
	var rd io.Reader = http.NoBody
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", FulcioPlaceholderToken)
	req.Header.Set("Authorization", "Bearer "+FulcioPlaceholderToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, string(b)
}

// OPS-188 (PROPOSED) — the gateway forwards the CA's two store calls and
// nothing else: sign with the CA key (the hash in the path or not) and read
// the CA key's public half. Everything else is 403 and never reaches the
// store. The token it forwards is the current one, read at each call, and no
// answer carries it.
func TestOPS188TheGatewayForwardsOnlyTheCAsTwoCalls(t *testing.T) {
	const tok = "hvs.the-real-token-1"
	c, fs, gw := gatewayFixture(t, tok)

	allowed := []struct{ method, path string }{
		// Fulcio's KMS client writes with PUT; the store treats POST alike.
		{http.MethodPut, "/v1/transit/sign/innsegl-ca/sha2-256"},
		{http.MethodPost, "/v1/transit/sign/innsegl-ca/sha2-256"},
		{http.MethodPut, "/v1/transit/sign/innsegl-ca"},
		{http.MethodPost, "/v1/transit/sign/innsegl-ca"},
		{http.MethodGet, "/v1/transit/keys/innsegl-ca"},
	}
	for _, a := range allowed {
		code, hdr, body := ask(t, gw.URL, a.method, a.path, `{"input":"aGVsbG8="}`)
		if code != http.StatusOK {
			t.Errorf("%s %s answered %d (%s); the CA needs it", a.method, a.path, code, body)
		}
		if strings.Contains(body, tok) || strings.Contains(headerText(hdr), tok) {
			t.Errorf("%s %s: the answer carries the token", a.method, a.path)
		}
	}
	got := fs.requests()
	if len(got) != len(allowed) {
		t.Fatalf("the store saw %d requests; want %d: %+v", len(got), len(allowed), got)
	}
	for i, r := range got {
		if r.method != allowed[i].method || r.path != allowed[i].path {
			t.Errorf("request %d reached the store as %s %s; want %s %s", i, r.method, r.path, allowed[i].method, allowed[i].path)
		}
		if r.token != tok {
			t.Errorf("request %d reached the store with token %q; want the custodian's current token", i, r.token)
		}
	}

	refused := []struct{ method, path string }{
		{http.MethodGet, "/v1/transit/export/signing-key/innsegl-ca"},
		{http.MethodPost, "/v1/transit/sign/innsegl-ca/sha2-512"},
		{http.MethodPost, "/v1/transit/sign/another/sha2-256"},
		{http.MethodPost, "/v1/transit/sign/innsegl-ca/sha2-256/extra"},
		{http.MethodPost, "/v1/transit/keys/innsegl-ca"},
		{http.MethodDelete, "/v1/transit/keys/innsegl-ca"},
		{http.MethodPost, "/v1/transit/keys/innsegl-ca/rotate"},
		{http.MethodPost, "/v1/transit/keys/innsegl-ca/config"},
		{http.MethodGet, "/v1/transit/keys/another"},
		{http.MethodPost, "/v1/transit/verify/innsegl-ca/sha2-256"},
		{http.MethodGet, "/v1/transit/sign/innsegl-ca/sha2-256"},
		{http.MethodGet, "/v1/auth/token/lookup-self"},
		{http.MethodPost, "/v1/auth/token/create"},
		{http.MethodPost, "/v1/auth/token/revoke-self"},
		{http.MethodPost, "/v1/auth/approle/login"},
		{http.MethodGet, "/v1/sys/seal-status"},
		{http.MethodPost, "/v1/sys/unseal"},
		{http.MethodPost, "/v1/sys/seal"},
		{http.MethodGet, "/v1/sys/storage/raft/snapshot"},
		{http.MethodGet, "/v1//transit/keys/innsegl-ca"},
		{http.MethodGet, "/v1/transit/keys/innsegl-ca/"},
		{http.MethodGet, "/v1/transit/keys/innsegl-ca/../../../sys/seal-status"},
		{http.MethodGet, "/v1/transit/keys/innsegl-ca%2F..%2F..%2F..%2Fsys%2Fseal-status"},
		{http.MethodGet, "/v1/transit/keys/%69nnsegl-ca"},
		{http.MethodGet, "/"},
		{"LIST", "/v1/transit/keys"},
	}
	for _, r := range refused {
		code, hdr, body := ask(t, gw.URL, r.method, r.path, `{"input":"aGVsbG8="}`)
		if code != http.StatusForbidden {
			t.Errorf("%s %s answered %d; want 403", r.method, r.path, code)
		}
		if strings.Contains(body, tok) || strings.Contains(headerText(hdr), tok) {
			t.Errorf("%s %s: the refusal carries the token", r.method, r.path)
		}
	}
	if n := len(fs.requests()); n != len(allowed) {
		t.Fatalf("a refused request reached the store: it saw %d requests, want %d: %+v", n, len(allowed), fs.requests()[len(allowed):])
	}

	// A query string is not the CA's, and never reaches the store.
	if code, _, _ := ask(t, gw.URL, http.MethodGet, "/v1/transit/keys/innsegl-ca?list=true", ""); code != http.StatusOK {
		t.Errorf("a read with a query answered %d", code)
	}
	if r := fs.requests(); r[len(r)-1].query != "" {
		t.Errorf("the query %q reached the store", r[len(r)-1].query)
	}

	// An unlock replaces the token: the next call carries the new one, with
	// nothing restarted.
	const tok2 = "hvs.the-real-token-2"
	if err := os.WriteFile(c.TokenPath, []byte(tok2), 0o600); err != nil {
		t.Fatal(err)
	}
	ask(t, gw.URL, http.MethodPut, "/v1/transit/sign/innsegl-ca/sha2-256", `{"input":"aGVsbG8="}`)
	if r := fs.requests(); r[len(r)-1].token != tok2 {
		t.Errorf("after the token changed the store saw %q; want the new token", r[len(r)-1].token)
	}

	// A store that echoes the token: the answer is withheld, not passed on.
	fs.mu.Lock()
	fs.echo = true
	fs.mu.Unlock()
	code, hdr, body := ask(t, gw.URL, http.MethodGet, "/v1/transit/keys/innsegl-ca", "")
	if strings.Contains(body, tok2) || strings.Contains(headerText(hdr), tok2) {
		t.Fatalf("a store answer that carried the token was passed to the CA (%d)", code)
	}
	if code != http.StatusBadGateway {
		t.Errorf("a store answer that carried the token answered %d; want 502", code)
	}
}

// OPS-188 (PROPOSED) — no token yet is an answer, not a forward: the store
// would see a request with no credential, and the CA a confusing 403.
func TestOPS188NoTokenIsServiceUnavailable(t *testing.T) {
	_, fs, gw := gatewayFixture(t, "")
	code, _, body := ask(t, gw.URL, http.MethodGet, "/v1/transit/keys/innsegl-ca", "")
	if code != http.StatusServiceUnavailable {
		t.Errorf("with no token the gateway answered %d (%s); want 503", code, body)
	}
	if len(fs.requests()) != 0 {
		t.Error("with no token a request reached the store")
	}
}

// OPS-188 (PROPOSED) — a sign request is one digest: a body far beyond that
// is refused, and never reaches the store.
func TestOPS188AnOversizedRequestIsRefused(t *testing.T) {
	_, fs, gw := gatewayFixture(t, "hvs.tok")
	code, _, _ := ask(t, gw.URL, http.MethodPut, "/v1/transit/sign/innsegl-ca/sha2-256",
		`{"input":"`+strings.Repeat("A", maxGatewayBody)+`"}`)
	if code != http.StatusBadRequest || len(fs.requests()) != 0 {
		t.Errorf("an oversized sign request answered %d and reached the store %d time(s); want 400 and never",
			code, len(fs.requests()))
	}
}

// OPS-188 (PROPOSED) — a store that does not answer is a 502 that says so.
func TestOPS188AStoreThatDoesNotAnswerIsBadGateway(t *testing.T) {
	c, _, gw := gatewayFixture(t, "hvs.tok")
	c.Store.Addr = "http://127.0.0.1:1"
	code, _, body := ask(t, gw.URL, http.MethodGet, "/v1/transit/keys/innsegl-ca", "")
	if code != http.StatusBadGateway || strings.Contains(body, "hvs.tok") {
		t.Errorf("an unreachable store answered %d (%s); want 502 without the token", code, body)
	}
}

func headerText(h http.Header) string {
	var b strings.Builder
	for k, vs := range h {
		b.WriteString(k + ": " + strings.Join(vs, ",") + "\n")
	}
	return b.String()
}

// fulcioStandIn is the CA as its KMS client behaves: it is configured once,
// at start, with the placeholder token and the gateway's address, and never
// again. It reads the CA key's public half once, as Fulcio does at start,
// and checks every signature against it.
type fulcioStandIn struct {
	base string
	pub  *ecdsa.PublicKey
}

func startFulcioStandIn(t *testing.T, base string) *fulcioStandIn {
	t.Helper()
	code, _, body := ask(t, base, http.MethodGet, "/v1/transit/keys/innsegl-ca", "")
	if code != http.StatusOK {
		t.Fatalf("the CA could not read its key through the gateway: %d %s", code, body)
	}
	var out struct {
		Data struct {
			Keys map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	k, ok := out.Data.Keys["1"]
	if !ok {
		t.Fatalf("the key has no version 1: %s", body)
	}
	block, _ := pem.Decode([]byte(k.PublicKey))
	if block == nil {
		t.Fatalf("the public key is not PEM: %q", k.PublicKey)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("the CA key is a %T", pub)
	}
	return &fulcioStandIn{base: base, pub: ec}
}

// sign asks for one signature the way Fulcio does, PUT
// transit/sign/<key>/sha2-256 over a prehashed digest, and answers whether
// a valid signature came back.
func (f *fulcioStandIn) sign(t *testing.T) (bool, string) {
	t.Helper()
	digest := sha256.Sum256([]byte("a certificate to be"))
	body := `{"input":"` + base64.StdEncoding.EncodeToString(digest[:]) +
		`","prehashed":true,"marshaling_algorithm":"asn1"}`
	code, _, resp := ask(t, f.base, http.MethodPut, "/v1/transit/sign/innsegl-ca/sha2-256", body)
	if code != http.StatusOK {
		return false, resp
	}
	var out struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(resp), &out); err != nil {
		return false, err.Error()
	}
	parts := strings.SplitN(out.Data.Signature, ":", 3)
	if len(parts) != 3 {
		return false, "not a store signature: " + out.Data.Signature
	}
	sig, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false, err.Error()
	}
	return ecdsa.VerifyASN1(f.pub, digest[:], sig), resp
}

// OPS-189 (PROPOSED) — the incident's second path (L2): the store restarts
// alone, sealed, while the CA keeps running. The operator's unlock logs the
// CA in again and revokes the token from before. The CA, configured once and
// never restarted, signs again at once: it never held the token the unlock
// revoked.
func TestOPS189AStoreRestartAndUnlockNeedNoCARestart(t *testing.T) {
	f := newCustodian(t)
	ctx := context.Background()
	if err := f.c.Init(ctx); err != nil {
		t.Fatal(err)
	}
	m := f.material(t)
	gw := httptest.NewServer(f.c.SigningGateway())
	t.Cleanup(gw.Close)

	ca := startFulcioStandIn(t, gw.URL)
	if ok, why := ca.sign(t); !ok {
		t.Fatalf("the CA could not sign through the gateway: %s", why)
	}
	before := readToken(t, f.c.TokenPath)

	f.store.restart(t)
	if ok, _ := ca.sign(t); ok {
		t.Fatal("a sealed store signed")
	}
	if err := f.c.Unlock(ctx, m); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := f.c.Store.RenewSelf(ctx, before); err == nil {
		t.Fatal("the unlock did not revoke the token from before the restart; this test would prove nothing")
	}
	if ok, why := ca.sign(t); !ok {
		t.Fatalf("after the store restarted and was unlocked, the CA, never restarted, cannot sign: %s", why)
	}
}
