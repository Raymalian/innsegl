// SPDX-License-Identifier: Apache-2.0

package cacustody

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
)

// The custodian's own routes. Only the core reaches them: the custodian
// listens on a network whose other member is the core (ADR-0076).
const (
	PathStatus   = "/status"
	PathMaterial = "/material"
	PathUnlock   = "/unlock"
)

// MaterialFile is the unlock material's ciphertext, in the custodian's
// directory. It is on the trust root's list: losing it loses the store.
const MaterialFile = "unlock.age"

// SnapshotFile is the store's own consistent snapshot, in the custodian's
// snapshot directory (ADR-0076). The trust-key backup carries it.
const SnapshotFile = "store.snap"

// maxUnlockBody bounds what an unlock may send. The material is three short
// strings; anything near this size is not material.
const maxUnlockBody = 64 << 10

// ErrIncomplete is answered for material with a field missing.
var ErrIncomplete = errors.New("ca custody: the unlock material is incomplete")

// errNotAccepted is what an unlock with the wrong material answers. It never
// says which part was wrong and never repeats any of it.
var errNotAccepted = errors.New("ca custody: the unlock material was not accepted")

// Status is the custodian's answer to "can the CA sign".
type Status struct {
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
	// CanSign is the answer, tested rather than assumed: the store is
	// unsealed, the CA's token is alive, it reads the CA key, and that key is
	// the one in the certificate the CA presents.
	CanSign bool `json:"can_sign"`
	// Reason says why CanSign is false. Empty when it is true.
	Reason string `json:"reason,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Custodian holds the CA key store's custody on the core: it initialises the
// store once, keeps the unlock material as ciphertext, writes the CA's token
// where the CA reads it, renews that token, and unlocks the store with
// material the operator's machine sends back.
type Custodian struct {
	Store *Store
	// Dir holds MaterialFile, ciphertext only.
	Dir string
	// TokenPath is the CA's token: a file on memory-backed storage the CA
	// mounts as its home, read by its KMS client as ~/.vault-token.
	TokenPath string
	// Key is the transit key the CA signs with.
	Key string
	// ChainPath is the certificate chain the CA presents (chain.pem). Status
	// requires the store's key to be the one in its first certificate. Empty
	// skips that check.
	ChainPath string
	// Recipients are who can open the unlock material: the operator's.
	Recipients []age.Recipient
	// Log receives one line per event, never a secret.
	Log io.Writer

	mu sync.Mutex
	// snapshotToken takes the store's snapshot. Memory only: a restart
	// leaves it empty until the next unlock, when the store is sealed anyway.
	snapshotToken string
}

// Seal encrypts m to recipients.
func Seal(m Material, recipients []age.Recipient) ([]byte, error) {
	if !m.Valid() {
		return nil, ErrIncomplete
	}
	if len(recipients) == 0 {
		return nil, errors.New("ca custody: no recipient to seal the unlock material to")
	}
	plain, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, recipients...)
	if err != nil {
		return nil, fmt.Errorf("ca custody: sealing the unlock material: %w", err)
	}
	if _, err := w.Write(plain); err != nil {
		return nil, fmt.Errorf("ca custody: sealing the unlock material: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("ca custody: sealing the unlock material: %w", err)
	}
	return out.Bytes(), nil
}

// Open decrypts sealed material. A Secure Enclave identity asks for Touch ID.
func Open(sealed []byte, identities []age.Identity) (Material, error) {
	r, err := age.Decrypt(bytes.NewReader(sealed), identities...)
	if err != nil {
		return Material{}, fmt.Errorf("ca custody: opening the unlock material: %w", err)
	}
	var m Material
	if err := json.NewDecoder(io.LimitReader(r, maxUnlockBody)).Decode(&m); err != nil {
		return Material{}, fmt.Errorf("ca custody: the unlock material is not readable: %w", err)
	}
	if !m.Valid() {
		return Material{}, ErrIncomplete
	}
	return m, nil
}

// Init initialises a store that has never been initialised: unlocks it,
// provisions the CA's key, policy and role, seals the material to the
// recipients, logs the CA in, and revokes the root token. Nothing it leaves
// behind is plaintext but the CA's own token.
func (c *Custodian) Init(ctx context.Context) error {
	st, err := c.Store.SealStatus(ctx)
	if err != nil {
		return err
	}
	if st.Initialized {
		return errors.New("ca custody: the store is already initialised; its material is " +
			c.materialPath() + ", and the operator's machine unlocks it")
	}
	if len(c.Recipients) == 0 {
		return errors.New("ca custody: no recipient: the unlock material would be readable by nobody")
	}
	unseal, root, err := c.Store.Init(ctx)
	if err != nil {
		return err
	}
	if err = c.Store.Unseal(ctx, unseal); err != nil {
		return err
	}
	m, err := c.Store.Provision(ctx, root, c.Key)
	if err != nil {
		return err
	}
	m.UnsealKey = unseal
	sealed, err := Seal(m, c.Recipients)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.materialPath()), 0o700); err != nil {
		return err
	}
	if err := writeAtomic(c.materialPath(), sealed); err != nil {
		return fmt.Errorf("ca custody: keeping the unlock material: %w. The store is initialised "+
			"and its material is lost; remove the store's volume and init again", err)
	}
	if err := c.login(ctx, m); err != nil {
		return err
	}
	if err := c.Store.RevokeSelf(ctx, root); err != nil {
		return fmt.Errorf("ca custody: revoking the root token: %w", err)
	}
	if err := c.Snapshot(ctx); err != nil {
		return fmt.Errorf("ca custody: the first snapshot: %w", err)
	}
	c.logf("initialised: the CA key %q is in the store, the unlock material is sealed to %d recipient(s), and the root token is revoked",
		c.Key, len(c.Recipients))
	return nil
}

// Material answers the sealed unlock material.
func (c *Custodian) Material() ([]byte, error) {
	b, err := os.ReadFile(c.materialPath())
	if err != nil {
		return nil, fmt.Errorf("ca custody: the unlock material: %w", err)
	}
	return b, nil
}

// Status reports whether the CA can sign, by testing each thing signing
// needs, in order: the store unsealed, the CA's token alive, the CA key
// readable with that token, and that key the one in the certificate the CA
// presents. It makes no signature. It is computed on every call, so a token
// the store stops accepting shows at the next call (#582).
func (c *Custodian) Status(ctx context.Context) Status {
	var out Status
	st, err := c.Store.SealStatus(ctx)
	if err != nil {
		out.Error = err.Error()
		out.Sealed = true
		out.Reason = "the store is not answering"
		return out
	}
	out.Initialized, out.Sealed = st.Initialized, st.Sealed
	switch {
	case !st.Initialized:
		out.Reason = "the store is not initialised"
	case st.Sealed:
		out.Reason = "the store is sealed; the operator's machine unlocks it"
	default:
		out.Reason = c.signingProblem(ctx)
		out.CanSign = out.Reason == ""
	}
	return out
}

// signingProblem answers why an unsealed store's CA cannot sign, or "".
func (c *Custodian) signingProblem(ctx context.Context) string {
	tok, err := os.ReadFile(c.TokenPath)
	if err != nil || len(tok) == 0 {
		return "the CA has no token yet"
	}
	ttl, err := c.Store.TTL(ctx, string(tok))
	switch {
	case errors.Is(err, ErrRefused):
		return "the CA's token was refused by the store"
	case err != nil:
		return "the store did not answer for the CA's token: " + err.Error()
	case ttl <= 0:
		return "the CA's token has expired"
	}
	pub, err := c.Store.PublicKey(ctx, string(tok), c.Key)
	switch {
	case errors.Is(err, ErrRefused):
		return fmt.Sprintf("the CA's token cannot read the CA key %q", c.Key)
	case err != nil:
		return fmt.Sprintf("reading the CA key %q: %v", c.Key, err)
	}
	return c.chainProblem(pub)
}

// chainProblem compares the store's key, as PEM, with the first certificate
// of the chain the CA presents: the check Fulcio makes at start, made
// continuously. No chain yet is no problem: the bootstrap mints it once the
// custodian is ready.
func (c *Custodian) chainProblem(storePEM string) string {
	if c.ChainPath == "" {
		return ""
	}
	chain, err := os.ReadFile(c.ChainPath)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		return fmt.Sprintf("the CA's certificate chain %s: %v", c.ChainPath, err)
	}
	cert, err := firstCertificate(chain)
	if err != nil {
		return fmt.Sprintf("the CA's certificate chain %s: %v", c.ChainPath, err)
	}
	pub, err := parsePublicKeyPEM(storePEM)
	if err != nil {
		return fmt.Sprintf("the CA key %q: %v", c.Key, err)
	}
	if !pub.Equal(cert.PublicKey) {
		return fmt.Sprintf("the CA key %q in the store is not the key in the certificate the CA presents (%s): "+
			DriftedPhrase+", and Fulcio refuses to start on them", c.Key, c.ChainPath)
	}
	return ""
}

// DriftedPhrase is in the reason when the store's key is not the key in the
// chain the CA presents. Nothing on the operator's machine repairs that: an
// unlock does not change a key, and a trust root is never "fixed" (#588).
const DriftedPhrase = "they have drifted"

func firstCertificate(chain []byte) (*x509.Certificate, error) {
	for rest := chain; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("holds no certificate")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}

func parsePublicKeyPEM(s string) (interface{ Equal(crypto.PublicKey) bool }, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("the store's public key is not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	eq, ok := pub.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return nil, fmt.Errorf("the store's public key is a %T", pub)
	}
	return eq, nil
}

// Unlock unseals the store with m, logs the CA in with m, and revokes the
// CA's previous token. Wrong material leaves the CA's token as it was.
func (c *Custodian) Unlock(ctx context.Context, m Material) error {
	if !m.Valid() {
		return ErrIncomplete
	}
	st, err := c.Store.SealStatus(ctx)
	if err != nil {
		return err
	}
	if !st.Initialized {
		return errors.New("ca custody: the store is not initialised; run the custodian's init")
	}
	if st.Sealed {
		if err := c.Store.Unseal(ctx, m.UnsealKey); err != nil {
			c.logf("unlock refused: the unseal key was not accepted")
			if errors.Is(err, ErrSealed) || strings.Contains(err.Error(), "answered 400") {
				return errNotAccepted
			}
			return err
		}
	}
	if err := c.login(ctx, m); err != nil {
		c.logf("unlock refused: the CA could not log in")
		if errors.Is(err, ErrRefused) || strings.Contains(err.Error(), "answered 400") {
			return errNotAccepted
		}
		return err
	}
	if err := c.Snapshot(ctx); err != nil {
		c.logf("the snapshot after the unlock failed (%v); the next scheduled one tries again", err)
	}
	c.logf("unlocked: the store is unsealed and the CA has a new token")
	return nil
}

// Renew renews the CA's current token.
func (c *Custodian) Renew(ctx context.Context) error {
	tok, err := os.ReadFile(c.TokenPath)
	if err != nil {
		return fmt.Errorf("ca custody: the CA's token: %w", err)
	}
	if err := c.Store.RenewSelf(ctx, string(tok)); err != nil {
		return err
	}
	c.mu.Lock()
	snap := c.snapshotToken
	c.mu.Unlock()
	if snap == "" {
		return nil
	}
	return c.Store.RenewSelf(ctx, snap)
}

// RunRenewer renews the CA's token at once, then every period until ctx
// ends. Renewing at start is what keeps the token alive across custodians
// recreated more often than every (#582). A failure is logged at once, and
// again only when it changes: a sealed store answers nothing until it is
// unlocked, and the unlock writes a fresh token anyway.
func (c *Custodian) RunRenewer(ctx context.Context, every time.Duration) {
	last := ""
	for {
		err := c.Renew(ctx)
		switch {
		case err == nil:
			last = ""
		case err.Error() != last:
			last = err.Error()
			if errors.Is(err, ErrRefused) {
				c.logf("the CA's token was refused by the store: the CA cannot sign until it has a new token")
			} else {
				c.logf("renewing the CA's token: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// login logs the CA in, puts the token where the CA reads it, and revokes the
// token it replaces; and logs the snapshot role in, keeping its token in
// memory.
func (c *Custodian) login(ctx context.Context, m Material) error {
	tok, err := c.Store.Login(ctx, m.RoleID, m.SecretID)
	if err != nil {
		return err
	}
	snap, err := c.Store.Login(ctx, m.BackupRoleID, m.BackupSecretID)
	if err != nil {
		if rerr := c.Store.RevokeSelf(ctx, tok); rerr != nil {
			c.logf("the CA token of a failed unlock was not revoked (%v); its period ends it", rerr)
		}
		return err
	}
	c.mu.Lock()
	old := c.snapshotToken
	c.snapshotToken = snap
	c.mu.Unlock()
	if old != "" {
		if rerr := c.Store.RevokeSelf(ctx, old); rerr != nil && !errors.Is(rerr, ErrRefused) {
			c.logf("the previous snapshot token could not be revoked (%v); its period ends it", rerr)
		}
	}
	// No previous token is the first login, not a failure.
	previous, readErr := os.ReadFile(c.TokenPath)
	if readErr != nil {
		previous = nil
	}
	if err := writeAtomic(c.TokenPath, []byte(tok)); err != nil {
		if rerr := c.Store.RevokeSelf(ctx, tok); rerr != nil {
			c.logf("the token that could not be written was not revoked (%v); its period ends it", rerr)
		}
		return fmt.Errorf("ca custody: writing the CA's token: %w", err)
	}
	if len(previous) > 0 && string(previous) != tok {
		if err := c.Store.RevokeSelf(ctx, string(previous)); err != nil && !errors.Is(err, ErrRefused) {
			c.logf("the CA's previous token could not be revoked (%v); its period ends it", err)
		}
	}
	return nil
}

// Handler serves the custodian's routes to the core.
func (c *Custodian) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(PathStatus, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "only GET")
			return
		}
		writeJSON(w, http.StatusOK, c.Status(r.Context()))
	})
	mux.HandleFunc(PathMaterial, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "only GET")
			return
		}
		b, err := c.Material()
		if err != nil {
			writeError(w, http.StatusNotFound, "ca custody: no unlock material; the store has not been initialised here")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		discardWrite(w.Write(b))
	})
	mux.HandleFunc(PathUnlock, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "only POST")
			return
		}
		var m Material
		body := http.MaxBytesReader(w, r.Body, maxUnlockBody)
		if err := json.NewDecoder(body).Decode(&m); err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				writeError(w, http.StatusRequestEntityTooLarge, "ca custody: the unlock is too large")
				return
			}
			writeError(w, http.StatusBadRequest, "ca custody: the unlock is not material")
			return
		}
		err := c.Unlock(r.Context(), m)
		switch {
		case err == nil:
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, ErrIncomplete):
			writeError(w, http.StatusBadRequest, ErrIncomplete.Error())
		case errors.Is(err, errNotAccepted):
			writeError(w, http.StatusForbidden, errNotAccepted.Error())
		default:
			c.logf("unlock failed: %v", err)
			writeError(w, http.StatusServiceUnavailable, "ca custody: the store did not answer; retry")
		}
	})
	return mux
}

func (c *Custodian) materialPath() string { return filepath.Join(c.Dir, "material", MaterialFile) }

func (c *Custodian) logf(format string, args ...any) {
	if c.Log != nil {
		_, _ = fmt.Fprintf(c.Log, "ca custody: "+format+"\n", args...)
	}
}

// writeAtomic writes body to path, 0600, through a temporary file in the same
// directory, so a reader sees the old file or the new one and never half.
func writeAtomic(path string, body []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	// A failed write means the caller has gone; there is nobody to tell.
	discardEncode(json.NewEncoder(w).Encode(v))
}

func discardWrite(int, error) {}

func discardEncode(error) {}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// SnapshotEvery is how often the custodian takes the store's snapshot. The
// trust-key backup carries the newest one.
const SnapshotEvery = time.Hour

// SnapshotPath is the store's newest snapshot: the trust backup's ca-store.
func (c *Custodian) SnapshotPath() string { return filepath.Join(c.Dir, "snapshot", SnapshotFile) }

// MaterialPath is the sealed unlock material: the trust backup's ca-custody.
func (c *Custodian) MaterialPath() string { return c.materialPath() }

// Snapshot writes the store's own snapshot over the previous one, through a
// temporary file, so a failure leaves the last good snapshot in place. Its
// token lives in memory only, from the last init or unlock.
func (c *Custodian) Snapshot(ctx context.Context) error {
	c.mu.Lock()
	tok := c.snapshotToken
	c.mu.Unlock()
	if tok == "" {
		return errors.New("ca custody: no snapshot token yet; the store has not been unlocked since the custodian started")
	}
	var buf bytes.Buffer
	if err := c.Store.Snapshot(ctx, tok, &buf); err != nil {
		return err
	}
	if buf.Len() == 0 {
		return errors.New("ca custody: the store answered an empty snapshot")
	}
	if err := os.MkdirAll(filepath.Dir(c.SnapshotPath()), 0o700); err != nil {
		return err
	}
	return writeAtomic(c.SnapshotPath(), buf.Bytes())
}

// RunSnapshots takes a snapshot every period until ctx ends, logging a
// failure once until it changes.
func (c *Custodian) RunSnapshots(ctx context.Context, every time.Duration) {
	last := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
		err := c.Snapshot(ctx)
		switch {
		case err == nil:
			last = ""
		case err.Error() != last:
			last = err.Error()
			c.logf("taking the store's snapshot: %v", err)
		}
	}
}
