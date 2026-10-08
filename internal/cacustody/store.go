// SPDX-License-Identifier: Apache-2.0

// Package cacustody keeps the Fulcio CA key in a sealed store that the
// operator's machine unlocks (ADR-0076). The store is OpenBao, spoken to over
// its HTTP API; the key is a non-exportable transit key; the CA logs in with
// an AppRole secret that, like the unseal key, exists at rest only as
// ciphertext to the operator's recipients.
package cacustody

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// TokenPeriod is how long the CA's token lives without a renewal. The
// custodian renews it every RenewEvery; a custodian that stops renewing
// leaves a token that is dead within a day.
const TokenPeriod = 24 * time.Hour

// RenewEvery is how often the custodian renews the CA's token.
const RenewEvery = 8 * time.Hour

// SignerPolicy is the only policy the CA's token carries.
const SignerPolicy = "innsegl-ca-signer"

// RoleName is the AppRole the CA logs in through.
const RoleName = "innsegl-ca"

// ErrSealed is answered by a store that has not been unlocked.
var ErrSealed = errors.New("ca custody: the store is sealed")

// ErrRefused is answered when the store refuses a token or a secret.
var ErrRefused = errors.New("ca custody: the store refused the credential")

// Store is a client of the CA key store's HTTP API.
type Store struct {
	Addr string
	HTTP *http.Client
}

// SealStatus is the store's answer to "is it ready".
type SealStatus struct {
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
}

// Material is what unlocks the store and logs the CA in. It exists in
// plaintext only in memory: at rest it is ciphertext (Seal), and on the wire
// it crosses the operator machine's enrolled connection only.
type Material struct {
	UnsealKey string `json:"unseal_key"`
	RoleID    string `json:"role_id"`
	SecretID  string `json:"secret_id"`
	// The snapshot role: a token that takes the store's snapshot and does
	// nothing else (ADR-0076).
	BackupRoleID   string `json:"backup_role_id"`
	BackupSecretID string `json:"backup_secret_id"`
}

// Valid says whether every field is present.
func (m Material) Valid() bool {
	return m.UnsealKey != "" && m.RoleID != "" && m.SecretID != "" &&
		m.BackupRoleID != "" && m.BackupSecretID != ""
}

// SealStatus asks the store whether it is initialised and sealed.
func (s *Store) SealStatus(ctx context.Context) (SealStatus, error) {
	var st SealStatus
	err := s.call(ctx, http.MethodGet, "/v1/sys/seal-status", "", nil, &st)
	return st, err
}

// Init initialises a new store with one unseal share, and answers the
// unseal key and the root token. One share for one operator: five shares
// kept in one place protect against nobody.
func (s *Store) Init(ctx context.Context) (unsealKey, rootToken string, err error) {
	var out struct {
		Keys      []string `json:"keys_base64"`
		RootToken string   `json:"root_token"`
	}
	if err := s.call(ctx, http.MethodPost, "/v1/sys/init", "",
		map[string]int{"secret_shares": 1, "secret_threshold": 1}, &out); err != nil {
		return "", "", err
	}
	if len(out.Keys) != 1 || out.RootToken == "" {
		return "", "", errors.New("ca custody: init answered no unseal key or no root token")
	}
	return out.Keys[0], out.RootToken, nil
}

// Unseal gives the store its unseal key. A wrong key leaves it sealed and
// is an error.
func (s *Store) Unseal(ctx context.Context, key string) error {
	var st SealStatus
	if err := s.call(ctx, http.MethodPost, "/v1/sys/unseal", "", map[string]string{"key": key}, &st); err != nil {
		return err
	}
	if st.Sealed {
		return fmt.Errorf("%w: the unseal key was not accepted", ErrSealed)
	}
	return s.waitActive(ctx)
}

// signerPolicy grants signing with the CA key and reading its public half.
// Nothing else: no export, no key creation, no configuration, no tokens.
func signerPolicy(key string) string {
	return fmt.Sprintf("path \"transit/sign/%s\" {\n  capabilities = [\"update\"]\n}\n"+
		"path \"transit/keys/%s\" {\n  capabilities = [\"read\"]\n}\n", key, key)
}

// Provision makes a fresh store ready for the CA: the transit engine, a
// non-exportable P-256 key, and two AppRoles whose periodic tokens carry one
// policy each: the CA's, which signs with that key and reads its public half,
// and the custodian's snapshot role, which takes the store's snapshot. It
// answers both roles' ids and one secret id each; the caller adds the unseal
// key. rootToken is the token from Init.
func (s *Store) Provision(ctx context.Context, rootToken, key string) (Material, error) {
	steps := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/v1/sys/mounts/transit", map[string]string{"type": "transit"}},
		{http.MethodPost, "/v1/transit/keys/" + key, map[string]any{"type": "ecdsa-p256", "exportable": false}},
		{http.MethodPut, "/v1/sys/policies/acl/" + SignerPolicy, map[string]string{"policy": signerPolicy(key)}},
		{http.MethodPost, "/v1/sys/auth/approle", map[string]string{"type": "approle"}},
		{http.MethodPost, "/v1/auth/approle/role/" + RoleName, map[string]any{
			"token_policies":     []string{SignerPolicy},
			"token_period":       int(TokenPeriod.Seconds()),
			"secret_id_num_uses": 0,
			"secret_id_ttl":      0,
			"token_type":         "service",
		}},
		{http.MethodPut, "/v1/sys/policies/acl/" + SnapshotPolicy, map[string]string{
			"policy": "path \"sys/storage/raft/snapshot\" {\n  capabilities = [\"read\"]\n}\n"}},
		{http.MethodPost, "/v1/auth/approle/role/" + SnapshotRoleName, map[string]any{
			"token_policies":     []string{SnapshotPolicy},
			"token_period":       int(TokenPeriod.Seconds()),
			"secret_id_num_uses": 0,
			"secret_id_ttl":      0,
			"token_type":         "service",
		}},
	}
	for _, st := range steps {
		if err := s.call(ctx, st.method, st.path, rootToken, st.body, nil); err != nil {
			return Material{}, fmt.Errorf("ca custody: provisioning %s: %w", st.path, err)
		}
	}
	var m Material
	var err error
	if m.RoleID, m.SecretID, err = s.roleCredentials(ctx, rootToken, RoleName); err != nil {
		return Material{}, err
	}
	if m.BackupRoleID, m.BackupSecretID, err = s.roleCredentials(ctx, rootToken, SnapshotRoleName); err != nil {
		return Material{}, err
	}
	return m, nil
}

// roleCredentials answers an AppRole's id and a new secret id.
func (s *Store) roleCredentials(ctx context.Context, rootToken, role string) (roleID, secretID string, err error) {
	var r struct {
		Data struct {
			RoleID string `json:"role_id"`
		} `json:"data"`
	}
	if err := s.call(ctx, http.MethodGet, "/v1/auth/approle/role/"+role+"/role-id", rootToken, nil, &r); err != nil {
		return "", "", fmt.Errorf("ca custody: reading the role id of %s: %w", role, err)
	}
	var sec struct {
		Data struct {
			SecretID string `json:"secret_id"`
		} `json:"data"`
	}
	if err := s.call(ctx, http.MethodPost, "/v1/auth/approle/role/"+role+"/secret-id", rootToken, nil, &sec); err != nil {
		return "", "", fmt.Errorf("ca custody: minting a secret id for %s: %w", role, err)
	}
	if r.Data.RoleID == "" || sec.Data.SecretID == "" {
		return "", "", fmt.Errorf("ca custody: the store answered an empty role id or secret id for %s", role)
	}
	return r.Data.RoleID, sec.Data.SecretID, nil
}

// Login logs the CA in and answers its token.
func (s *Store) Login(ctx context.Context, roleID, secretID string) (string, error) {
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := s.call(ctx, http.MethodPost, "/v1/auth/approle/login", "",
		map[string]string{"role_id": roleID, "secret_id": secretID}, &out); err != nil {
		return "", err
	}
	if out.Auth.ClientToken == "" {
		return "", errors.New("ca custody: login answered no token")
	}
	return out.Auth.ClientToken, nil
}

// RenewSelf renews token by its own authority.
func (s *Store) RenewSelf(ctx context.Context, token string) error {
	return s.call(ctx, http.MethodPost, "/v1/auth/token/renew-self", token, map[string]string{}, nil)
}

// RevokeSelf revokes token by its own authority.
func (s *Store) RevokeSelf(ctx context.Context, token string) error {
	return s.call(ctx, http.MethodPost, "/v1/auth/token/revoke-self", token, map[string]string{}, nil)
}

// TTL answers how long token has left.
func (s *Store) TTL(ctx context.Context, token string) (time.Duration, error) {
	var out struct {
		Data struct {
			TTL int64 `json:"ttl"`
		} `json:"data"`
	}
	if err := s.call(ctx, http.MethodGet, "/v1/auth/token/lookup-self", token, nil, &out); err != nil {
		return 0, err
	}
	return time.Duration(out.Data.TTL) * time.Second, nil
}

// call sends one request. A sealed store is ErrSealed and a refusal is
// ErrRefused, whatever path asked; neither error ever carries the body that
// was sent, because that body may be the unseal key or a secret id.
func (s *Store) call(ctx context.Context, method, path, token string, body, out any) error {
	var reader io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("ca custody: encoding %s: %w", path, err)
		}
		reader = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(s.Addr, "/")+path, reader)
	if err != nil {
		return fmt.Errorf("ca custody: %s: %w", path, err)
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := s.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ca custody: the store at %s is not answering: %w", s.Addr, err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("ca custody: reading %s: %w", path, err)
	}
	switch {
	case resp.StatusCode == http.StatusServiceUnavailable:
		return ErrSealed
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
		return fmt.Errorf("%w (%s %s)", ErrRefused, method, path)
	case resp.StatusCode >= 300:
		return fmt.Errorf("ca custody: %s %s answered %d: %s", method, path, resp.StatusCode, storeErrors(payload))
	}
	if out == nil || len(payload) == 0 {
		return nil
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("ca custody: decoding %s: %w", path, err)
	}
	return nil
}

// storeErrors is the store's own error list, which never echoes a request.
func storeErrors(payload []byte) string {
	var e struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(payload, &e) == nil && len(e.Errors) > 0 {
		return strings.Join(e.Errors, "; ")
	}
	return "no detail"
}

// activeWait bounds how long an unsealed store may take to become its own
// active node. Integrated storage elects itself after an unseal; until then
// every write answers "local node not active".
const activeWait = 60 * time.Second

// waitActive returns once the store answers its health check as the active
// node, unsealed.
func (s *Store) waitActive(ctx context.Context) error {
	client := s.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	deadline := time.Now().Add(activeWait)
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(s.Addr, "/")+"/v1/sys/health", http.NoBody)
		if err != nil {
			return err
		}
		if resp, derr := client.Do(req); derr == nil {
			discardClose(resp.Body.Close())
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("ca custody: the store at %s did not become active within %v", s.Addr, activeWait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func discardClose(error) {}

// SnapshotPolicy is the only policy the snapshot role's tokens carry.
const SnapshotPolicy = "innsegl-ca-snapshot"

// SnapshotRoleName is the AppRole the custodian takes snapshots through.
const SnapshotRoleName = "innsegl-ca-snapshot"

// Snapshot writes the store's own consistent snapshot to w.
func (s *Store) Snapshot(ctx context.Context, token string, w io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(s.Addr, "/")+"/v1/sys/storage/raft/snapshot", http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", token)
	client := s.HTTP
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ca custody: the store at %s is not answering: %w", s.Addr, err)
	}
	defer func() { discardClose(resp.Body.Close()) }()
	switch {
	case resp.StatusCode == http.StatusServiceUnavailable:
		return ErrSealed
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
		return fmt.Errorf("%w (snapshot)", ErrRefused)
	case resp.StatusCode != http.StatusOK:
		b, rerr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if rerr != nil {
			return rerr
		}
		return fmt.Errorf("ca custody: snapshot answered %d: %s", resp.StatusCode, storeErrors(b))
	}
	if _, err := io.Copy(w, resp.Body); err != nil {
		return fmt.Errorf("ca custody: reading the snapshot: %w", err)
	}
	return nil
}

// Restore puts a snapshot into a store that has never been initialised. It
// initialises the new store with keys of its own, only to be allowed to
// restore, and forgets them: the restored store is sealed under the keys of
// the store the snapshot came from, and opens only with that store's unlock
// material. Measured on the pinned store: the new store's own key is then
// refused, and the original unseal key opens it with the original CA key.
func (s *Store) Restore(ctx context.Context, snapshot io.Reader) error {
	st, err := s.SealStatus(ctx)
	if err != nil {
		return err
	}
	if st.Initialized {
		return errors.New("ca custody: restore needs a new store; this one is initialised. " +
			"Restoring over it would replace whatever it holds")
	}
	unseal, root, err := s.Init(ctx)
	if err != nil {
		return err
	}
	if err = s.Unseal(ctx, unseal); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(s.Addr, "/")+"/v1/sys/storage/raft/snapshot-force", snapshot)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", root)
	client := s.HTTP
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ca custody: restoring: %w", err)
	}
	b, rerr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	discardClose(resp.Body.Close())
	if rerr != nil {
		return rerr
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ca custody: restore answered %d: %s", resp.StatusCode, storeErrors(b))
	}
	// The restore reseals the store under the snapshot's keys; wait for it.
	deadline := time.Now().Add(activeWait)
	for {
		if st, err = s.SealStatus(ctx); err == nil && st.Sealed {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("ca custody: the restored store did not seal itself under the snapshot's keys")
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// PublicKey answers the newest public half of the transit key, as PEM.
func (s *Store) PublicKey(ctx context.Context, token, key string) (string, error) {
	var out struct {
		Data struct {
			LatestVersion int `json:"latest_version"`
			Keys          map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := s.call(ctx, http.MethodGet, "/v1/transit/keys/"+key, token, nil, &out); err != nil {
		return "", err
	}
	k, ok := out.Data.Keys[fmt.Sprint(out.Data.LatestVersion)]
	if !ok || k.PublicKey == "" {
		return "", fmt.Errorf("ca custody: the key %q has no public half", key)
	}
	return k.PublicKey, nil
}
