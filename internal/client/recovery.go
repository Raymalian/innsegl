// SPDX-License-Identifier: Apache-2.0
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/devicerecovery"
)

const recoveryPath = "/_core/recovery/"

// RecoveryStatus is local evidence, not a claim about server revocation.
type RecoveryStatus struct {
	State       string    `json:"state"`
	LastAttempt time.Time `json:"last_attempt,omitempty"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	NextRetry   time.Time `json:"next_retry,omitempty"`
	Error       string    `json:"error,omitempty"`
	Action      string    `json:"action,omitempty"`
}

func (s *Server) recoveryKeyPath() string {
	if s.paths.RecoveryKey != "" {
		return s.paths.RecoveryKey
	}
	return filepath.Join(s.paths.Dir, "recovery-key")
}

// RecoveryInstruction includes all required enrollment arguments without a token.
func RecoveryInstruction(coreURL, ca string) string {
	return fmt.Sprintf("authenticate on the account page to obtain a fresh enrollment token, then run innsegl connect --replace --token <fresh-token> --ca %q %q; to work without capture, run innsegl connect --pause and restart the harness", ca, coreURL)
}

func (s *Server) recoveryClient() *http.Client {
	// Clone only the pinned TLS policy: device recovery does not present the
	// expired traffic certificate and must never follow a redirect with proof.
	rt := s.transport.Clone()
	cfg := rt.TLSClientConfig.Clone()
	cfg.Certificates = nil
	cfg.GetClientCertificate = nil
	rt.TLSClientConfig = cfg
	return &http.Client{Transport: rt, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func recoveryJSON(ctx context.Context, c *http.Client, endpoint string, body any, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("reaching recovery service: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return ErrCredentialRefused
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("recovery service answered %d; retry or check client/core compatibility", resp.StatusCode)
	}
	if out == nil {
		_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 8192))
		return err
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(out)
}

func (s *Server) ensureRecoveryKey(ctx context.Context) (ed25519.PrivateKey, error) {
	path := s.recoveryKeyPath()
	raw, err := os.ReadFile(path)
	if err == nil {
		if len(raw) != ed25519.PrivateKeySize {
			return nil, errors.New("invalid device proof; account-owner recovery required")
		}
		info, statErr := os.Stat(path)
		if statErr != nil {
			return nil, statErr
		}
		if info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("device proof is not private; restrict its permissions before recovery")
		}
	} else {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		// Expired certificates never bootstrap device proof, even in grace.
		if !s.Now().Before(s.Leaf().NotAfter) || s.revoked.Load() {
			return nil, errors.New("no enrolled device proof; account-owner recovery required")
		}
		_, raw, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		if err := writeFileAtomic(path, raw, 0600); err != nil {
			return nil, err
		}
	}
	key := ed25519.PrivateKey(raw)
	// Registration is idempotent for the same key. Legacy clients migrate
	// only over their current, unexpired authenticated certificate.
	if s.Now().Before(s.Leaf().NotAfter) && !s.revoked.Load() {
		c := &http.Client{Transport: s.transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		err := recoveryJSON(ctx, c, s.core.CoreURL+recoveryPath+"enroll", map[string]string{"recovery_key": base64.StdEncoding.EncodeToString(key[ed25519.SeedSize:])}, nil)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}

func (s *Server) recoverCertificate(ctx context.Context) (issued, error) {
	key, err := s.ensureRecoveryKey(ctx)
	if err != nil {
		return issued{}, err
	}
	csr, err := newCSR(s.key, s.Leaf().URIs[0])
	if err != nil {
		return issued{}, err
	}
	c := s.recoveryClient()
	defer c.CloseIdleConnections()
	var challenge struct {
		Challenge string `json:"challenge"`
	}
	if challengeErr := recoveryJSON(ctx, c, s.core.CoreURL+recoveryPath+"challenge", map[string]string{"installation_id": s.core.InstallationID, "csr": csr}, &challenge); challengeErr != nil {
		return issued{}, challengeErr
	}
	if len(challenge.Challenge) != 64 {
		return issued{}, errors.New("invalid device recovery challenge")
	}
	signature := ed25519.Sign(key, devicerecovery.Message(strings.TrimSuffix(s.core.CoreURL, "/"), s.core.InstallationID, challenge.Challenge, csr))
	got, err := requestCertificate(ctx, c, s.core.CoreURL+recoveryPath+"issue", map[string]string{"installation_id": s.core.InstallationID, "csr": csr, "challenge": challenge.Challenge, "signature": base64.StdEncoding.EncodeToString(signature)}, s.key, s.Leaf().URIs[0])
	if errors.Is(err, errStatus401) {
		return issued{}, ErrCredentialRefused
	}
	if err != nil {
		return issued{}, err
	}
	return got, s.validateRenewed(got)
}

func (s *Server) validateRenewed(got issued) error {
	if got.InstallationID != s.core.InstallationID || len(got.Chain) == 0 {
		return errors.New("replacement certificate names another installation")
	}
	leaf := got.Chain[0]
	now := s.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || !got.ExpiresAt.Equal(leaf.NotAfter) {
		return errors.New("replacement certificate is not currently valid or expiry disagrees")
	}
	trusted, err := loadCerts(s.paths.Bundle)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	for _, ca := range trusted {
		roots.AddCert(ca)
	}
	intermediates := x509.NewCertPool()
	for _, ca := range got.Chain[1:] {
		intermediates.AddCert(ca)
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return err
}

func (s *Server) activateRenewed(got issued) error {
	// Parse the in-memory TLS pair before touching files. Keep the existing
	// trusted bundle; a recovery response cannot silently replace trust roots.
	candidate := tls.Certificate{PrivateKey: s.key, Leaf: got.Chain[0]}
	for _, c := range got.Chain {
		candidate.Certificate = append(candidate.Certificate, c.Raw)
	}
	err := writeFilesTransaction([]fileChange{{path: s.paths.Cert, data: got.ChainPEM, mode: 0600}, {path: s.paths.Refused, remove: true}, {path: s.paths.Revoked, remove: true}}, os.Rename)
	if err != nil && !errors.Is(err, ErrEnrolmentCommitted) {
		return err
	}
	s.cert.Store(&candidate)
	s.revoked.Store(false)
	s.transport.CloseIdleConnections()
	return err
}
