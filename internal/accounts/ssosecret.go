// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
)

// An organisation's sign-in client secret, encrypted at rest (#574).
//
// The key is a per-host credential (ADR-0078): `sso-key` in the core's trust
// credentials volume, rendered by innsegl-credentials into
// innsegl-credential-sso-key, which only innsegl-api mounts. The database
// never holds it, so the table and every database backup hold ciphertext
// only. The AES-256-GCM key is derived from the credential under a label of
// its own, and the connection's id is the additional data: a ciphertext
// copied onto another organisation's row does not open.
//
// A row written before migration 0020 holds the secret in client_secret.
// It is read as it is until SealSSOSecrets, which the API runs at every
// start, moves it into client_secret_sealed.

// ssoSealedPrefix names the one sealed form there is.
const ssoSealedPrefix = "v1:"

const ssoKeyLabel = "innsegl/sso-client-secret/v1"

// ErrNoSSOSecretKey: the store holds no key, so it can neither seal a client
// secret nor open one.
var ErrNoSSOSecretKey = errors.New("accounts: no key for organisation sign-in secrets " +
	"(INNSEGL_API_SSO_KEY_FILE); a client secret can be neither stored nor read")

// ssoKeyLine is credentials-lib.sh's cred_valid: one line of 16 or more of
// [A-Za-z0-9._~-].
var ssoKeyLine = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,}$`)

// SSOSecretKey seals and opens organisation sign-in client secrets.
type SSOSecretKey struct {
	aead cipher.AEAD
}

// LoadSSOSecretKey reads the credential file at path.
func LoadSSOSecretKey(path string) (*SSOSecretKey, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the operator's configured key file
	if err != nil {
		return nil, fmt.Errorf("accounts: reading the sign-in secret key: %w", err)
	}
	line := strings.TrimSuffix(string(raw), "\n")
	if !ssoKeyLine.MatchString(line) {
		return nil, fmt.Errorf("accounts: %s is not one line of 16 or more of [A-Za-z0-9._~-]", path)
	}
	mac := hmac.New(sha256.New, []byte(line))
	mac.Write([]byte(ssoKeyLabel))
	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("accounts: the sign-in secret key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("accounts: the sign-in secret key: %w", err)
	}
	return &SSOSecretKey{aead: aead}, nil
}

func ssoAAD(connectionID string) []byte {
	return []byte(ssoKeyLabel + "\x00" + connectionID)
}

// seal encrypts secret for connectionID. An empty secret (a public client)
// stays empty.
func (k *SSOSecretKey) seal(connectionID, secret string) (string, error) {
	if secret == "" {
		return "", nil
	}
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("accounts: sealing the client secret: %w", err)
	}
	out := k.aead.Seal(nonce, nonce, []byte(secret), ssoAAD(connectionID))
	return ssoSealedPrefix + base64.RawURLEncoding.EncodeToString(out), nil
}

// open decrypts what seal wrote for connectionID.
func (k *SSOSecretKey) open(connectionID, sealed string) (string, error) {
	body, ok := strings.CutPrefix(sealed, ssoSealedPrefix)
	if !ok {
		return "", errors.New("accounts: the client secret is not in a sealed form this release reads")
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || len(raw) < k.aead.NonceSize() {
		return "", errors.New("accounts: the sealed client secret is malformed")
	}
	n := k.aead.NonceSize()
	plain, err := k.aead.Open(nil, raw[:n], raw[n:], ssoAAD(connectionID))
	if err != nil {
		return "", errors.New("accounts: the client secret does not open under this host's key " +
			"(another host's key, or a row that is not its own)")
	}
	return string(plain), nil
}

// SetSSOSecretKey gives the store the key it seals and opens client secrets
// with. Without one it stores only public clients.
func (s *Store) SetSSOSecretKey(k *SSOSecretKey) { s.ssoKey = k }

// sealSecret is seal under the store's key.
func (s *Store) sealSecret(connectionID, secret string) (string, error) {
	if secret == "" {
		return "", nil
	}
	if s.ssoKey == nil {
		return "", ErrNoSSOSecretKey
	}
	return s.ssoKey.seal(connectionID, secret)
}

// openSecret answers a row's secret: the sealed one opened, or a row from
// before 0020 as it is.
func (s *Store) openSecret(connectionID, legacy, sealed string) (string, error) {
	if sealed == "" {
		return legacy, nil
	}
	if s.ssoKey == nil {
		return "", ErrNoSSOSecretKey
	}
	return s.ssoKey.open(connectionID, sealed)
}

// SealSSOSecrets moves every client secret still held in plain text into its
// sealed form, and answers how many it moved. Running it again moves none.
func (s *Store) SealSSOSecrets(ctx context.Context) (int, error) {
	if s.ssoKey == nil {
		return 0, ErrNoSSOSecretKey
	}
	n := 0
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT connection_id, client_secret FROM innsegl_auth.sso_connections
			WHERE client_secret <> '' FOR UPDATE`)
		if err != nil {
			return fmt.Errorf("accounts: reading plain client secrets: %w", err)
		}
		type row struct{ id, secret string }
		plain, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
			var x row
			return x, r.Scan(&x.id, &x.secret)
		})
		if err != nil {
			return fmt.Errorf("accounts: reading plain client secrets: %w", err)
		}
		for _, r := range plain {
			sealed, serr := s.ssoKey.seal(r.id, r.secret)
			if serr != nil {
				return serr
			}
			if _, err = tx.Exec(ctx, `UPDATE innsegl_auth.sso_connections
				SET client_secret = '', client_secret_sealed = $1 WHERE connection_id = $2`, sealed, r.id); err != nil {
				return fmt.Errorf("accounts: sealing a client secret: %w", err)
			}
		}
		n = len(plain)
		return nil
	})
	return n, err
}
