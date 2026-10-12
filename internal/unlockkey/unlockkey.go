// SPDX-License-Identifier: Apache-2.0

// Package unlockkey turns a security key's WebAuthn PRF output into a plain
// age X25519 identity, so a hardware key enrolled from the dashboard can open
// the CA custody material and trust-key backups (epic E34, #610).
//
// The derivation, format v1:
//
//	scalar    = HKDF-SHA256(ikm = PRF output (32 bytes),
//	                        salt = empty,
//	                        info = "innsegl unlock v1 age-x25519 " + purpose,
//	                        length = 32)
//	identity  = bech32("age-secret-key-", scalar), upper-cased: AGE-SECRET-KEY-1…
//	recipient = the identity's age1… X25519 recipient
//
// purpose is "custody" or "backup". The per-device randomness is not here: it
// is the salt the browser passes as the PRF input, so the PRF output is
// already specific to one device and one purpose's salt. The info string
// binds the output to this format and purpose so the same PRF output can
// never yield one key for two jobs.
//
// The strings are frozen once used, like a protected string: a change is a
// new format version, with its own info prefix and its own vectors. The
// TypeScript twin is web/src/lib/unlockkey; both pass the golden vectors in
// testdata/unlockkey/vectors.json (BAK-038, FE-153).
package unlockkey

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"strings"

	"filippo.io/age"
)

const (
	// PRFSize is the length of a WebAuthn PRF output (HMAC-SHA-256).
	PRFSize = 32
	// FormatVersion names the derivation format the vectors pin.
	FormatVersion = "innsegl unlock v1"
	// InfoPrefix is the HKDF info string before the purpose. The HKDF salt
	// is empty.
	InfoPrefix = "innsegl unlock v1 age-x25519 "
)

// Purpose separates the keys one PRF output can produce.
type Purpose string

const (
	// PurposeCustody opens the CA custody material (unlock.age).
	PurposeCustody Purpose = "custody"
	// PurposeBackup opens trust-key backup bundles.
	PurposeBackup Purpose = "backup"
)

var (
	// ErrPRFLength is returned for a PRF output that is not 32 bytes.
	ErrPRFLength = errors.New("unlockkey: PRF output must be 32 bytes")
	// ErrPurpose is returned for a purpose other than custody or backup.
	ErrPurpose = errors.New("unlockkey: unknown purpose")
)

// deriveScalar returns the 32-byte X25519 secret for prf and p. age clamps it
// when it computes the recipient, as X25519 does everywhere.
func deriveScalar(prf []byte, p Purpose) ([]byte, error) {
	if len(prf) != PRFSize {
		return nil, ErrPRFLength
	}
	if p != PurposeCustody && p != PurposeBackup {
		return nil, ErrPurpose
	}
	return hkdf.Key(sha256.New, prf, nil, InfoPrefix+string(p), 32)
}

// Derive returns the age X25519 identity for a PRF output and a purpose.
func Derive(prf []byte, p Purpose) (*age.X25519Identity, error) {
	scalar, err := deriveScalar(prf, p)
	if err != nil {
		return nil, err
	}
	return age.ParseX25519Identity(strings.ToUpper(bech32Encode("age-secret-key-", scalar)))
}

// BIP-173 bech32, encode only, without the 90-character limit (age's keys
// are longer). age keeps its own bech32 internal, so the few lines live here.
const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := range 5 {
			if (top>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32Encode(hrp string, data []byte) string {
	// 8-bit bytes to 5-bit groups, zero-padded at the end.
	var groups []byte
	acc, bits := uint32(0), uint(0)
	for _, b := range data {
		acc = acc<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			groups = append(groups, byte((acc>>bits)&31))
		}
	}
	if bits > 0 {
		groups = append(groups, byte((acc<<(5-bits))&31))
	}

	values := make([]byte, 0, 2*len(hrp)+1+len(groups)+6)
	for i := range len(hrp) {
		values = append(values, hrp[i]>>5)
	}
	values = append(values, 0)
	for i := range len(hrp) {
		values = append(values, hrp[i]&31)
	}
	values = append(values, groups...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := bech32Polymod(values) ^ 1

	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, g := range groups {
		sb.WriteByte(bech32Charset[g])
	}
	for i := range 6 {
		sb.WriteByte(bech32Charset[(mod>>(5*(5-i)))&31])
	}
	return sb.String()
}
