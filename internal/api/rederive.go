// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/sha1" //nolint:gosec // git's object name is SHA-1; this recomputes it, it does not choose it
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// ---------------------------------------------------------------------------
// Reading the material. Field reads, no decisions.
// ---------------------------------------------------------------------------

// logEntryBody is the part of a Rekor entry this package reads, flattened.
type logEntryBody struct {
	logIndex       int64
	algorithm      string
	artifact       string
	certificatePEM []byte
}

// entryBody pulls the fields out of a served log entry.
//
// The served document is Rekor's `{"<uuid>": {...}}` map. uuid names which
// entry to read when the response says; with an empty uuid the map must hold
// exactly one, because picking one of several would be choosing which entry to
// believe.
func entryBody(raw json.RawMessage, uuid string) (*logEntryBody, error) {
	if len(raw) == 0 {
		return nil, errors.New("the response carries no log entry")
	}
	var entries map[string]struct {
		Body     string `json:"body"`
		LogIndex int64  `json:"logIndex"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("the served log entry is not a Rekor entry map: %w", err)
	}
	key := uuid
	if key == "" {
		if len(entries) != 1 {
			return nil, fmt.Errorf("the served document holds %d entries and the "+
				"response names none", len(entries))
		}
		for k := range entries {
			key = k
		}
	}
	entry, ok := entries[key]
	if !ok {
		return nil, fmt.Errorf("the served document holds no entry %s", key)
	}
	body, err := base64Decode(entry.Body)
	if err != nil {
		return nil, fmt.Errorf("the entry body is not base64: %w", err)
	}
	var decoded struct {
		Kind string `json:"kind"`
		Spec struct {
			Data struct {
				Hash struct {
					Algorithm string `json:"algorithm"`
					Value     string `json:"value"`
				} `json:"hash"`
			} `json:"data"`
			Signature struct {
				PublicKey struct {
					Content string `json:"content"`
				} `json:"publicKey"`
			} `json:"signature"`
		} `json:"spec"`
	}
	if derr := json.Unmarshal(body, &decoded); derr != nil {
		return nil, fmt.Errorf("the entry body is not JSON: %w", derr)
	}
	certPEM, err := base64Decode(decoded.Spec.Signature.PublicKey.Content)
	if err != nil {
		return nil, fmt.Errorf("the entry's public key is not base64: %w", err)
	}
	return &logEntryBody{
		logIndex:       entry.LogIndex,
		algorithm:      decoded.Spec.Data.Hash.Algorithm,
		artifact:       decoded.Spec.Data.Hash.Value,
		certificatePEM: certPEM,
	}, nil
}

func base64Decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// gitObjectName recomputes a commit's object name from its bytes:
// sha1("commit " + length + NUL + content), or SHA-256 in a repository using
// that object format, chosen by the width of the name being checked against.
//
// This is the one piece of arithmetic that makes the rest of the material
// evidence rather than assertion, and it is deliberately something a reader
// can redo with `git hash-object -t commit` or four lines of any language.
func gitObjectName(object []byte, like string) string {
	header := []byte("commit " + strconv.Itoa(len(object)) + "\x00")
	if len(like) == sha256.Size*2 {
		sum := sha256.Sum256(append(header, object...))
		return hex.EncodeToString(sum[:])
	}
	sum := sha1.Sum(append(header, object...)) //nolint:gosec // see the import comment
	return hex.EncodeToString(sum[:])
}
