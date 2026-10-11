// SPDX-License-Identifier: Apache-2.0

// Package trustbackup writes and reads the encrypted trust-key backup
// (ADR-0074): the deployment's CA keys, log key, log database, identity
// secret and trust history, in one age-encrypted tar stream whose last entry
// is a manifest of every file's sha256.
//
// The core holds only public recipients. It can write a bundle and can never
// open one. Opening is for the operator's machine, which holds the identity.
package trustbackup

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"filippo.io/age/tag"
)

// EnvRecipients names the public keys a bundle is encrypted to, separated by
// spaces. Configuration on the host: a recipient belongs to one deployment.
const EnvRecipients = "INNSEGL_TRUST_BACKUP_RECIPIENTS"

// ErrNoRecipients is returned when no recipient is configured. With none, no
// bundle is written: an unencrypted key backup is never an option.
var ErrNoRecipients = errors.New("trust backup: no recipient is configured; set " + EnvRecipients +
	" to the public key the bundle is encrypted to")

// RecipientsFile is the name of the public recipients file the CA custody
// reseal writes beside the custody material: one recipient per line, blank
// lines and # comments allowed.
const RecipientsFile = "recipients.txt"

// LoadRecipients returns the recipients of this run: the space-separated env
// list plus every recipient in the file at path, each once. An absent file, or
// an empty path, means the env list only. A file that exists but cannot be
// read, or holds a line that is not a recipient this package can encrypt to,
// is an error naming the line: a recipient is never dropped silently.
func LoadRecipients(envList, path string) ([]age.Recipient, error) {
	seen := map[string]bool{}
	var all []string
	for _, f := range strings.Fields(envList) {
		if !seen[f] {
			seen[f] = true
			all = append(all, f)
		}
	}
	if path != "" {
		data, err := os.ReadFile(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return nil, fmt.Errorf("trust backup: reading the recipients file: %w", err)
		default:
			for i, line := range strings.Split(string(data), "\n") {
				line, _, _ = strings.Cut(line, "#")
				fields := strings.Fields(line)
				if len(fields) == 0 {
					continue
				}
				if len(fields) > 1 {
					return nil, fmt.Errorf("trust backup: %s:%d: want one recipient per line, got %d", path, i+1, len(fields))
				}
				if _, err := parseRecipient(fields[0]); err != nil {
					return nil, fmt.Errorf("trust backup: %s:%d: recipient %q: %w", path, i+1, fields[0], err)
				}
				if !seen[fields[0]] {
					seen[fields[0]] = true
					all = append(all, fields[0])
				}
			}
		}
	}
	return ParseRecipients(strings.Join(all, " "))
}

// ParseRecipients reads a space-separated recipient list. It takes recipients
// the core can encrypt to with no plugin binary:
//   - X25519 (age1…) and hybrid post-quantum (age1pq1…);
//   - tagged P-256 (age1tag1…, age1tagpq1…);
//   - age-plugin-se's Secure Enclave keys (age1se1…). Their payload is the
//     same compressed P-256 point a tag recipient carries, and age-plugin-se's
//     identity opens the tag stanza, so no plugin runs on the core.
func ParseRecipients(list string) ([]age.Recipient, error) {
	fields := strings.Fields(list)
	if len(fields) == 0 {
		return nil, ErrNoRecipients
	}
	out := make([]age.Recipient, 0, len(fields))
	for _, f := range fields {
		r, err := parseRecipient(f)
		if err != nil {
			return nil, fmt.Errorf("trust backup: recipient %q: %w", f, err)
		}
		out = append(out, r)
	}
	return out, nil
}

func parseRecipient(s string) (age.Recipient, error) {
	switch {
	case strings.HasPrefix(s, "age1tag1"), strings.HasPrefix(s, "age1tagpq1"):
		return tag.ParseRecipient(s)
	case strings.HasPrefix(s, "age1pq1"):
		return age.ParseHybridRecipient(s)
	case strings.HasPrefix(s, "age1") && strings.Count(s, "1") > 1:
		name, data, err := plugin.ParseRecipient(s)
		if err != nil {
			return nil, err
		}
		if name != "se" {
			return nil, fmt.Errorf("a %q plugin recipient needs its plugin binary to encrypt, "+
				"and the core runs none; use its tag form (age1tag1…) if the plugin offers one", name)
		}
		return tag.NewClassicRecipient(data)
	case strings.HasPrefix(s, "age1"):
		return age.ParseX25519Recipient(s)
	}
	return nil, errors.New("not an age recipient")
}
