// SPDX-License-Identifier: Apache-2.0

package trustbackup

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// A Secure Enclave recipient as age-plugin-se prints it: "se" over a
// compressed P-256 point. The point is the curve's generator, so the test
// carries no deployment's key.
func testSERecipient(t *testing.T) string {
	t.Helper()
	g := []byte{0x03,
		0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
		0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96}
	return plugin.EncodeRecipient("se", g)
}

func TestParseRecipientsRefusesAnEmptyList(t *testing.T) {
	for _, in := range []string{"", "   ", "\n\t"} {
		if _, err := ParseRecipients(in); !errors.Is(err, ErrNoRecipients) {
			t.Fatalf("ParseRecipients(%q) = %v, want ErrNoRecipients", in, err)
		}
	}
}

func TestParseRecipientsTakesX25519AndSecureEnclaveRecipients(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRecipients(id.Recipient().String() + "  " + testSERecipient(t) + "\n")
	if err != nil {
		t.Fatalf("ParseRecipients: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d recipients, want 2", len(got))
	}
}

// The core encrypts to a Secure Enclave key with no plugin binary: the file
// carries a p256tag stanza, the one age-plugin-se's identity opens.
func TestASecureEnclaveRecipientEncryptsWithNoPlugin(t *testing.T) {
	rs, err := ParseRecipients(testSERecipient(t))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rs...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, "x"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\n-> p256tag ") {
		t.Fatalf("header has no p256tag stanza:\n%.200s", buf.String())
	}
}

func TestParseRecipientsTakesTagRecipients(t *testing.T) {
	_, data, err := plugin.ParseRecipient(testSERecipient(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRecipients(plugin.EncodeRecipient("tag", data)); err != nil {
		t.Fatalf("age1tag1: %v", err)
	}
}

func TestParseRecipientsRefusesWhatItCannotEncryptTo(t *testing.T) {
	_, data, err := plugin.ParseRecipient(testSERecipient(t))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"not a recipient":         "hello",
		"a broken x25519":         "age1qqqq",
		"a plugin needing binary": plugin.EncodeRecipient("yubikey", data),
		"a short se key":          plugin.EncodeRecipient("se", data[:10]),
		"a broken tag":            plugin.EncodeRecipient("tag", data[:10]),
		"a broken plugin string":  "age1se1qqqq",
		"an ssh key":              "ssh-ed25519 AAAA",
	}
	for name, in := range cases {
		if _, err := ParseRecipients(in); err == nil || errors.Is(err, ErrNoRecipients) {
			t.Errorf("%s: ParseRecipients(%q) = %v, want a refusal naming it", name, in, err)
		}
	}
}
