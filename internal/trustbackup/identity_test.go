// SPDX-License-Identifier: Apache-2.0

package trustbackup

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

func TestParseIdentitiesTakesX25519AndPluginLines(t *testing.T) {
	id, rs := testIdentity(t)
	pluginLine := plugin.EncodeIdentity("se", []byte("opaque handle"))
	in := "# created: today\n# public key: x\n\n" + id.String() + "\n" + pluginLine + "\n"
	ids, err := ParseIdentities(strings.NewReader(in), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("got %d identities, want 2", len(ids))
	}
	// The X25519 one opens a bundle.
	var buf bytes.Buffer
	if _, err := WriteBundle(&buf, rs, []Source{ValueSource("a", "f", []byte("x"))}, testNow); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBundle(&buf, ids[:1], ""); err != nil {
		t.Fatal(err)
	}
}

func TestParseIdentitiesRefusesWhatIsNotAnIdentity(t *testing.T) {
	for name, in := range map[string]string{
		"empty":            "# only a comment\n",
		"a recipient":      "age1qqqq\n",
		"a broken key":     "AGE-SECRET-KEY-1QQQ\n",
		"a broken plugin":  "AGE-PLUGIN-SE-1QQQ\n",
		"an over-long one": strings.Repeat("A", 70000),
	} {
		if _, err := ParseIdentities(strings.NewReader(in), nil); err == nil {
			t.Errorf("%s: ParseIdentities accepted it", name)
		}
	}
}

func TestLoadIdentitiesReadsAFile(t *testing.T) {
	id, _ := testIdentity(t)
	p := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(p, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ids, err := LoadIdentities(p, nil)
	if err != nil || len(ids) != 1 {
		t.Fatalf("LoadIdentities = %v, %v", ids, err)
	}
	if _, ok := ids[0].(*age.X25519Identity); !ok {
		t.Fatalf("identity type %T", ids[0])
	}
	if _, err := LoadIdentities(filepath.Join(t.TempDir(), "absent"), nil); err == nil {
		t.Fatal("LoadIdentities read a missing file")
	}
}
