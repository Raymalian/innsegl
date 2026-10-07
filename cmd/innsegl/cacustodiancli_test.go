// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"filippo.io/age"
)

// OPS-146 (PROPOSED for doc 07's TC-OPS) — `innsegl ca-custodian` refuses to
// start without what it needs, and says which (#533, ADR-0076). A custodian
// with no recipient would seal the unlock material to nobody; one with no
// store address would report a sealed CA forever.
func TestOPS146TheCustodianNamesWhatItIsMissing(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		env  map[string]string
		want string
		code int
	}{
		{"no verb", nil, nil, "init or serve", exitUsage},
		{"unknown verb", []string{"export"}, nil, "init or serve", exitUsage},
		{"no store", []string{"init"}, map[string]string{envCARecipients: id.Recipient().String(),
			envCADir: t.TempDir(), envCATokenPath: t.TempDir() + "/t"}, envCAStoreAddr, exitCACustodyFailed},
		{"no recipient", []string{"init"}, map[string]string{envCAStoreAddr: "http://127.0.0.1:1",
			envCADir: t.TempDir(), envCATokenPath: t.TempDir() + "/t"}, envCARecipients, exitCACustodyFailed},
		{"no directory", []string{"serve"}, map[string]string{envCAStoreAddr: "http://127.0.0.1:1",
			envCARecipients: id.Recipient().String(), envCATokenPath: t.TempDir() + "/t"}, envCADir, exitCACustodyFailed},
		{"unreachable store", []string{"init"}, map[string]string{envCAStoreAddr: "http://127.0.0.1:1",
			envCARecipients: id.Recipient().String(), envCADir: t.TempDir(), envCATokenPath: t.TempDir() + "/t"},
			"not answering", exitCACustodyFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			getenv := func(k string) string { return c.env[k] }
			code := runCACustodian(t.Context(), c.args, &out, &errOut, getenv)
			if code != c.code || !strings.Contains(errOut.String(), c.want) {
				t.Fatalf("exit %d (want %d), stderr %q (want it to name %q)", code, c.code, errOut.String(), c.want)
			}
		})
	}
}
