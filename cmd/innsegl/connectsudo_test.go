// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"os/user"
	"strings"
	"testing"
)

// Under sudo, macOS resets HOME to root's; connect then looked for the
// enrolment in /var/root and found none, so `sudo innsegl connect --update`
// (and --pause) silently did nothing (measured 2026-10-02). The home and uid
// of the person who ran sudo are the ones that count.
func TestConnectUnderSudoUsesTheInvokingUsersHome(t *testing.T) {
	env := map[string]string{"SUDO_USER": "kody", "SUDO_UID": "501", "HOME": "/var/root"}
	lookup := func(name string) (*user.User, error) {
		if name != "kody" {
			return nil, errors.New("unknown user")
		}
		return &user.User{Username: "kody", Uid: "501", HomeDir: "/Users/kody"}, nil
	}
	home, uid, sudo, err := connectHome(func(k string) string { return env[k] }, 0, lookup, func() (string, error) { return "/var/root", nil })
	if err != nil || home != "/Users/kody" || uid != 501 || !sudo {
		t.Fatalf("connectHome = %q, %d, %v, %v; want /Users/kody, 501, true", home, uid, sudo, err)
	}
}

func TestConnectWithoutSudoUsesItsOwnHome(t *testing.T) {
	home, uid, sudo, err := connectHome(func(string) string { return "" }, 501, user.Lookup, func() (string, error) { return "/Users/kody", nil })
	if err != nil || home != "/Users/kody" || uid != 501 || sudo {
		t.Fatalf("connectHome = %q, %d, %v, %v", home, uid, sudo, err)
	}
}

// Enrolment under sudo would create root-owned files in the user's home and
// a service running as root: refused, saying to run it without sudo.
func TestConnectEnrolmentUnderSudoIsRefused(t *testing.T) {
	deps := connectDeps{home: "/Users/kody", underSudo: true}
	var stderr bytes.Buffer
	code := runConnect(context.Background(), []string{"https://core.example.test:28095", "--token", "ie_0123456789abcdef_" + strings.Repeat("a", 64), "--ca", "/nope"}, &bytes.Buffer{}, &stderr, deps)
	if code != exitUsage || !strings.Contains(stderr.String(), "without sudo") {
		t.Fatalf("code %d, stderr %q; want a usage refusal saying to run without sudo", code, stderr.String())
	}
}
