// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// API-040 — `innsegl api` takes the custodian's URL, by flag or by the
// variable the custody overlay sets on innsegl-api (#613, #615, ADR-0082
// decision 4), and its help names the unlock-key routes. PROPOSED for doc
// 07's TC-API.
// ---------------------------------------------------------------------------

func TestAPI040TheCustodianURLFallsBackToItsVariable(t *testing.T) {
	t.Setenv(envCACustodianURL, "http://innsegl-ca-custodian:8210")
	var seen apiOptions
	if code, _, stderr := runAPIUntilStopped(t, minimalAPIArgs(), stubAPIDeps(healthyStub(), &seen)); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if seen.caCustodianURL != "http://innsegl-ca-custodian:8210" {
		t.Errorf("-ca-custodian-url did not fall back to $%s: %q", envCACustodianURL, seen.caCustodianURL)
	}

	if code, _, stderr := runAPIUntilStopped(t, minimalAPIArgs("-ca-custodian-url", "http://elsewhere:1"),
		stubAPIDeps(healthyStub(), &seen)); code != exitOK || seen.caCustodianURL != "http://elsewhere:1" {
		t.Errorf("the flag: exit %d, %q: %s", code, seen.caCustodianURL, stderr)
	}
}

func TestAPI040WithoutTheVariableCustodyIsOff(t *testing.T) {
	t.Setenv(envCACustodianURL, "")
	var seen apiOptions
	if code, _, stderr := runAPIUntilStopped(t, minimalAPIArgs(), stubAPIDeps(healthyStub(), &seen)); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if seen.caCustodianURL != "" {
		t.Errorf("custodian %q with nothing set", seen.caCustodianURL)
	}
}

func TestAPI040HelpNamesTheFlagAndTheUnlockRoutes(t *testing.T) {
	var out bytes.Buffer
	if code := runAPI(context.Background(), []string{"-h"}, &out, &out, apiDeps{}); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"-ca-custodian-url", envCACustodianURL} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the help does not name %s", want)
		}
	}
	for _, route := range []string{
		"GET /api/v1/account/unlock-keys",
		"POST /api/v1/account/unlock-keys/begin",
		"POST /api/v1/account/unlock-keys/revoke/finish",
		"POST /api/v1/account/ca-custody/unlock/finish",
		"POST /api/v1/account/ca-custody/reseal/confirm",
	} {
		if !slices.Contains(apiRoutes, route) {
			t.Errorf("apiRoutes does not list %s", route)
		}
	}
}
