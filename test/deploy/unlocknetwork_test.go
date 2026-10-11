// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"reflect"
	"slices"
	"testing"
)

// ---------------------------------------------------------------------------
// OPS-207 (#615, ADR-0082 decision 4, amending ADR-0076 decision 6) — the
// dashboard API is on the unlock network, live and dev, and on nothing else
// new. The unlock network has three members: the custodian, the core
// (innsegl-mcp) and innsegl-api. No other service gains a network, and the
// custodian's unlock listener stays off every network the API already had.
// ---------------------------------------------------------------------------

const (
	devCoreBase    = "deploy/compose/dev/innsegl.yml"
	devCoreCustody = "deploy/compose/dev/innsegl.custody.yml"
	devSigBase     = "deploy/compose/dev/sigstore.yml"
	devSigCustody  = "deploy/compose/dev/sigstore.keycustody.yml"
)

func networkSet(s renderedService) []string {
	var out []string
	for n := range s.Networks {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

func TestOPS207TheAPIJoinsTheUnlockNetworkAndNothingElseChanges(t *testing.T) {
	const unlock = "innsegl-ca-unlock"
	for _, tc := range []struct {
		name                        string
		coreBase, coreOver, sigOver []string
		wantName                    string
	}{
		{"live", []string{coreBase}, []string{coreBase, coreCustody},
			[]string{sigstoreBase, sigstoreCustod}, "innsegl-ca-unlock"},
		{"dev", []string{coreBase, devCoreBase}, []string{coreBase, devCoreBase, coreCustody, devCoreCustody},
			[]string{sigstoreBase, devSigBase, sigstoreCustod, devSigCustody}, "innsegl-dev-ca-unlock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := composeRender(t, nil, tc.coreBase...)
			after := composeRender(t, nil, tc.coreOver...)
			sig := composeRender(t, nil, tc.sigOver...)

			if got := members(after, unlock); !reflect.DeepEqual(got, []string{"innsegl-api", "innsegl-mcp"}) {
				t.Errorf("the core-side unlock members are %v; want innsegl-api and innsegl-mcp only", got)
			}
			if got := members(sig, unlock); !reflect.DeepEqual(got, []string{"innsegl-ca-custodian"}) {
				t.Errorf("the custodian-side unlock members are %v; want the custodian alone", got)
			}
			if got := after.Networks[unlock].Name; got != tc.wantName {
				t.Errorf("the unlock network is named %q; want %q", got, tc.wantName)
			}

			// The API gained the unlock network and nothing else.
			wantAPI := append(networkSet(before.Services["innsegl-api"]), unlock)
			slices.Sort(wantAPI)
			if got := networkSet(after.Services["innsegl-api"]); !reflect.DeepEqual(got, wantAPI) {
				t.Errorf("innsegl-api is on %v; want its networks plus only %s: %v", got, unlock, wantAPI)
			}
			// No other service changed networks, but innsegl-mcp, which was
			// already on it.
			for name, s := range after.Services {
				if name == "innsegl-api" || name == "innsegl-mcp" {
					continue
				}
				if got, want := networkSet(s), networkSet(before.Services[name]); !reflect.DeepEqual(got, want) {
					t.Errorf("%s is on %v with custody; %v without", name, got, want)
				}
			}
			// The custodian's unlock listener is reachable only on the
			// unlock network: it shares no other network with the API.
			cust := networkSet(sig.Services["innsegl-ca-custodian"])
			for _, n := range networkSet(after.Services["innsegl-api"]) {
				if n != unlock && slices.Contains(cust, n) {
					t.Errorf("the custodian and innsegl-api share %s; the unlock listener is reachable there", n)
				}
			}
		})
	}
}
