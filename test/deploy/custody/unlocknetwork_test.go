// SPDX-License-Identifier: Apache-2.0

package custody

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"innsegl.dev/innsegl/test/deploy/deploytest"
)

// ---------------------------------------------------------------------------
// OPS-207 (#615, ADR-0082 decision 4, amending ADR-0076 decision 6) — the
// dashboard API is on the unlock network, live and dev, and on nothing else
// new. The unlock network has three members: the custodian, the core
// (innsegl-core) and innsegl-api. No other service gains a network, and the
// custodian's unlock listener stays off every network the API already had.
// ---------------------------------------------------------------------------

const (
	devCoreBase    = "deploy/compose/dev/innsegl.yml"
	devCoreCustody = "deploy/compose/dev/innsegl.custody.yml"
	devSigBase     = "deploy/compose/dev/sigstore.yml"
	devSigCustody  = "deploy/compose/dev/sigstore.keycustody.yml"
)

func networkSet(nets map[string]json.RawMessage) []string {
	var out []string
	for n := range nets {
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
		{"live", []string{deploytest.CoreBase}, []string{deploytest.CoreBase, deploytest.CoreCustody},
			[]string{deploytest.SigstoreBase, deploytest.SigstoreCustod}, "innsegl-ca-unlock"},
		{"dev", []string{deploytest.CoreBase, devCoreBase}, []string{deploytest.CoreBase, devCoreBase, deploytest.CoreCustody, devCoreCustody},
			[]string{deploytest.SigstoreBase, devSigBase, deploytest.SigstoreCustod, devSigCustody}, "innsegl-dev-ca-unlock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := deploytest.ComposeRender(t, nil, tc.coreBase...)
			after := deploytest.ComposeRender(t, nil, tc.coreOver...)
			sig := deploytest.ComposeRender(t, nil, tc.sigOver...)

			if got := members(after, unlock); !reflect.DeepEqual(got, []string{"innsegl-api", "innsegl-core"}) {
				t.Errorf("the core-side unlock members are %v; want innsegl-api and innsegl-core only", got)
			}
			if got := members(sig, unlock); !reflect.DeepEqual(got, []string{"innsegl-ca-custodian"}) {
				t.Errorf("the custodian-side unlock members are %v; want the custodian alone", got)
			}
			if got := after.Networks[unlock].Name; got != tc.wantName {
				t.Errorf("the unlock network is named %q; want %q", got, tc.wantName)
			}

			// The API gained the unlock network and nothing else.
			wantAPI := append(networkSet(before.Services["innsegl-api"].Networks), unlock)
			slices.Sort(wantAPI)
			if got := networkSet(after.Services["innsegl-api"].Networks); !reflect.DeepEqual(got, wantAPI) {
				t.Errorf("innsegl-api is on %v; want its networks plus only %s: %v", got, unlock, wantAPI)
			}
			// No other service changed networks, but innsegl-core, which was
			// already on it.
			for name, s := range after.Services {
				if name == "innsegl-api" || name == "innsegl-core" {
					continue
				}
				if got, want := networkSet(s.Networks), networkSet(before.Services[name].Networks); !reflect.DeepEqual(got, want) {
					t.Errorf("%s is on %v with custody; %v without", name, got, want)
				}
			}
			// The custodian's unlock listener is reachable only on the
			// unlock network: it shares no other network with the API.
			cust := networkSet(sig.Services["innsegl-ca-custodian"].Networks)
			for _, n := range networkSet(after.Services["innsegl-api"].Networks) {
				if n != unlock && slices.Contains(cust, n) {
					t.Errorf("the custodian and innsegl-api share %s; the unlock listener is reachable there", n)
				}
			}
		})
	}
}
