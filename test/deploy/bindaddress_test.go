// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/test/deploy/deploytest"
)

// ---------------------------------------------------------------------------
// OPS-127 — the published host address is one setting, and loopback by default.
//
// The gateway (8095) and the dashboard (served by innsegl-api since #475, on
// 8082 inside its container) are the two surfaces a hosted shape has to
// expose. Their host address is
// ${INNSEGL_BIND:-127.0.0.1}. Everything else stays on loopback exactly as it
// is today, and no new port is published. Read the way GW-005 reads it:
// `docker compose config`, never a container.
// ---------------------------------------------------------------------------

// publishedHosts maps "service:target" to host_ip for every published port.
func publishedHosts(cfg deploytest.ComposeConfig) map[string]string {
	out := map[string]string{}
	for name, svc := range cfg.Services {
		for _, p := range svc.Ports {
			out[name+":"+strconv.Itoa(p.Target)] = p.HostIP
		}
	}
	return out
}

func TestOPS127BindAddressIsConfigurableAndLoopbackByDefault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := deploytest.ComposeUsable(ctx); err != nil {
		t.Skipf("skipping OPS-127: %v", err)
	}

	t.Setenv("INNSEGL_BIND", "")
	def := publishedHosts(deploytest.InterpolateComposeProfiles(ctx, t, "innsegl-segments", nil, "deploy/compose/innsegl.yml"))

	t.Setenv("INNSEGL_BIND", deploytest.BindDocAddr)
	bound := publishedHosts(deploytest.InterpolateComposeProfiles(ctx, t, "innsegl-segments", nil, "deploy/compose/innsegl.yml"))

	exposed := map[string]bool{
		"innsegl-core:" + strconv.Itoa(gatewayContainerPort):                true,
		"innsegl-api:" + strconv.Itoa(deploytest.DashboardContainerPort):    true,
		"innsegl-api:" + strconv.Itoa(deploytest.DashboardTLSContainerPort): true,
	}
	for k := range exposed {
		if _, ok := def[k]; !ok {
			t.Fatalf("%s is not published at all; got %v", k, def)
		}
	}

	if len(def) != len(bound) {
		t.Errorf("setting INNSEGL_BIND changed the set of published ports: default %v, bound %v", def, bound)
	}
	keys := make([]string, 0, len(def))
	for k := range def {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if def[k] != "127.0.0.1" {
			t.Errorf("%s defaults to host_ip %q, want 127.0.0.1", k, def[k])
		}
		want := "127.0.0.1"
		if exposed[k] {
			want = deploytest.BindDocAddr
		}
		if bound[k] != want {
			t.Errorf("%s with INNSEGL_BIND=%s publishes on %q, want %q", k, deploytest.BindDocAddr, bound[k], want)
		}
	}
}

func TestOPS127TheServiceSeesTheExposureVariables(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := deploytest.ComposeUsable(ctx); err != nil {
		t.Skipf("skipping OPS-127: %v", err)
	}
	t.Setenv("INNSEGL_BIND", deploytest.BindDocAddr)
	t.Setenv("INNSEGL_GATEWAY_CLIENT_AUTH", "spiffe")
	t.Setenv("INNSEGL_GATEWAY_CERT_NAMES", "<core-name>")
	cfg := deploytest.InterpolateComposeProfiles(ctx, t, "innsegl-segments", nil, "deploy/compose/innsegl.yml")
	env := cfg.Service(t, "innsegl-core").Environment

	want := map[string]string{
		"INNSEGL_BIND":                deploytest.BindDocAddr,
		"INNSEGL_GATEWAY_CLIENT_AUTH": "spiffe",
		"INNSEGL_GATEWAY_CERT_NAMES":  "<core-name>",
	}
	for k, v := range want {
		got, ok := env[k]
		if !ok || got == nil || *got != v {
			t.Errorf("innsegl-core environment %s = %v, want %q", k, got, v)
		}
	}
	dsn, ok := env["INNSEGL_GATEWAY_ACCOUNTS_DSN"]
	if !ok || dsn == nil || *dsn == "" {
		t.Fatalf("innsegl-core environment carries no INNSEGL_GATEWAY_ACCOUNTS_DSN")
	}
	// RM-355 (#603): the core enrols as the enroller, never as the
	// auth-writer the API holds.
	if !strings.HasPrefix(*dsn, "postgres://innsegl_enroller@") ||
		!strings.Contains(*dsn, "passfile=/run/innsegl/credentials/enroller/pgpass") {
		t.Errorf("INNSEGL_GATEWAY_ACCOUNTS_DSN = %q, want the enroller's DSN", *dsn)
	}
	if api := cfg.Service(t, "innsegl-api").Environment["INNSEGL_API_AUTH_DSN"]; api != nil && *api == *dsn {
		t.Errorf("the core holds the auth-writer DSN the API holds (%q)", *dsn)
	}
}
