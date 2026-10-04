// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// P1: the core reads repositories only from its mirror (ADR-0065 decision 1,
// completed by its 2026-10-03 amendment; doc 05 §1).
//
// The core used to mount the operator's own projects folder into the MCP,
// the query API and the reconciler, from an overlay file that had to be named
// on every compose command. On a hosted core that folder is the core's own
// disk, not any client's, so a proof read there answered only for
// repositories that happened to be checked out on the core. Now every
// service that reads a repository reads the mirror clients push to, and the
// query API and the reconciler can only read it.
func TestTheCoreReadsRepositoriesOnlyFromTheMirror(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping: %v", err)
	}

	if _, err := os.Stat(filepath.Join(repoRoot(t), "deploy/compose/innsegl.workrepo.yml")); err == nil {
		t.Error("deploy/compose/innsegl.workrepo.yml still ships; the core has no projects overlay")
	}

	// Every profile, so no service escapes the check by being opt-in.
	const projects = "/srv/host-projects"
	t.Setenv("INNSEGL_PROJECTS", projects)
	cfg := interpolateComposeProfiles(ctx, t, "innsegl-segments",
		[]string{"init", "separate", "demo", "canary"}, "deploy/compose/innsegl.yml")

	for name, svc := range cfg.Services {
		for _, v := range svc.Volumes {
			if v.Target == "/projects" || strings.HasPrefix(v.Source, projects) {
				t.Errorf("%s mounts the host projects folder (%s -> %s)", name, v.Source, v.Target)
			}
		}
		for key, val := range svc.Environment {
			if key == "INNSEGL_HOST_PROJECTS" {
				t.Errorf("%s is told a host projects folder (%s)", name, key)
			}
			if val != nil && strings.HasPrefix(key, "GIT_CONFIG_VALUE_") && strings.Contains(*val, "/projects") {
				t.Errorf("%s trusts a projects mount for git: %s=%s", name, key, *val)
			}
		}
		if _, ok := svc.Environment["INNSEGL_API_REPOS"]; ok {
			t.Errorf("%s still carries a static repository list (INNSEGL_API_REPOS)", name)
		}
	}

	// The readers: the mirror, read-only, and told where it is.
	for _, name := range []string{"innsegl-api", "innsegl-reconciler"} {
		svc := cfg.service(t, name)
		var mounted, readOnly bool
		for _, v := range svc.Volumes {
			if v.Type == "volume" && v.Source == "innsegl-mirror" && v.Target == "/mirror" {
				mounted, readOnly = true, v.ReadOnly
			}
			if v.Target == "/work" {
				t.Errorf("%s mounts the MCP's working-tree volume at /work; it reads the mirror", name)
			}
		}
		if !mounted {
			t.Errorf("%s does not mount the innsegl-mirror volume at /mirror", name)
		}
		if mounted && !readOnly {
			t.Errorf("%s mounts the mirror read-write; only innsegl-mcp, which receives pushes, may", name)
		}
		if dir, _ := cfg.env(name, "INNSEGL_MIRROR_DIR"); dir != "/mirror" {
			t.Errorf("%s has INNSEGL_MIRROR_DIR=%q, want /mirror", name, dir)
		}
	}

	// What the overlay carried besides the projects folder is the core's own,
	// and a plain `up` of the one file has it: the bodies and the query
	// API's read of them. Not the session markers: they need a projects
	// folder (TestTheCoreSetsNoSessionFolderWithoutAProjectsFolder).
	plain := interpolateComposeProfiles(ctx, t, "innsegl-segments", nil, "deploy/compose/innsegl.yml")
	for service, want := range map[string]map[string]bool{
		// target -> read-only
		"innsegl-mcp": {"/agentlog": false, "/harness-log": true},
		"innsegl-api": {"/agentlog": true, "/message-key": true, "/mirror": true},
	} {
		got := map[string]bool{}
		for _, v := range plain.service(t, service).Volumes {
			got[v.Target] = v.ReadOnly
		}
		for target, ro := range want {
			have, ok := got[target]
			switch {
			case !ok:
				t.Errorf("a plain up of innsegl.yml gives %s no mount at %s", service, target)
			case have != ro:
				t.Errorf("%s mounts %s read-only=%v, want %v", service, target, have, ro)
			}
		}
	}
	for service, keys := range map[string][]string{
		"innsegl-mcp": {"INNSEGL_MCP_LOG_DIR"},
		"innsegl-api": {"INNSEGL_API_LOG_DIR", "INNSEGL_API_SNAPSHOT_DIR", "INNSEGL_API_MESSAGE_KEY_DIR"},
	} {
		for _, key := range keys {
			if v, ok := plain.env(service, key); !ok || v == "" {
				t.Errorf("a plain up of innsegl.yml gives %s no %s", service, key)
			}
		}
	}
}

// The core refuses a session folder without a host projects folder
// (cmd/innsegl serve.go, validate): observe_session resolves workspaces
// there. With the projects folder gone from the core, a session folder left
// in innsegl.yml crash-looped innsegl-mcp on every host (measured
// 2026-10-04). The two are set together or not at all.
func TestTheCoreSetsNoSessionFolderWithoutAProjectsFolder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping: %v", err)
	}
	cfg := interpolateComposeProfiles(ctx, t, "innsegl-segments",
		[]string{"init", "separate", "demo", "canary"}, "deploy/compose/innsegl.yml")
	for name, svc := range cfg.Services {
		session := svc.Environment["INNSEGL_MCP_SESSION_DIR"]
		projects := svc.Environment["INNSEGL_HOST_PROJECTS"]
		if session != nil && *session != "" && (projects == nil || *projects == "") {
			t.Errorf("%s sets INNSEGL_MCP_SESSION_DIR=%s without INNSEGL_HOST_PROJECTS; innsegl serve refuses to start", name, *session)
		}
	}
}
