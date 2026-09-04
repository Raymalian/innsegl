// SPDX-License-Identifier: Apache-2.0

package smoke

import (
	"context"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// OPS-014 (PROPOSED for doc 07's TC-OPS) — rekorPortConflict's decision,
// exercised against `docker ps` output alone.
//
// #131's observed shape: `docker ps --filter publish=3000` on this machine
// named juice-authz, image bkimminich/juice-shop:latest, while OPS-004 read
// a Rekor fault out of an HTTP 500 from that same container. This pins the
// decision that stops that misdiagnosis, without needing a container to do
// it — the same reasoning OPS-006 applies to startupOutcome.
// ---------------------------------------------------------------------------

func TestOPS014RekorPortConflictDecidesFromDockerPS(t *testing.T) {
	for _, tc := range []struct {
		name    string
		psOut   string
		wantErr bool
		want    []string // substrings a non-nil error must carry
	}{
		{
			name:  "our own rekor holds the port",
			psOut: rekorContainerName + "\tghcr.io/sigstore/rekor/rekor-server:v1.3.10\n",
		},
		{
			name:    "juice-authz holds the port — the observed case",
			psOut:   "juice-authz\tbkimminich/juice-shop:latest\n",
			wantErr: true,
			want:    []string{"juice-authz", "bkimminich/juice-shop:latest", "3000", rekorContainerName},
		},
		{
			name:    "nothing has the port published at all",
			psOut:   "",
			wantErr: true,
			want:    []string{"3000", rekorContainerName, "no container has it published"},
		},
		{
			name:  "our rekor is present alongside an unrelated match",
			psOut: "some-other-thing\tnginx:alpine\n" + rekorContainerName + "\tghcr.io/sigstore/rekor/rekor-server:v1.3.10\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := rekorPortConflict("3000", tc.psOut)
			if tc.wantErr && err == nil {
				t.Fatalf("rekorPortConflict(%q) = nil, want a port-conflict error", tc.psOut)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("rekorPortConflict(%q) = %v, want nil — our own container is on "+
					"the port and a probe on it is allowed to proceed", tc.psOut, err)
			}
			if err == nil {
				return
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %q; a misdiagnosed port conflict is "+
						"exactly the bug (#131) — the message must say who is actually "+
						"there, not just that something is wrong", err.Error(), want)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// OPS-015 (PROPOSED for doc 07's TC-OPS) — the live version of #131:
// assertRekorPortIsOurs against a real Docker daemon and a real foreign
// container squatting on the chosen port, reproducing the observed shape
// (juice-authz on host port 3000) at unit-test speed rather than needing the
// full ~289s reference-stack boot to prove the detection bites.
// ---------------------------------------------------------------------------

func TestOPS015AssertRekorPortIsOursNamesARealOccupier(t *testing.T) {
	ctx := t.Context()
	if err := dockerUsable(ctx); err != nil {
		t.Skipf("skipping OPS-015: %v", err)
	}

	port, err := freeHostPort(ctx)
	if err != nil {
		t.Fatalf("choosing a port to squat on: %v", err)
	}

	const decoy = "innsegl-smoke-ops015-decoy"
	dockerIgnore(docker(ctx, "rm", "--force", decoy)) // in case a previous run of this test was killed mid-way
	if _, runErr := docker(ctx, "run", "-d", "--name", decoy,
		"--publish", "127.0.0.1:"+port+":80",
		"--entrypoint", "sleep",
		runnerImage, "60"); runErr != nil {
		t.Fatalf("starting a decoy container on port %s: %v", port, runErr)
	}
	t.Cleanup(func() { dockerIgnore(docker(context.Background(), "rm", "--force", decoy)) })

	s := &stack{rekorPort: port}
	err = s.assertRekorPortIsOurs(ctx)
	if err == nil {
		t.Fatalf("assertRekorPortIsOurs saw nothing wrong with host port %s while %s "+
			"held it — this is #131 reproduced live: a foreign container on Rekor's "+
			"port must never be silently trusted", port, decoy)
	}
	for _, want := range []string{decoy, port, rekorContainerName} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("assertRekorPortIsOurs's error does not name %q: %v", want, err)
		}
	}
	t.Logf("OPS-015: port %s correctly reported as held by %s, not %s: %v",
		port, decoy, rekorContainerName, err)
}
