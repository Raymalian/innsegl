// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// OPS-192 (PROPOSED for doc 07's TC-OPS) — a fresh custody bring-up needs no
// manual chown: every volume a custody service writes as a non-root uid is
// owned by that uid when it is new (#589).
//
// Docker initialises an EMPTY named volume from the image's directory AND
// OWNERSHIP at the mount path, at whichever mount finds it empty. The
// bootstrap writes the root's chain to the KMS volume as 65532, and its image
// had no /etc/fulcio-kms, so on a fresh volume the mountpoint was root's and
// the bootstrap failed "permission denied" writing chain.pem. A volume that
// already holds the chain keeps its owner: only a first bring-up showed it.
//
// External volumes are chowned where they are made (ca-custody-volumes), and
// tmpfs volumes carry their uid in driver_opts; neither is this check's.
func TestOPS192EveryCustodyVolumeIsOwnedByItsWriterWhenNew(t *testing.T) {
	doc := composeRender(t, nil, sigstoreBase, sigstoreCustod)
	df := readFile(t, filepath.Join(repoRoot(t), "Dockerfile"))
	stageOf := map[string]string{"innsegl-ca-bootstrap:": "ca-bootstrap", "innsegl:": "runtime"}

	checked := 0
	for name, svc := range doc.Services {
		stage := ""
		for prefix, s := range stageOf {
			if strings.HasPrefix(svc.Image, prefix) {
				stage = s
			}
		}
		if stage == "" || svc.User == "" || strings.HasPrefix(svc.User, "0:") {
			continue
		}
		text := dockerfileStage(t, df, stage)
		for _, v := range svc.Volumes {
			if v.Type != "volume" || v.ReadOnly {
				continue
			}
			vol := doc.Volumes[v.Source]
			if vol.Name == "" || vol.DriverOpts["type"] == "tmpfs" || vol.External {
				continue
			}
			checked++
			made := regexp.MustCompile(`(?m)^RUN mkdir -p ` + regexp.QuoteMeta(v.Target) +
				` && chown ` + regexp.QuoteMeta(svc.User) + ` ` + regexp.QuoteMeta(v.Target) + `\b`)
			if !made.MatchString(text) {
				t.Errorf("%s writes volume %s at %s as %s, and the %s stage does not create %s owned by %s: "+
					"a fresh bring-up gets a root-owned mountpoint", name, v.Source, v.Target, svc.User, stage, v.Target, svc.User)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no custody service writes a named volume of its own; the check checked nothing")
	}
}

// OPS-192, the bring-up itself: the KMS volume made fresh, mounted first
// read-only by another container at a path its image lacks (the custodian
// starts before the bootstrap), then by the built bootstrap image as the CA's
// uid, which writes chain.pem with no chown by anyone.
func TestOPS192AFreshKMSVolumeIsWritableByTheBootstrap(t *testing.T) {
	requireDocker(t, "OPS-192")
	root := repoRoot(t)
	image := uniqueName(t, "innsegl-ops192-bootstrap") + ":test"
	vol := uniqueName(t, "innsegl-ops192-kms")
	docker := func(args ...string) (string, error) {
		cmd := exec.CommandContext(t.Context(), "docker", args...)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	// The ca-bootstrap stage as the Dockerfile writes it, minus its one
	// `COPY --from=build`. The binary has no bearing on the mountpoint's
	// owner, and building it means building the whole `build` stage: on a
	// cold CI runner that is gitsign plus every Go module, minutes that pushed
	// this package past go test's 10-minute limit (#591). Every other line,
	// the mkdir/chown under test included, runs exactly as written; an empty
	// context makes any other COPY from the checkout fail here, loudly.
	df, readErr := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	from := regexp.MustCompile(`(?m)^FROM ([^\n]*) AS ca-bootstrap$`).FindStringSubmatch(string(df))
	if from == nil {
		t.Fatal("the Dockerfile has no ca-bootstrap stage")
	}
	var stage strings.Builder
	stage.WriteString("FROM " + from[1] + "\n")
	dropped := 0
	for _, line := range strings.Split(dockerfileStage(t, string(df), "ca-bootstrap"), "\n") {
		if strings.HasPrefix(line, "COPY --from=build ") {
			dropped++
			continue
		}
		stage.WriteString(line + "\n")
	}
	if dropped != 1 {
		t.Fatalf("the ca-bootstrap stage has %d `COPY --from=build` lines, want 1: revisit what this test leaves out", dropped)
	}
	build := exec.CommandContext(t.Context(), "docker", "build", "-q", "-t", image, "-f", "-", t.TempDir())
	build.Stdin = strings.NewReader(stage.String())
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the ca-bootstrap stage: %v\n%s\n%s", err, out, stage.String())
	}
	t.Cleanup(func() {
		if err := exec.CommandContext(context.Background(), "docker", "rmi", "-f", image).Run(); err != nil {
			t.Logf("removing %s: %v", image, err)
		}
	})
	if out, err := docker("volume", "create", vol); err != nil {
		t.Fatalf("volume create: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if err := exec.CommandContext(context.Background(), "docker", "volume", "rm", "-f", vol).Run(); err != nil {
			t.Logf("removing %s: %v", vol, err)
		}
	})

	const alpine = "alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"
	if out, err := docker("run", "--rm", "-v", vol+":/etc/fulcio:ro", alpine, "true"); err != nil {
		t.Fatalf("the custodian's read-only mount: %v\n%s", err, out)
	}
	out, err := docker("run", "--rm", "--user", "65532:65532", "-v", vol+":/etc/fulcio-kms",
		"--entrypoint", "sh", image, "-c", "echo chain > /etc/fulcio-kms/chain.pem && stat -c %u /etc/fulcio-kms")
	if err != nil {
		t.Fatalf("the bootstrap could not write chain.pem to a fresh KMS volume: %v\n%s", err, out)
	}
	if strings.TrimSpace(out) != "65532" {
		t.Errorf("the fresh KMS volume is owned by %q, want 65532", strings.TrimSpace(out))
	}
}
