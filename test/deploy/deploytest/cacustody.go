// SPDX-License-Identifier: Apache-2.0

package deploytest

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type renderedService struct {
	Image       string                     `json:"image"`
	User        string                     `json:"user"`
	ReadOnly    bool                       `json:"read_only"`
	NetworkMode string                     `json:"network_mode"`
	Command     []string                   `json:"command"`
	Environment map[string]*string         `json:"environment"`
	Networks    map[string]json.RawMessage `json:"networks"`
	Volumes     []struct {
		Type     string `json:"type"`
		Source   string `json:"source"`
		Target   string `json:"target"`
		ReadOnly bool   `json:"read_only"`
	} `json:"volumes"`
	Profiles []string `json:"profiles"`
	Configs  []struct {
		Source string          `json:"source"`
		Target string          `json:"target"`
		Mode   json.RawMessage `json:"mode"`
	} `json:"configs"`
}

type ComposeDoc struct {
	Services map[string]renderedService `json:"services"`
	Configs  map[string]struct {
		Content string `json:"content"`
		File    string `json:"file"`
	} `json:"configs"`
	Networks map[string]struct {
		Name     string `json:"name"`
		Internal bool   `json:"internal"`
		External bool   `json:"external"`
	} `json:"networks"`
	Volumes map[string]struct {
		Name       string            `json:"name"`
		Driver     string            `json:"driver"`
		DriverOpts map[string]string `json:"driver_opts"`
		External   bool              `json:"external"`
	} `json:"volumes"`
}

func ComposeRender(t *testing.T, env []string, files ...string) ComposeDoc {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is not on PATH: %v", err)
	}
	root := RepoRoot(t)
	args := []string{"compose"}
	for _, f := range files {
		args = append(args, "-f", filepath.Join(root, f))
	}
	// Every profile these files name, so no service is left out of a
	// membership read.
	args = append(args, "--profile", "trust-backup", "--profile", "ca-import", "config", "--format", "json")
	cmd := exec.CommandContext(t.Context(), "docker", args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), append([]string{
		"INNSEGL_SPIRE_JWT_ISSUER=http://spire-oidc:8080",
		"INNSEGL_SPIRE_PARENT_ID=unset",
	}, env...)...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker compose %v config: %v\n%s", files, err, stderr.String())
	}
	var doc ComposeDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

const (
	SigstoreBase   = "deploy/compose/sigstore.yml"
	SigstoreCustod = "deploy/compose/sigstore.keycustody.yml"
	CoreBase       = "deploy/compose/innsegl.yml"
	CoreCustody    = "deploy/compose/innsegl.custody.yml"
)
