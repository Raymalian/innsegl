// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The images a deployment runs can be built once, on another machine, and
// carried to the host as one file (ADR-0070). The host accepts that file only
// if every image in it is labelled with the commit of every input it was built
// from, and refuses it otherwise. These tests hold the labels, the inputs, the
// compose file and the Makefile together; scripts/image-bundle-selftest.sh
// drives the accept-or-refuse path itself.

// makeRecipe is the recipe of one Makefile target: every line after its rule
// line up to the first blank line.
func makeRecipe(t *testing.T, mk, target string) string {
	t.Helper()
	m := regexp.MustCompile(`(?ms)^` + regexp.QuoteMeta(target) + `:[^\n]*\n(.*?)\n\n`).FindStringSubmatch(mk)
	if m == nil {
		t.Fatalf("the Makefile has no %s target", target)
	}
	return m[1]
}

func makeVar(t *testing.T, mk, name string) []string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + `\s*:=\s*(.+)$`).FindStringSubmatch(mk)
	if m == nil {
		t.Fatalf("the Makefile defines no %s", name)
	}
	return strings.Fields(m[1])
}

// Every image the stack builds carries the commit of what it was built from.
// The api image is the runtime plus the built UI, so it carries two: the Go
// inputs' commit, inherited from the runtime stage, and the UI's. The backup
// image copies nothing from the build context, so its only input is the
// Dockerfile. Without these, a bundle built from other UI sources, or another
// backup stage, would match the Go commit and be accepted.
func TestEveryBuiltImageIsLabelledWithTheCommitOfItsInputs(t *testing.T) {
	root := repoRoot(t)
	mk := readFile(t, filepath.Join(root, "Makefile"))
	df := readFile(t, filepath.Join(root, "Dockerfile"))
	stack := readFile(t, filepath.Join(root, "deploy", "compose", "innsegl.yml"))

	ui := map[string]bool{}
	for _, in := range makeVar(t, mk, "UI_IMAGE_INPUTS") {
		ui[in] = true
	}
	if !ui["web"] || !ui["Dockerfile"] || len(ui) != 2 {
		t.Errorf("UI_IMAGE_INPUTS = %v, want web and Dockerfile", makeVar(t, mk, "UI_IMAGE_INPUTS"))
	}
	if got := makeVar(t, mk, "BACKUP_IMAGE_INPUTS"); len(got) != 1 || got[0] != "Dockerfile" {
		t.Errorf("BACKUP_IMAGE_INPUTS = %v, want Dockerfile alone", got)
	}
	for _, v := range []string{"UI", "BACKUP"} {
		want := "$(shell git log -1 --format=%h --abbrev=12 -- $(" + v + "_IMAGE_INPUTS) 2>/dev/null)$(shell git diff --quiet HEAD -- $(" + v + "_IMAGE_INPUTS) 2>/dev/null || echo -dirty)"
		if !strings.Contains(mk, v+"_IMAGE_COMMIT := "+want) {
			t.Errorf("%s_IMAGE_COMMIT is not computed the way GO_IMAGE_COMMIT is", v)
		}
	}

	api := dockerfileStage(t, df, "api")
	if !regexp.MustCompile(`(?m)^ARG UI_COMMIT=unknown$`).MatchString(api) ||
		!regexp.MustCompile(`(?m)^LABEL dev\.innsegl\.ui-commit=\$\{UI_COMMIT\}$`).MatchString(api) {
		t.Error("the api stage does not label its image with the UI's commit")
	}
	backup := dockerfileStage(t, df, "backup")
	if !regexp.MustCompile(`(?m)^ARG COMMIT=unknown$`).MatchString(backup) ||
		!regexp.MustCompile(`(?m)^LABEL dev\.innsegl\.commit=\$\{COMMIT\}$`).MatchString(backup) {
		t.Error("the backup stage does not label its image with its commit")
	}
	if regexp.MustCompile(`(?m)^(?:COPY|ADD) `).MatchString(backup) {
		t.Error("the backup stage copies from the build context, so the Dockerfile is no longer its only input")
	}

	if !strings.Contains(composeService(t, stack, "innsegl-api"), "UI_COMMIT: ${INNSEGL_UI_COMMIT:-unknown}") {
		t.Error("compose does not pass the UI's commit to the api build")
	}
	if !strings.Contains(composeService(t, stack, "innsegl-backup"), "COMMIT: ${INNSEGL_BACKUP_COMMIT:-unknown}") {
		t.Error("compose does not pass the backup's commit to the backup build")
	}

	here := makeRecipe(t, mk, "innsegl-here-services")
	for _, want := range []string{
		"INNSEGL_COMMIT='$(GO_IMAGE_COMMIT)'",
		"INNSEGL_UI_COMMIT='$(UI_IMAGE_COMMIT)'",
		"INNSEGL_BACKUP_COMMIT='$(BACKUP_IMAGE_COMMIT)'",
	} {
		if strings.Count(here, want) < 2 {
			t.Errorf("innsegl-here-services does not pass %s to both the build and the start", want)
		}
	}
}

// The host takes its images from a verified bundle when one is there, and
// builds them when none is; either way the start that follows never builds.
// A bundle that fails its checks stops the target before anything starts.
func TestTheHostTakesABundleOrBuildsAndTheStartNeverBuilds(t *testing.T) {
	mk := readFile(t, filepath.Join(repoRoot(t), "Makefile"))
	here := makeRecipe(t, mk, "innsegl-here-services")

	find := strings.Index(here, "scripts/image-bundle.sh find")
	load := strings.Index(here, "scripts/image-bundle.sh load")
	build := strings.Index(here, "$(INNSEGL_COMPOSE) build $(INNSEGL_BUILD_SERVICES)")
	register := strings.Index(here, "deploy/compose/spire/register.sh")
	if find < 0 || load < 0 || build < 0 || register < 0 {
		t.Fatalf("innsegl-here-services does not find, load or build the images before registering:\n%s", here)
	}
	if find > load || load > register || build > register {
		t.Error("innsegl-here-services registers before the images are in place")
	}
	if !strings.Contains(here, "$(IMAGE_BUNDLE_ENV) scripts/image-bundle.sh") {
		t.Error("innsegl-here-services does not hand the bundle script the expected commits")
	}
	up := regexp.MustCompile(`(?m)\$\(INNSEGL_COMPOSE\) up -d[^\n]*$`).FindString(here)
	if up == "" || !strings.Contains(up, "--no-build") {
		t.Errorf("the start may build an image the bundle did not supply: %q", up)
	}

	env := regexp.MustCompile(`(?m)^IMAGE_BUNDLE_ENV := (.+)$`).FindStringSubmatch(mk)
	if env == nil {
		t.Fatal("the Makefile defines no IMAGE_BUNDLE_ENV")
	}
	for _, want := range []string{
		"INNSEGL_DEPLOY_COMMIT='$(DEPLOY_COMMIT)'",
		"INNSEGL_GO_IMAGE_COMMIT='$(GO_IMAGE_COMMIT)'",
		"INNSEGL_UI_IMAGE_COMMIT='$(UI_IMAGE_COMMIT)'",
		"INNSEGL_BACKUP_IMAGE_COMMIT='$(BACKUP_IMAGE_COMMIT)'",
		"INNSEGL_IMAGE_BUNDLE='$(INNSEGL_IMAGE_BUNDLE)'",
		"INNSEGL_IMAGE_PLATFORM='$(INNSEGL_IMAGE_PLATFORM)'",
	} {
		if !strings.Contains(env[1], want) {
			t.Errorf("IMAGE_BUNDLE_ENV does not set %s", want)
		}
	}
}

// `make image-bundle` builds for the deployment host's platform, amd64 unless
// the operator says otherwise, through the same script the host checks with.
func TestImageBundleBuildsForTheHostPlatform(t *testing.T) {
	root := repoRoot(t)
	mk := readFile(t, filepath.Join(root, "Makefile"))
	if !regexp.MustCompile(`(?m)^INNSEGL_IMAGE_PLATFORM \?= linux/amd64$`).MatchString(mk) {
		t.Error("the bundle's platform is not linux/amd64 by default, overridable")
	}
	if !strings.Contains(makeRecipe(t, mk, "image-bundle"), "$(IMAGE_BUNDLE_ENV) scripts/image-bundle.sh create") {
		t.Error("make image-bundle does not run scripts/image-bundle.sh create")
	}
	phony := regexp.MustCompile(`(?ms)^\.PHONY:(.*?)\n\n`).FindStringSubmatch(mk)
	if phony == nil || !regexp.MustCompile(`\bimage-bundle\b`).MatchString(phony[1]) {
		t.Error("image-bundle is not .PHONY")
	}
	st, err := os.Stat(filepath.Join(root, "scripts", "image-bundle.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&0o111 == 0 {
		t.Error("scripts/image-bundle.sh is not executable")
	}
}

// A bundle's images are retagged to the names compose runs. Those names are
// compose's defaults, so the two must not drift apart.
func TestTheBundleRetagsToTheImagesComposeRuns(t *testing.T) {
	root := repoRoot(t)
	stack := readFile(t, filepath.Join(root, "deploy", "compose", "innsegl.yml"))
	script := readFile(t, filepath.Join(root, "scripts", "image-bundle.sh"))
	for _, ref := range []string{
		"${INNSEGL_IMAGE:-innsegl:local}",
		"${INNSEGL_API_IMAGE:-innsegl-api:local}",
		"${INNSEGL_BACKUP_IMAGE:-innsegl-backup:local}",
	} {
		if !strings.Contains(stack, "image: "+ref) {
			t.Errorf("compose no longer names its image %s", ref)
		}
		if !strings.Contains(script, ref) {
			t.Errorf("scripts/image-bundle.sh does not retag to %s", ref)
		}
	}
}

// A bundle is a build artifact: it never enters git, and never enters the
// build context, which is uploaded to the daemon whole on every build.
func TestBundlesStayOutOfGitAndTheBuildContext(t *testing.T) {
	root := repoRoot(t)
	if !regexp.MustCompile(`(?m)^dist/$`).MatchString(readFile(t, filepath.Join(root, ".gitignore"))) {
		t.Error(".gitignore does not ignore dist/")
	}
	if !regexp.MustCompile(`(?m)^dist$`).MatchString(readFile(t, filepath.Join(root, ".dockerignore"))) {
		t.Error(".dockerignore does not exclude dist")
	}
}

// The images are built on one machine for another's platform, so the build
// stage must cross-compile. `go install` refuses to cross-compile into a set
// GOBIN ("cannot install cross-compiled binaries when GOBIN is set"), and the
// failure shows only on a build for another platform: measured 2026-10-04,
// an arm64 build for linux/amd64 stopped at the gitsign step. It installs to
// GOPATH and copies from whichever directory the Go toolchain chose.
func TestTheBuildStageCrossCompilesGitsign(t *testing.T) {
	df := readFile(t, filepath.Join(repoRoot(t), "Dockerfile"))
	build := dockerfileStage(t, df, "build")
	for _, run := range regexp.MustCompile(`(?ms)^RUN .*?[^\\]$`).FindAllString(build, -1) {
		if strings.Contains(run, "go install") && strings.Contains(run, "GOARCH=") && strings.Contains(run, "GOBIN=") {
			t.Errorf("a cross-compiling go install sets GOBIN, which go refuses:\n%s", run)
		}
	}
	if !strings.Contains(build, "${TARGETOS}_${TARGETARCH}/gitsign") {
		t.Error("the build stage does not look for gitsign where a cross-compiling go install puts it")
	}
}
