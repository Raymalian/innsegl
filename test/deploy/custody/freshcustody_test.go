// SPDX-License-Identifier: Apache-2.0

package custody

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"innsegl.dev/innsegl/test/deploy/deploytest"
)

// ---------------------------------------------------------------------------
// A FRESH custody `make start` (RM-370, #622). Proposed for doc 07; doc 07 is
// not modified here.
//
// OPS-231. #591 (OPS-192) gave the ca-bootstrap image a mountpoint owned by
// the CA's uid, so Docker hands a fresh fulcio-kms volume that owner. No
// bring-up step built that image: innsegl-images built the core, backup and
// api images, the bundle carried those three, and `compose up` reused any
// innsegl-ca-bootstrap:local already on the machine. A machine that built it
// before #591 kept the old one, the volume stayed root's, and the bootstrap
// failed "permission denied" writing chain.pem. Measured on a development
// machine 2026-10-12: the local image had no /etc/fulcio-kms at all. So the
// bootstrap image is built, or loaded from the bundle and checked, with the
// others, labelled with the commit of the Go inputs it is built from.
//
// OPS-232. sigstore-up pinned the log in rekor-index-ready, AFTER
// ca-custody-up. A custody failure stopped the bring-up before the pin was
// written, and the next start was refused by the pin guard. The log is up
// before custody is, so it is pinned first.
// ---------------------------------------------------------------------------

// The image compose runs for the bootstrap, and the one the bundle retags to.
const bootstrapImageRef = "${INNSEGL_CA_BOOTSTRAP_IMAGE:-innsegl-ca-bootstrap:local}"

func TestOPS231TheCABootstrapImageIsBuiltOrLoadedWithTheOthers(t *testing.T) {
	root := deploytest.RepoRoot(t)

	// The host build: with custody on, innsegl-images builds the bootstrap,
	// handing it the Go inputs' commit as the others get theirs.
	for _, mode := range []string{"live", "dev"} {
		out := strings.ReplaceAll(makeDryRunCustody(t, mode, "innsegl-images"), "\\\n", " ")
		build := regexp.MustCompile(`(?m)^.*INNSEGL_COMMIT='[^']*'.*sigstore\.keycustody\.yml.* build innsegl-ca-bootstrap\b.*$`)
		if !build.MatchString(out) {
			t.Errorf("%s: with custody on, make innsegl-images does not build innsegl-ca-bootstrap "+
				"from this checkout with the Go inputs' commit, so a machine keeps whatever "+
				"bootstrap image it built first:\n%s", mode, out)
		}
	}

	// The bundle: the bootstrap is one of the images it carries and checks.
	script := deploytest.ReadFile(t, filepath.Join(root, "scripts", "image-bundle.sh"))
	if !strings.Contains(script, "innsegl-ca-bootstrap:bundle|"+bootstrapImageRef+"|ca-bootstrap") {
		t.Errorf("scripts/image-bundle.sh does not carry the ca-bootstrap image retagged to %s",
			bootstrapImageRef)
	}
	if !regexp.MustCompile(`(?s)innsegl-ca-bootstrap:bundle\)\s*echo "dev\.innsegl\.commit \$GO_COMMIT"`).MatchString(script) {
		t.Error("scripts/image-bundle.sh does not require the bootstrap image to carry the Go inputs' commit")
	}
	if !regexp.MustCompile(`ca-bootstrap\) build_args\+=\(--build-arg "COMMIT=\$GO_COMMIT"\)`).MatchString(script) {
		t.Error("scripts/image-bundle.sh does not build the bootstrap image with the Go inputs' commit")
	}

	// What labels it, in the Dockerfile and in compose.
	df := deploytest.ReadFile(t, filepath.Join(root, "Dockerfile"))
	stage := deploytest.DockerfileStage(t, df, "ca-bootstrap")
	if !regexp.MustCompile(`(?m)^ARG COMMIT=unknown$`).MatchString(stage) ||
		!regexp.MustCompile(`(?m)^LABEL dev\.innsegl\.commit=\$\{COMMIT\}$`).MatchString(stage) {
		t.Error("the ca-bootstrap stage does not label its image with its commit")
	}
	if !strings.Contains(stage, "chown 65532:65532 /etc/fulcio-kms") {
		t.Error("the ca-bootstrap stage no longer gives the KMS mountpoint to the CA's uid (OPS-192)")
	}
	custody := deploytest.ReadFile(t, filepath.Join(root, "deploy", "compose", "sigstore.keycustody.yml"))
	if !strings.Contains(custody, "image: "+bootstrapImageRef) {
		t.Errorf("sigstore.keycustody.yml no longer runs the bootstrap as %s", bootstrapImageRef)
	}
	if !strings.Contains(custody, "COMMIT: ${INNSEGL_COMMIT:-unknown}") {
		t.Error("sigstore.keycustody.yml does not pass the commit to the bootstrap's build")
	}
}

func TestOPS232TheLogIsPinnedBeforeCustodyComesUp(t *testing.T) {
	for _, mode := range []string{"live", "dev"} {
		out := makeDryRunCustody(t, mode, "sigstore-up")
		pin := strings.Index(out, "scripts/rekor-tlog-pin.sh record")
		custody := strings.Index(out, "up -d innsegl-ca-store innsegl-ca-custodian")
		if pin < 0 || custody < 0 {
			t.Fatalf("%s: make -n sigstore-up with custody on does not both pin the log and bring "+
				"custody up (pin at %d, custody at %d):\n%s", mode, pin, custody, out)
		}
		if pin > custody {
			t.Errorf("%s: sigstore-up brings custody up before it pins the log, so a custody "+
				"failure leaves the log unpinned and the next start is refused", mode)
		}
	}
}

// OPS-234. The last line of `make start` asks whether the pinned tree is still
// served (OPS-034). rekor-tlog-health.sh looked for the pin under the checkout
// it ran from, while the pin lives in the repository's main worktree (RM-150).
// From a linked worktree, which is where a development stack is brought up,
// the fresh custody bring-up of #622 pinned its tree and the check still said
// "no tree pinned yet". The check reads the pin where rekor-tlog-pin.sh puts it.
func TestOPS234TheReadinessCheckReadsThePinWhereTheBringUpWroteIt(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git is not on PATH: %v", err)
	}
	root := deploytest.RepoRoot(t)
	main := filepath.Join(t.TempDir(), "main")
	for _, name := range []string{"rekor-tlog-health.sh", "rekor-tlog-pin.sh", "repo-main-worktree.sh", "rekor-port.sh"} {
		body := deploytest.ReadFile(t, filepath.Join(root, "scripts", name))
		path := filepath.Join(main, "scripts", name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		deploytest.WriteFile(t, path, body)
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git(main, "init", "-q", "-b", "main")
	git(main, "add", ".")
	git(main, "commit", "-q", "--no-gpg-sign", "-m", "scripts")
	linked := filepath.Join(t.TempDir(), "linked")
	git(main, "worktree", "add", "-q", linked)

	const pinned = "579955947091588685"
	if err := os.MkdirAll(filepath.Join(main, "deploy", "compose"), 0o755); err != nil {
		t.Fatal(err)
	}
	deploytest.WriteFile(t, filepath.Join(main, "deploy", "compose", ".rekor-tlog-id.innsegl-dev"), pinned+"\n")
	rekor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("treeID") != pinned {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"treeID":%q,"treeSize":3}`, pinned)
	}))
	defer rekor.Close()

	cmd := exec.CommandContext(t.Context(), filepath.Join(linked, "scripts", "rekor-tlog-health.sh"), "--url", rekor.URL)
	cmd.Dir = linked
	cmd.Env = append(os.Environ(), "INNSEGL_STACK_PREFIX=innsegl-dev")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("rekor-tlog-health.sh from a linked worktree: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "no tree pinned yet") || !strings.Contains(string(out), pinned) {
		t.Errorf("from a linked worktree the readiness check did not read the main worktree's pin "+
			"(tree %s):\n%s", pinned, out)
	}
}
