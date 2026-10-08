// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// OPS-149..OPS-151 (PROPOSED for doc 07's TC-OPS) — CA key custody unlocked by
// the operator's machine (#533, ADR-0076), as the shipped files say it.
//
// What has to hold: it is off unless a deployment's .env turns it on, so the
// default is still the file CA OPS-051 requires; when on, every bring-up runs
// Fulcio under the overlay (a `make start` that dropped it would put the file
// CA back); the store's network admits the custodian and nobody new besides;
// the unlock network has two members; the CA holds no key and no token in
// its environment; and the trust backup carries what a restore needs.
// ---------------------------------------------------------------------------

type renderedService struct {
	Image       string                     `json:"image"`
	User        string                     `json:"user"`
	ReadOnly    bool                       `json:"read_only"`
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

type composeDoc struct {
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
	} `json:"volumes"`
}

func composeRender(t *testing.T, env []string, files ...string) composeDoc {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is not on PATH: %v", err)
	}
	root := repoRoot(t)
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
	var doc composeDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

const (
	sigstoreBase   = "deploy/compose/sigstore.yml"
	sigstoreCustod = "deploy/compose/sigstore.keycustody.yml"
	coreBase       = "deploy/compose/innsegl.yml"
	coreCustody    = "deploy/compose/innsegl.custody.yml"
)

// OPS-149 (PROPOSED) — off unless .env turns it on; on, every bring-up and
// update of Fulcio and the core carries both overlays.
func TestOPS149CustodyIsOnOnlyWhereEnvTurnsItOn(t *testing.T) {
	dir := t.TempDir()
	on := filepath.Join(dir, "on.env")
	off := filepath.Join(dir, "off.env")
	if err := os.WriteFile(on, []byte("COMPOSE_PROFILES=trust-backup\nINNSEGL_CA_CUSTODY=on\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(off, []byte("COMPOSE_PROFILES=trust-backup\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"sigstore-up", "rekor-log-up", "fulcio-file-ca-up", "innsegl-here-services"} {
		offRun := makeDryRunEnv(t, target, "COMPOSE_ENV_FILE="+off)
		if strings.Contains(offRun, "keycustody") || strings.Contains(offRun, "innsegl.custody.yml") {
			t.Errorf("%s with custody off names a custody overlay; the default must stay the file CA (OPS-051)", target)
		}
		onRun := makeDryRunEnv(t, target, "COMPOSE_ENV_FILE="+on)
		// rekor-log-up names the log's services alone and never Fulcio, so
		// it needs no overlay; the other two are how Fulcio comes up.
		// sigstore-up calls the target by name; fulcio-file-ca-up has it as a
		// prerequisite, so its dry run shows what the target runs.
		brought := strings.Contains(onRun, "ca-custody-up") || strings.Contains(onRun, "up -d innsegl-ca-store innsegl-ca-custodian")
		if target != "innsegl-here-services" && target != "rekor-log-up" && !brought {
			t.Errorf("%s with custody on does not bring the store up (ca-custody-up):\n%s", target, onRun)
		}
		if target == "innsegl-here-services" && !strings.Contains(onRun, coreCustody) {
			t.Errorf("%s with custody on does not bring the core up under %s:\n%s", target, coreCustody, onRun)
		}
	}
}

// The Makefile names every Sigstore service but Fulcio for a custody
// bring-up; a service added to sigstore.yml and missing there would never
// start on a custody host.
func TestOPS149TheCustodyBringUpNamesEverySigstoreServiceButFulcio(t *testing.T) {
	var want []string
	for name := range composeRender(t, nil, sigstoreBase).Services {
		if name != "fulcio" {
			want = append(want, name)
		}
	}
	slices.Sort(want)
	out := makeDryRunEnv(t, "-p", "COMPOSE_ENV_FILE=/dev/null")
	var got []string
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(line, "SIGSTORE_UP_EXCEPT_FULCIO = "); ok {
			got = strings.Fields(v)
		}
	}
	slices.Sort(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SIGSTORE_UP_EXCEPT_FULCIO is %v; sigstore.yml's services but Fulcio are %v", got, want)
	}
}

// OPS-150 (PROPOSED) — the rendered overlay: the CA holds no key and no
// token in its environment; the store's network admits the custodian and
// nobody new; the unlock network has the custodian and the core alone.
func TestOPS150TheCustodyNetworksAndTheCAsHands(t *testing.T) {
	sig := composeRender(t, nil, sigstoreBase, sigstoreCustod)
	core := composeRender(t, nil, coreBase, coreCustody)

	fulcio := sig.Services["fulcio"]
	if !slices.Contains(fulcio.Command, "--ca=kmsca") {
		t.Fatalf("Fulcio is not on the store under the overlay: %v", fulcio.Command)
	}
	for _, v := range fulcio.Volumes {
		if strings.Contains(v.Source, "fulcio-pki") {
			t.Errorf("Fulcio mounts the file CA's volume %s, which holds a key", v.Source)
		}
		if !v.ReadOnly {
			t.Errorf("Fulcio mounts %s writable", v.Target)
		}
	}
	if tok := fulcio.Environment["VAULT_TOKEN"]; tok != nil && *tok != "" {
		t.Errorf("Fulcio has a token in its environment: a reader of the container's config would have it")
	}
	if home := fulcio.Environment["HOME"]; home == nil || *home != "/run/ca-token" {
		t.Errorf("Fulcio's HOME is %v; its KMS client reads ~/.vault-token from the token volume", home)
	}

	members := func(doc composeDoc, network string) []string {
		var out []string
		for name, s := range doc.Services {
			if _, ok := s.Networks[network]; ok {
				out = append(out, name)
			}
		}
		slices.Sort(out)
		return out
	}
	if got, want := members(sig, "innsegl-ca-store"), []string{"fulcio", "innsegl-ca-bootstrap",
		"innsegl-ca-custodian", "innsegl-ca-import", "innsegl-ca-store"}; !reflect.DeepEqual(got, want) {
		t.Errorf("the store's network admits %v; want %v (ADR-0076)", got, want)
	}
	if got := members(sig, "innsegl-ca-unlock"); !reflect.DeepEqual(got, []string{"innsegl-ca-custodian"}) {
		t.Errorf("the unlock network's Sigstore-side members are %v; want the custodian alone", got)
	}
	if got := members(core, "innsegl-ca-unlock"); !reflect.DeepEqual(got, []string{"innsegl-mcp"}) {
		t.Errorf("the unlock network's core-side members are %v; want innsegl-mcp alone", got)
	}
	if n := sig.Networks["innsegl-ca-unlock"]; !n.Internal {
		t.Error("the unlock network is not internal")
	}
	if url := core.Services["innsegl-mcp"].Environment["INNSEGL_CA_CUSTODIAN_URL"]; url == nil || *url == "" {
		t.Error("the core is not told where the custodian is")
	}

	c := sig.Services["innsegl-ca-custodian"]
	if c.User != "65532:65532" || !c.ReadOnly {
		t.Errorf("the custodian runs as %q read_only=%t; want the CA's uid and a read-only root", c.User, c.ReadOnly)
	}
	tv := sig.Volumes["innsegl-ca-token"]
	if tv.DriverOpts["type"] != "tmpfs" {
		t.Errorf("the CA's token volume is %+v; want memory-backed", tv)
	}

	var images []string
	for _, name := range []string{"innsegl-ca-store", "innsegl-ca-import"} {
		images = append(images, sig.Services[name].Image)
	}
	for _, img := range images {
		if !strings.Contains(img, "@sha256:") || img != images[0] {
			t.Errorf("the store images are %v; want one pinned reference", images)
			break
		}
	}
}

// OPS-151 (PROPOSED) — under custody the trust backup carries the store and
// the sealed material, and is otherwise the base backup: the overlay repeats
// the base command, and must not drift from it.
func TestOPS151TheBackupCarriesTheStoreAndTheMaterial(t *testing.T) {
	base := composeRender(t, nil, coreBase).Services["innsegl-trust-backup"]
	on := composeRender(t, nil, coreBase, coreCustody).Services["innsegl-trust-backup"]
	// The store's own snapshot, not its files: a copy of the files taken
	// while the store writes is not a backup (OPS-155). And the marker the
	// drill reads to require both (BAK-030).
	want := append(slices.Clone(base.Command),
		"--path", "ca-store=/in/ca-custody/snapshot", "--path", "ca-custody=/in/ca-custody/material",
		"--value", "custody=INNSEGL_CA_CUSTODY")
	if !reflect.DeepEqual(on.Command, want) {
		t.Fatalf("the custody backup's command is not the base command plus the two custody items:\n got %v\nwant %v",
			on.Command, want)
	}
	ro, found := false, false
	for _, v := range on.Volumes {
		if v.Target == "/in/ca-custody" {
			found, ro = true, v.ReadOnly
		}
		if v.Target == "/in/ca-store" {
			t.Errorf("the backup mounts the store's raw files (%s); it carries the store's snapshot instead", v.Source)
		}
	}
	if !found || !ro {
		t.Fatalf("the custody volume is not mounted read-only for the backup")
	}
	if v := on.Environment["INNSEGL_CA_CUSTODY"]; v == nil || *v != "on" {
		t.Fatalf("the backup does not mark its bundles as custody bundles: %v", v)
	}
}

// OPS-155 (PROPOSED) — the store keeps integrated storage, which can
// snapshot itself, on the directory the store image owns.
func TestOPS155TheStoreCanSnapshotItself(t *testing.T) {
	doc := composeRender(t, nil, sigstoreBase, sigstoreCustod)
	hcl := storeConfig(t, doc)
	if !strings.Contains(hcl, `storage "raft"`) || !strings.Contains(hcl, `path    = "/openbao/file"`) {
		t.Fatalf("the store's config does not use integrated storage on /openbao/file:\n%s", hcl)
	}
	store := doc.Services["innsegl-ca-store"]
	mounted := false
	for _, v := range store.Volumes {
		if v.Target == "/openbao/file" {
			mounted = true
		}
	}
	if !mounted {
		t.Fatal("the store's volume is not mounted on /openbao/file, the directory the image owns and the config names")
	}
}

// makeDryRunEnv is `make -n target` with extra variables on the command line.
func makeDryRunEnv(t *testing.T, target string, vars ...string) string {
	t.Helper()
	if _, err := exec.LookPath("make"); err != nil {
		t.Skipf("make is not on PATH: %v", err)
	}
	args := append([]string{"-n", "--no-print-directory", target}, vars...)
	cmd := exec.CommandContext(t.Context(), "make", args...)
	cmd.Dir = repoRoot(t)
	cmd.Env = stackEnv(t.TempDir(), "")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n %s: %v\n%s", target, err, out)
	}
	return string(out)
}

// storeConfig is the store's config as compose delivers it: the content of
// the config mounted at /openbao/config/store.hcl.
func storeConfig(t *testing.T, doc composeDoc) string {
	t.Helper()
	for _, c := range doc.Services["innsegl-ca-store"].Configs {
		if c.Target == "/openbao/config/store.hcl" {
			return doc.Configs[c.Source].Content
		}
	}
	t.Fatal("the store has no config at /openbao/config/store.hcl")
	return ""
}

// OPS-157 (PROPOSED) — the store reads its config whatever the checkout's
// file modes are.
//
// MEASURED on a core whose operator's umask is 0077: every file the checkout
// wrote was mode 600, the store (a non-root user) could not read the config
// bind-mounted from it, and restarted forever on "permission denied". CI's
// umask is 022, so nothing there saw it. Compose delivers inline config
// content into the container with the mode it is given; a bind mount carries
// the host file's mode.
func TestOPS157TheStoreConfigDoesNotDependOnTheCheckoutsFileModes(t *testing.T) {
	doc := composeRender(t, nil, sigstoreBase, sigstoreCustod)
	store := doc.Services["innsegl-ca-store"]
	for _, v := range store.Volumes {
		if v.Type == "bind" {
			t.Fatalf("the store bind-mounts %s from the host; under a 0077 umask its user cannot read it", v.Source)
		}
	}
	for _, c := range store.Configs {
		if c.Target != "/openbao/config/store.hcl" {
			continue
		}
		if doc.Configs[c.Source].File != "" || doc.Configs[c.Source].Content == "" {
			t.Fatalf("the store's config %q is a host file, which compose bind-mounts with the host's mode", c.Source)
		}
		if m := strings.Trim(string(c.Mode), `"`); m != "0444" && m != "292" {
			t.Fatalf("the store's config is not delivered readable by every user (mode 0444): %s", c.Mode)
		}
		return
	}
	t.Fatal("the store has no config at /openbao/config/store.hcl")
}

// OPS-158 (PROPOSED) — the store's health check asks the store over the
// scheme it listens on.
//
// MEASURED on a live core: `bao status` defaults to https://127.0.0.1:8200,
// the store listens without TLS on its two-member network, so the check
// failed every time ("server gave HTTP response to HTTPS client"), the store
// was never healthy, and `make update` stopped on the custodian's
// depends_on. Against http the same command answers 2, sealed, as designed.
func TestOPS158TheStoreHealthCheckUsesTheListenersScheme(t *testing.T) {
	doc := composeRender(t, nil, sigstoreBase, sigstoreCustod)
	hcl := storeConfig(t, doc)
	if !strings.Contains(hcl, "tls_disable = true") {
		t.Skip("the store listens with TLS; this case is for the plain listener")
	}
	addr := doc.Services["innsegl-ca-store"].Environment["BAO_ADDR"]
	if addr == nil || *addr != "http://127.0.0.1:8200" {
		t.Fatalf("the store's BAO_ADDR is %v; bao status then speaks https to a plain listener and the health check never passes", addr)
	}
}

// OPS-160 (PROPOSED) — the custodian runs the image this checkout builds.
//
// MEASURED on a live core: `make update` brought the store and its
// custodian up (fulcio-file-ca-up) before it built innsegl:local
// (innsegl-here-services). The custodian, which runs that image, provisioned
// a fresh store with the previous build's policy, and Fulcio's signing was
// refused again after the fix had merged. The image comes first.
func TestOPS160TheCustodianRunsTheImageThisCheckoutBuilds(t *testing.T) {
	on := filepath.Join(t.TempDir(), "on.env")
	if err := os.WriteFile(on, []byte("INNSEGL_CA_CUSTODY=on\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"ca-custody-up", "fulcio-file-ca-up"} {
		run := makeDryRunEnv(t, target, "COMPOSE_ENV_FILE="+on)
		img := strings.Index(run, "image-bundle.sh find")
		up := strings.Index(run, "up -d innsegl-ca-store innsegl-ca-custodian")
		if up < 0 {
			t.Fatalf("%s does not bring the custodian up:\n%s", target, run)
		}
		if img < 0 || img > up {
			t.Errorf("%s brings the custodian up before it builds or loads the innsegl image (image at %d, custodian at %d)", target, img, up)
		}
	}
}
