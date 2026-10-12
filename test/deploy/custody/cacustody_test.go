// SPDX-License-Identifier: Apache-2.0

package custody

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"innsegl.dev/innsegl/test/deploy/deploytest"

	"innsegl.dev/innsegl/internal/cacustody"
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
		if target == "innsegl-here-services" && !strings.Contains(onRun, deploytest.CoreCustody) {
			t.Errorf("%s with custody on does not bring the core up under %s:\n%s", target, deploytest.CoreCustody, onRun)
		}
	}
}

// The Makefile names every Sigstore service but Fulcio for a custody
// bring-up; a service added to sigstore.yml and missing there would never
// start on a custody host.
func TestOPS149TheCustodyBringUpNamesEverySigstoreServiceButFulcio(t *testing.T) {
	var want []string
	for name := range deploytest.ComposeRender(t, nil, deploytest.SigstoreBase).Services {
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
	sig := deploytest.ComposeRender(t, nil, deploytest.SigstoreBase, deploytest.SigstoreCustod)
	core := deploytest.ComposeRender(t, nil, deploytest.CoreBase, deploytest.CoreCustody)

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
	// What Fulcio holds instead of a token is OPS-187's.

	if got, want := members(sig, "innsegl-ca-store"), []string{"innsegl-ca-bootstrap",
		"innsegl-ca-custodian", "innsegl-ca-import", "innsegl-ca-store"}; !reflect.DeepEqual(got, want) {
		t.Errorf("the store's network admits %v; want %v (ADR-0076)", got, want)
	}
	if got := members(sig, "innsegl-ca-unlock"); !reflect.DeepEqual(got, []string{"innsegl-ca-custodian"}) {
		t.Errorf("the unlock network's Sigstore-side members are %v; want the custodian alone", got)
	}
	if got := members(core, "innsegl-ca-unlock"); !reflect.DeepEqual(got, []string{"innsegl-api", "innsegl-core"}) {
		t.Errorf("the unlock network's core-side members are %v; want innsegl-api and innsegl-core (ADR-0082)", got)
	}
	if n := sig.Networks["innsegl-ca-unlock"]; !n.Internal {
		t.Error("the unlock network is not internal")
	}
	if url := core.Services["innsegl-core"].Environment["INNSEGL_CA_CUSTODIAN_URL"]; url == nil || *url == "" {
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

func strOf(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// members lists the services of doc on network, sorted.
func members(doc deploytest.ComposeDoc, network string) []string {
	var out []string
	for name, s := range doc.Services {
		if _, ok := s.Networks[network]; ok {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// OPS-187 (PROPOSED) — the CA holds no store token (#585). Under custody
// Fulcio mounts no token volume, is not on the store's network, and has no
// token in its environment but the fixed placeholder its KMS client needs to
// start; it reaches the store only through the custodian's gateway, on a
// network the two of them alone share. A token in the operator's environment
// does not reach it either.
func TestOPS187TheCAHoldsNoStoreToken(t *testing.T) {
	sig := deploytest.ComposeRender(t, []string{"INNSEGL_CA_STORE_TOKEN=hvs.from-the-environment"}, deploytest.SigstoreBase, deploytest.SigstoreCustod)
	fulcio := sig.Services["fulcio"]

	tokenVolume := sig.Volumes["innsegl-ca-token"].Name
	for _, v := range fulcio.Volumes {
		if v.Source == "innsegl-ca-token" || v.Source == tokenVolume || strings.Contains(v.Target, "ca-token") {
			t.Errorf("Fulcio mounts the CA's token volume (%s at %s)", v.Source, v.Target)
		}
	}
	for name := range fulcio.Networks {
		if slices.Contains(members(sig, name), "innsegl-ca-store") {
			t.Errorf("Fulcio shares the network %s with the store", name)
		}
	}
	for k, v := range fulcio.Environment {
		val := strOf(v)
		switch {
		case strings.Contains(val, "hvs.from-the-environment"):
			t.Errorf("Fulcio's %s carries the operator's token", k)
		case k == "VAULT_TOKEN":
			if val != cacustody.FulcioPlaceholderToken {
				t.Errorf("Fulcio's VAULT_TOKEN is %q; want only the placeholder %q", val, cacustody.FulcioPlaceholderToken)
			}
		case k == "BAO_TOKEN", strings.Contains(k, "STORE_TOKEN"):
			t.Errorf("Fulcio has %s in its environment", k)
		case k == "HOME" && strings.Contains(val, "ca-token"):
			t.Errorf("Fulcio's HOME is %s, where a token would be read from", val)
		}
	}

	// Its way to the store: the custodian's gateway, by the alias the
	// gateway listens on, on a network of two.
	if addr := fulcio.Environment["VAULT_ADDR"]; addr == nil || *addr != "http://innsegl-ca-signer:8211" {
		t.Fatalf("Fulcio's VAULT_ADDR is %q; want the custodian's gateway", strOf(addr))
	}
	if got, want := members(sig, "innsegl-ca-sign"), []string{"fulcio", "innsegl-ca-custodian"}; !reflect.DeepEqual(got, want) {
		t.Errorf("the CA's network has %v; want %v", got, want)
	}
	if !sig.Networks["innsegl-ca-sign"].Internal {
		t.Error("the CA's network is not internal")
	}
	c := sig.Services["innsegl-ca-custodian"]
	var attach struct {
		Aliases []string `json:"aliases"`
	}
	if raw := c.Networks["innsegl-ca-sign"]; len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &attach); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Contains(attach.Aliases, "innsegl-ca-signer") {
		t.Errorf("the custodian is not innsegl-ca-signer on the CA's network: %+v", attach)
	}
	if l := c.Environment["INNSEGL_CA_SIGN_LISTEN"]; l == nil || *l != "innsegl-ca-signer:8211" {
		t.Errorf("the gateway listens on %q; want the alias on the CA's network alone", strOf(l))
	}

	// The token volume stays mounted while the custodian is replaced, by a
	// container that cannot read it.
	k, ok := sig.Services["innsegl-ca-token-keeper"]
	if !ok {
		t.Fatal("nothing keeps the token volume mounted while the custodian is recreated")
	}
	if k.User == "" || strings.HasPrefix(k.User, "65532") || k.NetworkMode != "none" || !k.ReadOnly {
		t.Errorf("the token keeper runs as %q network %q read_only=%t; want not the CA's uid, no network, read-only",
			k.User, k.NetworkMode, k.ReadOnly)
	}
	held := false
	for _, v := range k.Volumes {
		held = held || (v.Source == "innsegl-ca-token" && v.ReadOnly)
	}
	if !held {
		t.Error("the token keeper does not hold the token volume (read-only)")
	}
}

// OPS-151 (PROPOSED) — under custody the trust backup carries the store and
// the sealed material, and is otherwise the base backup: the overlay repeats
// the base command, and must not drift from it.
func TestOPS151TheBackupCarriesTheStoreAndTheMaterial(t *testing.T) {
	base := deploytest.ComposeRender(t, nil, deploytest.CoreBase).Services["innsegl-trust-backup"]
	on := deploytest.ComposeRender(t, nil, deploytest.CoreBase, deploytest.CoreCustody).Services["innsegl-trust-backup"]
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
	doc := deploytest.ComposeRender(t, nil, deploytest.SigstoreBase, deploytest.SigstoreCustod)
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
	cmd.Dir = deploytest.RepoRoot(t)
	cmd.Env = deploytest.StackEnv(t.TempDir(), "")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n %s: %v\n%s", target, err, out)
	}
	return string(out)
}

// storeConfig is the store's config as compose delivers it: the content of
// the config mounted at /openbao/config/store.hcl.
func storeConfig(t *testing.T, doc deploytest.ComposeDoc) string {
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
	doc := deploytest.ComposeRender(t, nil, deploytest.SigstoreBase, deploytest.SigstoreCustod)
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
	doc := deploytest.ComposeRender(t, nil, deploytest.SigstoreBase, deploytest.SigstoreCustod)
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

// OPS-186 (PROPOSED) — the live path of the custodian's drift check (#582):
// the shipped overlay gives the custodian the very chain the CA presents,
// read-only. Without it INNSEGL_CA_CHAIN_PATH is unset and the check is
// skipped, so a store key and a chain that drifted apart are found only when
// Fulcio refuses to start.
func TestOPS186TheCustodianReadsTheChainTheCAPresents(t *testing.T) {
	sig := deploytest.ComposeRender(t, nil, deploytest.SigstoreBase, deploytest.SigstoreCustod)
	fulcio := sig.Services["fulcio"]
	var chain string
	for _, a := range fulcio.Command {
		if v, ok := strings.CutPrefix(a, "--kms-cert-chain-path="); ok {
			chain = v
		}
	}
	if chain == "" {
		t.Fatalf("Fulcio names no --kms-cert-chain-path: %v", fulcio.Command)
	}
	// The volume Fulcio reads its chain from, and the chain's path inside it.
	var volume, inside string
	for _, v := range fulcio.Volumes {
		if rel, ok := strings.CutPrefix(chain, v.Target+"/"); ok && v.Type == "volume" {
			volume, inside = v.Source, rel
		}
	}
	if volume == "" {
		t.Fatalf("Fulcio's chain %s is on no volume it mounts", chain)
	}

	c := sig.Services["innsegl-ca-custodian"]
	got := c.Environment["INNSEGL_CA_CHAIN_PATH"]
	if got == nil || *got == "" {
		t.Fatal("the custodian is not given INNSEGL_CA_CHAIN_PATH: its drift check never runs")
	}
	found := false
	for _, v := range c.Volumes {
		if v.Source != volume {
			continue
		}
		found = true
		if !v.ReadOnly {
			t.Errorf("the custodian mounts %s writable; it only reads the chain", volume)
		}
		if want := v.Target + "/" + inside; *got != want {
			t.Errorf("INNSEGL_CA_CHAIN_PATH is %s; the chain the CA presents is at %s", *got, want)
		}
	}
	if !found {
		t.Errorf("the custodian does not mount %s, where the CA's chain is", volume)
	}
}
