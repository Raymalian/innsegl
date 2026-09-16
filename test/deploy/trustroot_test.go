// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// The durable trust root — OPS-031..OPS-035 (PROPOSED for doc 07's TC-OPS).
//
// WHAT THESE MEASURE, and why they are worth the containers they cost.
//
// On 2026-09-16 a teardown with volumes removed, in one command, took the
// ledger from 19,595 chain positions to 60, the transparency log from 525
// entries to 3, and minted a new Fulcio CA key and a new Rekor signing key.
// Commits signed the previous day stopped verifying: the signature is intact
// and the trailer still matches the certificate; the CA that issued it and the
// log that recorded it are gone. There is no repair — see doc 05 §2 and the
// local decision record for the full account.
//
// The rule that follows is one sentence: THE TRUST ROOT MUST NOT LIVE WHERE
// THE TEARDOWN REACHES. A compose project's volumes are exactly what `down -v`
// removes, and the CA key, the log key, the log and the ledger were all in
// them.
//
// So these are the four defences, each measured rather than asserted:
//
//   OPS-031  a teardown that would destroy a key or the chain is REFUSED,
//            and the same teardown with the deliberate opt-out succeeds.
//   OPS-032  the irreplaceable volumes are declared outside the compose
//            project, so `down -v` can only detach them.
//   OPS-033  bringing the stack up on a machine that has never run it creates
//            them, and never silently adopts another deployment's.
//   OPS-034  readiness says "the pinned tree is absent" in those words.
//   OPS-035  the backup that already exists runs on a timer.
//   OPS-036  bring-up rebuilds the search index `down -v` takes with it.
//
// A refusal nobody has watched happen is not known to work, which is why
// OPS-031 runs a real `docker compose down -v` against a real project and
// reads the real exit status — and why it proves the refusal is THE GUARD by
// sending an unprotected volume in the SAME project through the SAME command.
// ---------------------------------------------------------------------------

// exitRefused is scripts/teardown-guard.sh's status for "this would have
// destroyed the trust root". Distinct from 1 so a caller can tell a refusal
// from a broken command, the same way verify-branch.sh separates 3 from 4.
const exitRefused = 9

// trustVolumeKeys are the compose volume KEYS the guard protects. Spelled out
// here rather than read from the guard: a test that took its expectations from
// the thing under test would agree with it by construction.
//
// THE FIFTH ONE WAS FOUND BY LOSING IT. innsegl-identity-secret was not on
// this list, so proving OPS-032 destroyed it — and the deployment minted a new
// one, after which the SAME task string "main" pseudonymised to a different
// id. The run that had been registered minutes earlier could no longer claim a
// commit: "Agent-Task is 4a3f6604, which does not lowercase to the task
// 6ddc6071 in Agent-Identity". Nothing already signed stopped verifying — the
// discontinuity is in ATTRIBUTION, not in the proof — but every pseudonym in
// the ledger now names an agent and a task that no future run will ever
// reproduce. ADR-0041 (#124) makes it per-deployment on purpose; that is
// exactly what makes it unrecoverable.
var trustVolumeKeys = []string{
	"innsegl-ledger-data",
	"innsegl-identity-secret",
	"sigstore-fulcio-pki",
	"sigstore-rekor-key",
	"sigstore-trillian-db-data",
}

// ---------------------------------------------------------------------------
// OPS-031 — the teardown that refuses.
// ---------------------------------------------------------------------------

func TestOPS031TeardownRefusesToDestroyTheTrustRoot(t *testing.T) {
	ctx := t.Context()
	if err := dockerUsable(ctx); err != nil {
		t.Skipf("skipping OPS-031: %v. A refusal nobody has watched happen is "+
			"not known to work, so this runs a real `docker compose down -v` "+
			"against a real project rather than a parsed command line", err)
	}
	root := repoRoot(t)
	guard := filepath.Join(root, "scripts", "teardown-guard.sh")

	project := uniqueName(t, "innsegl-guardtest")
	dir := t.TempDir()
	// The protected volume carries one of the four shipped KEYS; the scratch
	// volume does not. Both live in one project and are removed by one
	// command, which is what makes the refusal attributable to the guard.
	// TWO protected volumes and not one. An opt-out naming a single volume is
	// the case that hides a whole class of bug — measured: the first version
	// of the guard released only the LAST name in a list and refused the rest,
	// and a one-name test passes that every time.
	protectedVol := project + "-rekor-key"
	otherVol := project + "-fulcio-pki"
	scratchVol := project + "-scratch"
	writeFile(t, filepath.Join(dir, "compose.yml"), fmt.Sprintf(`name: %s
services:
  keeper:
    image: alpine:3.20
    command: ["sleep", "600"]
    volumes:
      - sigstore-rekor-key:/key
      - sigstore-fulcio-pki:/pki
      - scratch:/scratch
volumes:
  sigstore-rekor-key:
    name: %s
  sigstore-fulcio-pki:
    name: %s
  scratch:
    name: %s
`, project, protectedVol, otherVol, scratchVol))

	t.Cleanup(func() {
		//nolint:usetesting // cleanup must outlive the test's cancelled context
		c := context.Background()
		discardError(docker(c, "compose", "-f", filepath.Join(dir, "compose.yml"), "down", "-v"))
		discardError(docker(c, "volume", "rm", "--force", protectedVol, otherVol, scratchVol))
	})

	if out, err := docker(ctx, "compose", "-f", filepath.Join(dir, "compose.yml"), "up", "-d"); err != nil {
		t.Fatalf("bringing the throwaway project up: %v\n%s", err, out)
	}

	// --- 1. the refusal ----------------------------------------------------
	out, code := run(t, guard, nil,
		"docker", "compose", "-f", filepath.Join(dir, "compose.yml"), "down", "-v")
	if code != exitRefused {
		t.Fatalf("a `down -v` that would destroy %s exited %d, want %d (refused).\n%s",
			protectedVol, code, exitRefused, out)
	}
	for _, v := range []string{protectedVol, otherVol} {
		if !strings.Contains(out, v) {
			t.Errorf("the refusal never names %s. A gate that will not say what it "+
				"would have destroyed leaves the operator to guess:\n%s", v, out)
		}
	}
	for _, phrase := range []string{"REFUSED", "trust root"} {
		if !strings.Contains(out, phrase) {
			t.Errorf("the refusal never says %q:\n%s", phrase, out)
		}
	}

	// The refusal must be a refusal and not a half-executed teardown.
	if !volumeExists(ctx, protectedVol) {
		t.Fatalf("%s is gone after a REFUSED teardown", protectedVol)
	}
	if !volumeExists(ctx, scratchVol) {
		t.Errorf("%s is gone after a REFUSED teardown: the guard let the command "+
			"run and then complained, which is not a gate", scratchVol)
	}
	if ids, err := docker(ctx, "compose", "-f", filepath.Join(dir, "compose.yml"), "ps", "-q"); err != nil || ids == "" {
		t.Errorf("the containers are gone after a REFUSED teardown (%v): a refusal "+
			"that still stops the stack is a teardown with a rude message", err)
	}

	// --- 2. the refusal is THE GUARD, not an unrelated error ---------------
	//
	// The same guard, the same docker, the same project — a `down` WITHOUT
	// -v touches no volume and must pass straight through.
	plainOut, plainCode := run(t, guard, nil,
		"docker", "compose", "-f", filepath.Join(dir, "compose.yml"), "down")
	if plainCode != 0 {
		t.Fatalf("a `down` with no -v was refused (exit %d). The guard is refusing "+
			"something other than volume removal:\n%s", plainCode, plainOut)
	}
	if !volumeExists(ctx, protectedVol) {
		t.Fatalf("`down` with no -v removed %s", protectedVol)
	}

	// --- 3. an opt-out that names ONE does not release the others ----------
	//
	// The naming is the decision, so it is a decision about each volume. An
	// operator who means to destroy one must not destroy the rest with the
	// same keystroke.
	partial, partialCode := run(t, guard,
		[]string{"INNSEGL_DESTROY_TRUST_ROOT=" + protectedVol},
		"docker", "compose", "-f", filepath.Join(dir, "compose.yml"), "down", "-v")
	if partialCode != exitRefused {
		t.Fatalf("an opt-out naming only %s exited %d, want %d: it released %s "+
			"too, which nobody asked for.\n%s",
			protectedVol, partialCode, exitRefused, otherVol, partial)
	}
	if !strings.Contains(partial, otherVol) {
		t.Errorf("the partial refusal does not name the volume still at risk:\n%s", partial)
	}
	if !volumeExists(ctx, protectedVol) || !volumeExists(ctx, otherVol) {
		t.Fatalf("a REFUSED teardown removed something")
	}

	// --- 4. the deliberate opt-out succeeds --------------------------------
	//
	// Naming the volumes is the opt-out. Not a yes, not a 1: the difference
	// between a decision and an accident is that a decision says what it is
	// destroying. More than one name, because a list of one is the case that
	// passes even when list handling is broken.
	out, code = run(t, guard,
		[]string{"INNSEGL_DESTROY_TRUST_ROOT=" + protectedVol + "," + otherVol},
		"docker", "compose", "-f", filepath.Join(dir, "compose.yml"), "down", "-v")
	if code != 0 {
		t.Fatalf("the deliberate opt-out was still refused (exit %d). An operator "+
			"who means it must have a way to say so:\n%s", code, out)
	}
	for _, v := range []string{protectedVol, otherVol} {
		if volumeExists(ctx, v) {
			t.Errorf("%s survived a teardown that named it in the opt-out: the escape "+
				"hatch does not work, which makes the gate a wall", v)
		}
	}

	// --- 5. a yes that names nothing is not an opt-out ----------------------
	if out, code := run(t, guard, []string{"INNSEGL_DESTROY_TRUST_ROOT=1"},
		"docker", "volume", "rm", "--force", scratchVol); code != 0 {
		t.Logf("unprotected volume removal with a junk opt-out: exit %d\n%s", code, out)
	}
}

// TestOPS031RefusesRemovalByName covers the other door into the same data: the
// volumes are external after OPS-032, so `down -v` can only detach them and
// `docker volume rm` is what actually destroys one. A guard that watched only
// compose would be guarding the door nobody uses.
func TestOPS031RefusesRemovalByName(t *testing.T) {
	ctx := t.Context()
	if err := dockerUsable(ctx); err != nil {
		t.Skipf("skipping OPS-031 (by name): %v", err)
	}
	root := repoRoot(t)
	guard := filepath.Join(root, "scripts", "teardown-guard.sh")

	name := uniqueName(t, "innsegl-guardtest") + "-fulcio-pki"
	if _, err := docker(ctx, "volume", "create",
		"--label", "dev.innsegl.trust-root=the Fulcio CA key",
		"--label", "dev.innsegl.deployment=ops031",
		name); err != nil {
		t.Fatalf("creating the labelled volume: %v", err)
	}
	t.Cleanup(func() {
		//nolint:usetesting // cleanup must outlive the test's cancelled context
		discardError(docker(context.Background(), "volume", "rm", "--force", name))
	})

	out, code := run(t, guard, nil, "docker", "volume", "rm", name)
	if code != exitRefused {
		t.Fatalf("`docker volume rm %s` exited %d, want %d. The label is the only "+
			"thing that identifies a trust volume once it is external:\n%s",
			name, code, exitRefused, out)
	}
	if !strings.Contains(out, "the Fulcio CA key") {
		t.Errorf("the refusal never says WHAT the volume holds:\n%s", out)
	}
	if !volumeExists(ctx, name) {
		t.Fatalf("%s was removed by a refused command", name)
	}

	if out, code := run(t, guard, []string{"INNSEGL_DESTROY_TRUST_ROOT=" + name},
		"docker", "volume", "rm", name); code != 0 {
		t.Fatalf("the named opt-out did not let the removal through (exit %d):\n%s", code, out)
	}
	if volumeExists(ctx, name) {
		t.Errorf("%s survived its own named removal", name)
	}
}

// ---------------------------------------------------------------------------
// OPS-032 — the trust root lives outside the compose project.
// ---------------------------------------------------------------------------

func TestOPS032TheIrreplaceableVolumesAreExternal(t *testing.T) {
	ctx := t.Context()
	if err := dockerUsable(ctx); err != nil {
		t.Skipf("skipping OPS-032: %v", err)
	}
	root := repoRoot(t)

	// Compose's OWN answer, not a grep of the YAML. A file that reads as if a
	// volume were external and resolves to something else is precisely the
	// failure this is here to catch.
	// What `make` passes, spelled out rather than read back from
	// deploy/compose/trust-volumes.sh: a test that took its expectations from
	// the thing under test would agree with it by construction.
	env := []string{
		"INNSEGL_TRUST_VOLUMES_EXTERNAL=true",
		"INNSEGL_TRUST_LEDGER_VOLUME=innsegl-trust-ledger-data",
		"INNSEGL_TRUST_IDENTITY_SECRET_VOLUME=innsegl-trust-identity-secret",
		"INNSEGL_TRUST_FULCIO_PKI_VOLUME=innsegl-trust-fulcio-pki",
		"INNSEGL_TRUST_REKOR_KEY_VOLUME=innsegl-trust-rekor-key",
		"INNSEGL_TRUST_TRILLIAN_DB_VOLUME=innsegl-trust-trillian-db",
		"INNSEGL_SPIRE_JWT_ISSUER=http://spire-oidc:8080",
		"INNSEGL_SPIRE_PARENT_ID=unset",
	}
	wantName := map[string]string{
		"innsegl-ledger-data":       "innsegl-trust-ledger-data",
		"innsegl-identity-secret":   "innsegl-trust-identity-secret",
		"sigstore-fulcio-pki":       "innsegl-trust-fulcio-pki",
		"sigstore-rekor-key":        "innsegl-trust-rekor-key",
		"sigstore-trillian-db-data": "innsegl-trust-trillian-db",
	}
	found := map[string]composeVolume{}
	for _, rel := range []string{"deploy/compose/sigstore.yml", "deploy/compose/innsegl.yml"} {
		for key, v := range composeVolumes(t, root, rel, env) {
			found[key] = v
		}
	}
	for _, key := range trustVolumeKeys {
		v, ok := found[key]
		if !ok {
			t.Errorf("no compose file declares the volume %q", key)
			continue
		}
		if !v.External {
			t.Errorf("%s resolves to external=false. `down -v` removes exactly the "+
				"volumes a project owns, and this one holds a key or the chain", key)
		}
		if v.Name != wantName[key] {
			t.Errorf("%s resolves to name %q, want %q", key, v.Name, wantName[key])
		}
		t.Logf("external  %-26s -> %s", key, v.Name)
	}

	// Everything else must stay project-local. A blanket `external: true` over
	// the whole file would pass the loop above and quietly make `down -v` a
	// no-op for the workspace, the demo repo and the session store.
	for key, v := range found {
		if v.External && !isTrustVolumeKey(key) && key != "spire-agent-socket" {
			t.Errorf("%s is external and is not part of the trust root. "+
				"`down -v` is supposed to still work", key)
		}
	}

	// --- the mechanism, measured ------------------------------------------
	//
	// Compose's config output says what the file MEANS; this says what docker
	// DOES. One external volume and one project-local volume, one `down -v`:
	// the external one survives and the local one does not, so the survival is
	// the declaration and not a teardown that did nothing.
	project := uniqueName(t, "innsegl-exttest")
	dir := t.TempDir()
	external := project + "-external"
	local := project + "-local"
	if _, err := docker(ctx, "volume", "create", external); err != nil {
		t.Fatalf("creating the external volume: %v", err)
	}
	writeFile(t, filepath.Join(dir, "compose.yml"), fmt.Sprintf(`name: %s
services:
  keeper:
    image: alpine:3.20
    command: ["sh", "-c", "echo trust-root > /e/mark; echo scratch > /l/mark; sleep 600"]
    volumes:
      - ext:/e
      - loc:/l
volumes:
  ext:
    name: %s
    external: true
  loc:
    name: %s
`, project, external, local))
	t.Cleanup(func() {
		//nolint:usetesting // cleanup must outlive the test's cancelled context
		c := context.Background()
		discardError(docker(c, "compose", "-f", filepath.Join(dir, "compose.yml"), "down", "-v"))
		discardError(docker(c, "volume", "rm", "--force", external, local))
	})

	if out, err := docker(ctx, "compose", "-f", filepath.Join(dir, "compose.yml"), "up", "-d", "--wait"); err != nil {
		t.Logf("up --wait: %v\n%s", err, out)
	}
	if got := readMark(ctx, external); got != "trust-root" {
		t.Fatalf("the external volume never got its mark: %q", got)
	}
	if out, err := docker(ctx, "compose", "-f", filepath.Join(dir, "compose.yml"), "down", "-v"); err != nil {
		t.Fatalf("down -v: %v\n%s", err, out)
	}
	if volumeExists(ctx, local) {
		t.Fatalf("`down -v` left the project-local volume %s behind, so this run "+
			"proves nothing about what it removes", local)
	}
	if !volumeExists(ctx, external) {
		t.Fatalf("`down -v` removed the EXTERNAL volume %s", external)
	}
	if got := readMark(ctx, external); got != "trust-root" {
		t.Errorf("the external volume survived `down -v` empty: %q", got)
	}
}

// ---------------------------------------------------------------------------
// OPS-033 — created if absent, never silently another deployment's.
// ---------------------------------------------------------------------------

func TestOPS033TrustVolumesAreCreatedAndNeverAdopted(t *testing.T) {
	ctx := t.Context()
	if err := dockerUsable(ctx); err != nil {
		t.Skipf("skipping OPS-033: %v", err)
	}
	root := repoRoot(t)
	ensure := filepath.Join(root, "deploy", "compose", "trust-volumes.sh")

	prefix := uniqueName(t, "innsegl-trusttest")
	env := []string{"INNSEGL_TRUST_VOLUME_PREFIX=" + prefix}
	names := []string{
		prefix + "-ledger-data",
		prefix + "-identity-secret",
		prefix + "-fulcio-pki",
		prefix + "-rekor-key",
		prefix + "-trillian-db",
	}
	t.Cleanup(func() {
		//nolint:usetesting // cleanup must outlive the test's cancelled context
		c := context.Background()
		for _, n := range names {
			discardError(docker(c, "volume", "rm", "--force", n))
		}
	})

	// --- 1. a machine that has never run this ------------------------------
	out, code := run(t, ensure, env, "ensure")
	if code != 0 {
		t.Fatalf("ensure on a clean machine exited %d. Bringing the stack up must "+
			"work on a machine that has never run it:\n%s", code, out)
	}
	var stamp string
	for _, n := range names {
		if !volumeExists(ctx, n) {
			t.Fatalf("ensure did not create %s:\n%s", n, out)
		}
		got := volumeLabel(ctx, n, "dev.innsegl.deployment")
		if got == "" {
			t.Fatalf("%s carries no dev.innsegl.deployment label; nothing can tell "+
				"whose trust root it is", n)
		}
		if stamp == "" {
			stamp = got
		} else if got != stamp {
			t.Errorf("%s is stamped %q but the set is stamped %q: the four are one "+
				"trust root and must carry one id", n, got, stamp)
		}
		if volumeLabel(ctx, n, "dev.innsegl.trust-root") == "" {
			t.Errorf("%s carries no dev.innsegl.trust-root label, so "+
				"scripts/teardown-guard.sh cannot recognise it by name", n)
		}
	}

	// --- 2. a second ensure reuses them ------------------------------------
	again, againCode := run(t, ensure, env, "ensure")
	if againCode != 0 {
		t.Fatalf("a second ensure exited %d; it must be a no-op:\n%s", againCode, again)
	}
	for _, n := range names {
		if got := volumeLabel(ctx, n, "dev.innsegl.deployment"); got != stamp {
			t.Errorf("%s was re-stamped %q over %q: ensure destroyed the identity "+
				"it exists to preserve", n, got, stamp)
		}
	}

	// --- 3. another deployment's volume is refused, not adopted ------------
	foreign := names[1]
	if _, err := docker(ctx, "volume", "rm", "--force", foreign); err != nil {
		t.Fatalf("removing %s to re-create it under a foreign stamp: %v", foreign, err)
	}
	if _, err := docker(ctx, "volume", "create",
		"--label", "dev.innsegl.trust-root=the Fulcio CA key",
		"--label", "dev.innsegl.deployment=some-other-deployment",
		foreign); err != nil {
		t.Fatalf("creating the foreign volume: %v", err)
	}
	out, code = run(t, ensure, env, "ensure")
	if code == 0 {
		t.Fatalf("ensure adopted a volume stamped for another deployment. Booting "+
			"onto someone else's CA key is how a trust root gets mixed:\n%s", out)
	}
	if !strings.Contains(out, "some-other-deployment") || !strings.Contains(out, foreign) {
		t.Errorf("the refusal names neither the volume nor the stamp it carries:\n%s", out)
	}
}

// TestOPS033EnsureMigratesAnEmptyDestination — a volume that exists and is
// empty is not a migrated volume.
//
// MEASURED. `ensure` migrated only when it had just CREATED the destination.
// So a run that created the volume and then refused the copy — because the
// stack was still up, which is the refusal working correctly — left an empty
// external volume behind, and every `ensure` afterwards reported it "ok". The
// deployment would have booted onto an empty trust volume with the real bytes
// sitting in the volume beside it, and the report would have said fine.
//
// The condition is therefore the DESTINATION BEING EMPTY, not the destination
// being new. INNSEGL_TRUST_LEGACY_PREFIX is what makes this measurable at all:
// migration is otherwise restricted to the default prefix precisely so a test
// can never inherit the real deployment's CA key, and this names a legacy set
// of the test's own instead.
func TestOPS033EnsureMigratesAnEmptyDestination(t *testing.T) {
	ctx := t.Context()
	if err := dockerUsable(ctx); err != nil {
		t.Skipf("skipping OPS-033 (migration): %v", err)
	}
	ensure := filepath.Join(repoRoot(t), "deploy", "compose", "trust-volumes.sh")

	prefix := uniqueName(t, "innsegl-migtest")
	legacy := prefix + "-old"
	dest := prefix + "-fulcio-pki"
	src := legacy + "-fulcio-pki"

	if _, err := docker(ctx, "volume", "create", src); err != nil {
		t.Fatalf("creating the legacy volume: %v", err)
	}
	if out, err := docker(ctx, "run", "--rm", "--volume", src+":/d", "alpine:3.20",
		"sh", "-c", "echo the-ca-key > /d/mark"); err != nil {
		t.Fatalf("seeding the legacy volume: %v\n%s", err, out)
	}
	// The destination already exists and is empty: the state a refused
	// migration leaves behind.
	if _, err := docker(ctx, "volume", "create", dest); err != nil {
		t.Fatalf("creating the empty destination: %v", err)
	}
	t.Cleanup(func() {
		//nolint:usetesting // cleanup must outlive the test's cancelled context
		c := context.Background()
		for _, n := range []string{src, dest, prefix + "-ledger-data",
			prefix + "-identity-secret", prefix + "-rekor-key", prefix + "-trillian-db"} {
			discardError(docker(c, "volume", "rm", "--force", n))
		}
	})

	out, code := run(t, ensure, []string{
		"INNSEGL_TRUST_VOLUME_PREFIX=" + prefix,
		"INNSEGL_TRUST_LEGACY_PREFIX=" + legacy,
	}, "ensure")
	if code != 0 {
		t.Fatalf("ensure exited %d:\n%s", code, out)
	}
	if got := readMark(ctx, dest); got != "the-ca-key" {
		t.Errorf("the destination is still empty after ensure (mark %q). A volume "+
			"that exists and holds nothing is reported \"ok\" and the deployment "+
			"boots onto it with the real bytes in the volume beside it:\n%s", got, out)
	}
}

// ---------------------------------------------------------------------------
// OPS-034 — the pinned tree, reported.
// ---------------------------------------------------------------------------

func TestOPS034ReadinessNamesAnAbsentPinnedTree(t *testing.T) {
	root := repoRoot(t)
	health := filepath.Join(root, "scripts", "rekor-tlog-health.sh")

	const pinned = "2028999985815895099"

	// A Rekor serving the pinned tree, and a Rekor whose pinned tree is gone.
	// The second is the measured behaviour of 2026-09-16: Trillian's database
	// was recreated, the tree the pin named no longer existed, and every
	// request came back HTTP 500 with no explanation at all.
	present := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("treeID") != "" && r.URL.Query().Get("treeID") != pinned {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"treeID":%q,"treeSize":525}`, pinned)
	}))
	defer present.Close()

	absent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"code":500,"message":"unexpected server error"}`)
	}))
	defer absent.Close()

	pinFile := filepath.Join(t.TempDir(), "rekor-tlog-id")
	writeFile(t, pinFile, pinned+"\n")

	out, code := run(t, health, nil, "--url", present.URL, "--pin-file", pinFile)
	if code != 0 {
		t.Fatalf("a healthy pin reported exit %d:\n%s", code, out)
	}
	if !strings.Contains(out, pinned) || !strings.Contains(out, "525") {
		t.Errorf("a healthy report names neither the tree nor its size:\n%s", out)
	}

	out, code = run(t, health, nil, "--url", absent.URL, "--pin-file", pinFile)
	if code == 0 {
		t.Fatalf("a Rekor that 500s on every request reported healthy:\n%s", out)
	}
	if !strings.Contains(out, "the pinned tree is absent") {
		t.Errorf("the report does not say %q. An operator faced with HTTP 500 and "+
			"no explanation is where this started:\n%s", "the pinned tree is absent", out)
	}
	if !strings.Contains(out, pinned) {
		t.Errorf("the report never names the tree that is missing:\n%s", out)
	}

	// The readiness reporter must actually call it. A health check nothing
	// runs is the same shape as a gate nobody has watched fail.
	start := readFile(t, filepath.Join(root, "scripts", "innsegl-start.sh"))
	if !strings.Contains(start, "rekor-tlog-health.sh") {
		t.Errorf("scripts/innsegl-start.sh — the thing that reports readiness — " +
			"never calls scripts/rekor-tlog-health.sh")
	}
}

// OPS-036 — the other way the log answers
// wrongly after a teardown, and this one is worse than an outage.
//
// MEASURED while proving OPS-032. `down -v` removes sigstore-rekor-search, the
// Redis map from artifact digest to entry UUID. The entries themselves are
// untouched — same tree, same size — but Rekor indexes an entry when it is
// written and never afterwards, so the log can no longer FIND them. `innsegl
// verify` then reports, of a commit whose entry is sitting in the log:
//
//  2. Rekor inclusion proven — result: failed
//     the log answered, and it holds no entry whose artifact is sha256:d8b5…
//     Nothing ever logged a signature over this commit object.
//
// That is a FALSE ACCUSATION, not an unavailable verdict, and doc 06 P2's
// tri-state has no room for one. The index is derived and rebuildable — which
// is why it is not one of the irreplaceable four — but rebuildable is worth
// nothing if nothing rebuilds it. Running scripts/rekor-reindex.sh turned the
// same commit back to VERIFIED, 50 keys from 25 log entries.
func TestOPS036BringUpRebuildsTheSearchIndex(t *testing.T) {
	mk := readFile(t, filepath.Join(repoRoot(t), "Makefile"))
	if !strings.Contains(mk, "rekor-reindex.sh") {
		t.Errorf("no bring-up target rebuilds Rekor's search index. `down -v` " +
			"removes it, and a log that cannot find an entry it holds makes " +
			"`innsegl verify` accuse a commit that is perfectly good")
	}
}

// ---------------------------------------------------------------------------
// OPS-035 — the backup runs on a timer.
// ---------------------------------------------------------------------------

func TestOPS035TheLedgerBackupIsScheduled(t *testing.T) {
	root := repoRoot(t)
	sched := filepath.Join(root, "scripts", "backup-schedule.sh")

	dir := t.TempDir()
	mirror := filepath.Join(dir, "second-copy")
	env := []string{
		"INNSEGL_SCHEDULE_DIR=" + dir,
		"INNSEGL_BACKUP_DIR=" + mirror,
	}

	out, code := run(t, sched, env, "install", "--no-load")
	if code != 0 {
		t.Fatalf("install exited %d:\n%s", code, out)
	}

	out, code = run(t, sched, env, "status")
	if code != 0 {
		t.Fatalf("status exited %d after a successful install:\n%s", code, out)
	}
	if !strings.Contains(out, "backup-ledger.sh") {
		t.Errorf("the installed schedule does not name scripts/backup-ledger.sh. "+
			"The script is written, tested and self-tested; scheduling a second "+
			"implementation of it would be the one mistake worth avoiding:\n%s", out)
	}
	if !strings.Contains(out, mirror) {
		t.Errorf("the installed schedule does not write to the second directory "+
			"it was given (%s):\n%s", mirror, out)
	}
	if strings.Contains(out, filepath.Join(root, "backups")) {
		t.Errorf("the schedule writes into the checkout. doc 05 §2 wants the copy "+
			"off the box; a copy in the working tree shares its fate:\n%s", out)
	}

	if out, code := run(t, sched, env, "uninstall"); code != 0 {
		t.Fatalf("uninstall exited %d:\n%s", code, out)
	}
	if _, code := run(t, sched, env, "status"); code == 0 {
		t.Errorf("status still reports a schedule after uninstall")
	}
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

// composeVolume is the part of compose's resolved config this package reads.
type composeVolume struct {
	Name     string `json:"name"`
	External bool   `json:"external"`
}

// composeVolumes asks compose what a file's volumes RESOLVE to.
func composeVolumes(t *testing.T, root, rel string, env []string) map[string]composeVolume {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "docker", "compose",
		"-f", filepath.Join(root, rel), "config", "--format", "json")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), env...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker compose -f %s config: %v\n%s", rel, err, stderr.String())
	}
	var doc struct {
		Volumes map[string]composeVolume `json:"volumes"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("parsing compose config for %s: %v", rel, err)
	}
	return doc.Volumes
}

// run executes one of the shipped scripts and returns its combined output and
// exit status. The status is the contract these gates publish, so it is read
// rather than collapsed into an error.
func run(t *testing.T, script string, env []string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), script, args...)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("running %s %v: %v\n%s", script, args, err, out)
		}
		code = ee.ExitCode()
	}
	return string(out), code
}

func volumeExists(ctx context.Context, name string) bool {
	_, err := docker(ctx, "volume", "inspect", name)
	return err == nil
}

func volumeLabel(ctx context.Context, name, label string) string {
	out, err := docker(ctx, "volume", "inspect", name,
		"--format", "{{index .Labels \""+label+"\"}}")
	if err != nil {
		return ""
	}
	if out == "<no value>" {
		return ""
	}
	return out
}

// readMark reads /d/mark out of a volume with a throwaway container.
func readMark(ctx context.Context, volume string) string {
	out, err := docker(ctx, "run", "--rm", "--volume", volume+":/d",
		"alpine:3.20", "cat", "/d/mark")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// isTrustVolumeKey reports whether a compose volume key is part of the trust root.
func isTrustVolumeKey(key string) bool {
	for _, k := range trustVolumeKeys {
		if k == key {
			return true
		}
	}
	return false
}

// uniqueName keeps concurrent runs and leftovers from colliding.
func uniqueName(t *testing.T, prefix string) string {
	t.Helper()
	return fmt.Sprintf("%s-%d", prefix, os.Getpid())
}
