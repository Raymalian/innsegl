// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"

	"innsegl.dev/innsegl/internal/segment"
)

// ---------------------------------------------------------------------------
// OPS-029 (PROPOSED for doc 07's TC-OPS) — the store's Filer is a second door
// to the same bytes, and nothing but the gateway can reach it.
//
// THE FINDING THIS CASE EXISTS FOR, measured on the pinned image before any of
// it was written:
//
//	an object under COMPLIANCE retention, which the S3 gateway refuses to
//	delete for EVERY identity including the store's own root account, is
//	destroyed by
//
//	    curl -X DELETE http://<filer>:8888/buckets/<bucket>/<key>
//
//	No credential. No signature. One request, 204, and the S3 layer then
//	reports NoSuchKey.
//
// Object lock is enforced at the S3 layer. The Filer is a different process
// speaking a different protocol to the same metadata, and it has no lock on
// it. So I4 — a sealed segment's bytes are never destroyed, by anyone — is
// worth exactly what the reachability of that door is worth, and reachability
// is the only thing there is to control.
//
// TWO CONTROLS CLOSE IT IN THE REFERENCE STACK AND THIS CASE MEASURES BOTH:
//
//	1. the Filer's HTTP API is switched off at the process (-disableHttp),
//	2. the Filer is on a network whose only other member is the gateway.
//
// WHY PHASE A EXISTS. "The delete was refused" is also true of a wrong path, a
// misspelled bucket, a server that is not running and an API that never
// existed. A refusal is evidence only when the same request, in the same
// shape, is shown WORKING somewhere — so phase A stands up the arrangement the
// reference stack deliberately avoids (one process serving S3 and the Filer on
// one bind address, which is what `weed server -s3` is), writes a retained
// object through the gateway, watches the gateway refuse to delete it for the
// ROOT identity, and then destroys it with the unauthenticated request. That
// is the anti-vacuity control appendonlyrole_test.go and SEG-005's canary are
// both built around, and it is why phase B's silence means something.
//
// It also performs a destruction in order to report one, which every other
// case in this package refuses to do. The difference is what is destroyed: an
// object in a throwaway bucket in a container this test created and removes,
// whose body says what it is. Nothing in this repository or in any deployment
// is touched.
// ---------------------------------------------------------------------------

// ops029 is one test run's naming, so a killed run leaves names a later one
// removes rather than collides with.
type ops029 struct {
	tag        string
	containers []string
	networks   []string
	client     string // the reference S3 client image
	store      string // the object store image
}

func (o *ops029) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	for _, name := range o.containers {
		discardError(docker(ctx, "rm", "--force", "--volumes", name))
	}
	for _, name := range o.networks {
		discardError(docker(ctx, "network", "rm", name))
	}
}

func TestOPS029TheFilerIsReachableOnlyFromTheGateway(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping OPS-029: %v", err)
	}
	if err := dockerUsable(ctx); err != nil {
		t.Skipf("skipping OPS-029: %v. The Filer's reachability is measured against real "+
			"containers on real networks — a mocked refusal proves only that the mock was "+
			"written to refuse. Start Docker and re-run.", err)
	}

	root := repoRoot(t)
	o := &ops029{
		tag:    fmt.Sprintf("innsegl-ops029-%d", os.Getpid()),
		client: shippedS3ClientImage(t, root),
		store:  shippedObjectStoreImage(t, root),
	}
	t.Cleanup(o.cleanup)

	cfg := interpolateCompose(ctx, t, "innsegl-segments", "deploy/compose/innsegl.yml")

	// -----------------------------------------------------------------------
	// The membership the shipped file declares. Read before anything is
	// started, because if this has drifted the containers below would be
	// measuring an arrangement the deployment does not have.
	// -----------------------------------------------------------------------
	filer := cfg.service(t, "innsegl-object-filer")
	gateway := cfg.service(t, "innsegl-s3")
	store := cfg.service(t, "innsegl-object-store")

	for _, member := range []struct {
		service string
		want    []string
	}{
		{"innsegl-object-filer", []string{"innsegl-object-backend"}},
		{"innsegl-object-store", []string{"innsegl-object-backend"}},
		{"innsegl-s3", []string{"innsegl-object-backend", "innsegl-objects"}},
	} {
		got := cfg.service(t, member.service).networkNames()
		if strings.Join(got, ",") != strings.Join(member.want, ",") {
			t.Errorf("deploy/compose/innsegl.yml puts %s on %v; doc 05 §1 requires %v.\n\n"+
				"The gateway is the only service that may be on both. A Filer that joins "+
				"innsegl-objects is reachable by the sealer, the canary and the one-time "+
				"init, and its API destroys a retained object with no credential.",
				member.service, got, member.want)
		}
	}
	for _, service := range []string{"innsegl-sealer", "innsegl-canary", "innsegl-object-init"} {
		for _, network := range cfg.service(t, service).networkNames() {
			if network == "innsegl-object-backend" {
				t.Errorf("deploy/compose/innsegl.yml puts %s on innsegl-object-backend. "+
					"That network exists so that the Filer and the volume server have "+
					"exactly one route in, and it is the gateway.", service)
			}
		}
	}

	// -----------------------------------------------------------------------
	// PHASE A — the door is real, and it destroys what the gateway protects.
	// -----------------------------------------------------------------------
	t.Log("OPS-029 phase A: the arrangement the reference stack avoids — S3 and the Filer in one process")

	aNet := o.tag + "-oneprocess"
	if _, err := docker(ctx, "network", "create", aNet); err != nil {
		t.Fatalf("creating the phase A network: %v", err)
	}
	o.networks = append(o.networks, aNet)

	aPort, portErr := freeHostPort(ctx)
	if portErr != nil {
		t.Fatalf("reserving a host port: %v", portErr)
	}
	aName := o.tag + "-oneprocess-store"
	o.containers = append(o.containers, aName)
	discardError(docker(ctx, "rm", "--force", "--volumes", aName))
	if _, err := docker(ctx, "run", "--detach",
		"--name", aName,
		"--network", aNet,
		"--network-alias", "oneprocess",
		"--publish", "127.0.0.1:"+aPort+":8333",
		"--volume", root+"/deploy/compose/innsegl:/innsegl/init:ro",
		"--env", "INNSEGL_S3_IDENTITIES_FILE="+storeIdentitiesFile,
		"--env", "INNSEGL_OBJECT_STORE_ACCESS_KEY="+storeRootUser,
		"--env", "INNSEGL_OBJECT_STORE_SECRET_KEY="+storeRootPassword,
		"--env", "INNSEGL_OBJECT_STORE_BUCKET=innsegl-ops029",
		"--env", "INNSEGL_OBJECT_STORE_PREFIX="+storeSegmentPrefix,
		"--entrypoint", "sh", o.store, "-c",
		// `weed server -s3` — S3 AND the Filer in one process on one bind
		// address. This is the thing deploy/compose/innsegl.yml splits.
		"/innsegl/init/s3-identities.sh && exec weed server -dir=/data -volume.max=100 -s3 -filer "+
			"-s3.config="+storeIdentitiesFile+" -s3.port=8333 -s3.iam=false "+
			"-s3.port.iceberg=0 -s3.port.lance=0",
	); err != nil {
		t.Fatalf("starting the one-process store: %v", err)
	}

	aStore := &objectStoreContainer{
		name: aName, endpoint: "127.0.0.1:" + aPort, bucket: "innsegl-ops029",
		client: o.client, root: root,
	}
	if err := waitForObjectStore(ctx, aStore); err != nil {
		logs, _ := docker(ctx, "logs", "--tail", "40", aName) //nolint:errcheck // a best-effort diagnostic on a path that is already failing
		t.Fatalf("the one-process store never answered: %v\n%s", err, logs)
	}
	out, initErr := aStore.runObjectInit(ctx)
	t.Logf("--- object-init.sh, phase A ---\n%s", out)
	if initErr != nil {
		t.Fatalf("object-init.sh failed against the one-process store: %v", initErr)
	}

	// A retained object, written the way the sealer writes one.
	worm, wormErr := segment.NewWORM(ctx, segment.WORMConfig{
		Endpoint:  aStore.endpoint,
		AccessKey: storeRootUser,
		SecretKey: storeRootPassword,
		UseTLS:    false,
		Bucket:    aStore.bucket,
		Prefix:    storeSegmentPrefix,
		Mode:      segment.RetentionCompliance,
		OpTimeout: 30 * time.Second,
	})
	if wormErr != nil {
		t.Fatalf("opening the phase A bucket: %v", wormErr)
	}
	const name = "sha256:0000000000000000000000000000000000000000000000000000000000000029"
	body := []byte(`{"ops":"029","this":"a throwaway object in a throwaway container, destroyed on purpose"}`)
	if putErr := worm.Put(name, body); putErr != nil {
		t.Fatalf("writing the phase A object: %v", putErr)
	}
	key := storeSegmentPrefix + name

	cl, clErr := aStore.clientAs(storeRootUser, storeRootPassword)
	if clErr != nil {
		t.Fatalf("building a client: %v", clErr)
	}
	info, statOK := cl.StatObject(ctx, aStore.bucket, key, minio.StatObjectOptions{})
	if statOK != nil {
		t.Fatalf("reading back the phase A object: %v", statOK)
	}

	// The gateway refuses to destroy it for the ROOT identity. This is the
	// protection the Filer then goes around.
	rmErr := cl.RemoveObject(ctx, aStore.bucket, key,
		minio.RemoveObjectOptions{VersionID: info.VersionID, GovernanceBypass: true})
	if rmErr == nil {
		t.Fatalf("the S3 gateway DESTROYED a COMPLIANCE-retained version for the store's root "+
			"identity. SEG-005 does not hold on this store at all and nothing below this line "+
			"is the finding it looks like.\n  bucket %s key %s", aStore.bucket, key)
	}
	t.Logf("OPS-029 phase A  S3 delete of the retained version, as %s: refused %s",
		storeRootUser, minio.ToErrorResponse(rmErr).Code)

	// And now the Filer, with no credential at all.
	//
	// THE PATH CARRIES `.versions` AND THAT IS NOT A DETAIL. A versioned S3
	// object is a DIRECTORY in the Filer's namespace — `<key>.versions` — with
	// one entry per version, and the retention lives on the entries. Deleting
	// the plain `<key>` path answers 204 and removes nothing, because nothing
	// is there; measured, and it is how this case first passed for the wrong
	// reason. The request below removes the directory and every version in it.
	code, curlErr := o.curl(ctx, aNet, "DELETE", filerDestroyURL("oneprocess", aStore.bucket, key))
	if curlErr != nil {
		t.Fatalf("the unauthenticated Filer request could not be made at all: %v\n\n"+
			"Phase A is the control: without it, phase B's refusals are indistinguishable "+
			"from an API that never existed.", curlErr)
	}
	t.Logf("OPS-029 phase A  unauthenticated DELETE through the Filer: HTTP %s", code)

	_, statErr := cl.StatObject(ctx, aStore.bucket, key, minio.StatObjectOptions{VersionID: info.VersionID})
	switch { //nolint:staticcheck // two outcomes with different messages, not a value switch
	case statErr == nil:
		t.Fatalf("the Filer's unauthenticated DELETE answered HTTP %s and the retained object "+
			"is still there. This case cannot tell whether phase B's silence is isolation or "+
			"an API this store no longer has; it must be rewritten against whatever the door "+
			"is now, not relaxed.", code)
	default:
		t.Logf("OPS-029 phase A  the retained object is GONE: %s. "+
			"This is why the Filer gets its own network and no HTTP listener.",
			minio.ToErrorResponse(statErr).Code)
	}

	// -----------------------------------------------------------------------
	// PHASE B — the shipped arrangement, and the same request finding nothing.
	// -----------------------------------------------------------------------
	t.Log("OPS-029 phase B: the shipped three-container arrangement")

	backend := o.tag + "-backend"
	objects := o.tag + "-objects"
	for _, n := range []string{backend, objects} {
		if _, err := docker(ctx, "network", "create", n); err != nil {
			t.Fatalf("creating %s: %v", n, err)
		}
		o.networks = append(o.networks, n)
	}

	// Every container below runs THE SHIPPED IMAGE WITH THE SHIPPED COMMAND,
	// read out of the compose file rather than restated. The container names
	// are per-run so a live deployment is untouched; the network ALIASES are
	// the compose service names, because the shipped commands address each
	// other by those.
	starts := []struct {
		alias   string
		service interpolatedService
		nets    []string
		publish string
	}{
		{"innsegl-object-store", store, []string{backend}, ""},
		{"innsegl-object-filer", filer, []string{backend}, ""},
		{"innsegl-s3", gateway, []string{backend, objects}, "8333"},
	}
	bPort, portErr := freeHostPort(ctx)
	if portErr != nil {
		t.Fatalf("reserving a host port: %v", portErr)
	}
	for _, st := range starts {
		cname := o.tag + "-" + st.alias
		o.containers = append(o.containers, cname)
		discardError(docker(ctx, "rm", "--force", "--volumes", cname))

		args := []string{"run", "--detach", "--name", cname,
			"--network", st.nets[0], "--network-alias", st.alias,
			"--volume", root + "/deploy/compose/innsegl:/innsegl/init:ro",
			"--env", "INNSEGL_S3_IDENTITIES_FILE=" + storeIdentitiesFile,
			"--env", "INNSEGL_OBJECT_STORE_ACCESS_KEY=" + storeRootUser,
			"--env", "INNSEGL_OBJECT_STORE_SECRET_KEY=" + storeRootPassword,
			"--env", "INNSEGL_OBJECT_STORE_BUCKET=innsegl-ops029",
			"--env", "INNSEGL_OBJECT_STORE_PREFIX=" + storeSegmentPrefix,
		}
		if st.publish != "" {
			args = append(args, "--publish", "127.0.0.1:"+bPort+":"+st.publish)
		}
		args = append(args, "--entrypoint", "sh", st.service.Image, "-c",
			// The gateway needs the identity file the compose stack's own
			// one-shot writes; the other two need nothing. Running it
			// unconditionally keeps one command for all three.
			//
			// THE WHOLE `command:` IS PASSED, not its tail. The image's
			// entrypoint is what supplies `weed`, so the compose file's first
			// element is already the subcommand — dropping it once left three
			// containers exiting on an unknown flag and a phase that could not
			// start (measured, the first time this was written).
			"/innsegl/init/s3-identities.sh >/dev/null && exec weed "+
				strings.Join(st.service.Command, " "))
		if len(st.service.Command) == 0 {
			t.Fatalf("deploy/compose/innsegl.yml gives %s no command; this case runs the "+
				"SHIPPED one rather than a copy of it", st.alias)
		}
		if _, err := docker(ctx, args...); err != nil {
			t.Fatalf("starting %s from the shipped command %v: %v", st.alias, st.service.Command, err)
		}
		if len(st.nets) > 1 {
			for _, extra := range st.nets[1:] {
				if _, err := docker(ctx, "network", "connect", "--alias", st.alias, extra, cname); err != nil {
					t.Fatalf("joining %s to %s: %v", cname, extra, err)
				}
			}
		}
	}

	bStore := &objectStoreContainer{
		name: o.tag + "-innsegl-s3", endpoint: "127.0.0.1:" + bPort,
		bucket: "innsegl-ops029", client: o.client, root: root,
	}
	if err := waitForObjectStore(ctx, bStore); err != nil {
		for _, st := range starts {
			logs, _ := docker(ctx, "logs", "--tail", "30", o.tag+"-"+st.alias) //nolint:errcheck // a best-effort diagnostic on a path that is already failing
			t.Logf("--- %s ---\n%s", st.alias, logs)
		}
		t.Fatalf("the shipped three-container arrangement never answered: %v", err)
	}
	// The endpoint is the gateway's SERVICE NAME here, not loopback: the
	// client is on a docker network in this phase rather than in the store
	// container's own namespace, which is the arrangement the compose stack
	// has and the whole reason this phase exists.
	out, initErr = bStore.runObjectInitOn(ctx, objects,
		"--env", "INNSEGL_OBJECT_STORE_URL=http://innsegl-s3:8333")
	t.Logf("--- object-init.sh, phase B ---\n%s", out)
	if initErr != nil {
		t.Fatalf("object-init.sh failed against the shipped arrangement: %v", initErr)
	}

	// A retained segment for the attempt to be aimed at. Without one the
	// request below would be asking the Filer to destroy nothing, and "nothing
	// was destroyed" would be true however reachable the Filer was.
	bWorm, bWormErr := segment.NewWORM(ctx, segment.WORMConfig{
		Endpoint:  bStore.endpoint,
		AccessKey: storeRootUser,
		SecretKey: storeRootPassword,
		UseTLS:    false,
		Bucket:    bStore.bucket,
		Prefix:    storeSegmentPrefix,
		Mode:      segment.RetentionCompliance,
		OpTimeout: 30 * time.Second,
	})
	if bWormErr != nil {
		t.Fatalf("opening the phase B bucket: %v", bWormErr)
	}
	if putErr := bWorm.Put(name, body); putErr != nil {
		t.Fatalf("writing the phase B object: %v", putErr)
	}

	// ---- the attempt, from the network the sealer and the canary are on ----
	//
	// The same request phase A destroyed a retained object with, made from the
	// one place a compromised sealer, canary or init would make it from.
	code, curlErr = o.curl(ctx, objects, "DELETE",
		filerDestroyURL("innsegl-object-filer", bStore.bucket, key))
	switch {
	case curlErr == nil && isHTTPSuccess(code):
		t.Errorf("a container on innsegl-objects REACHED the Filer and its DELETE answered "+
			"HTTP %s.\n\nThat request destroys a COMPLIANCE-retained object with no "+
			"credential — phase A measured it. doc 05 §1 requires the Filer to have exactly "+
			"one route in, and it is the gateway.", code)
	case curlErr == nil:
		t.Errorf("a container on innsegl-objects RESOLVED and REACHED the Filer; the request "+
			"answered HTTP %s rather than failing to connect.\n\nThe HTTP listener being off "+
			"is the second control, not the first: the first is that this name should not "+
			"resolve from here at all.", code)
	default:
		t.Logf("OPS-029 phase B  from innsegl-objects, the Filer is not reachable: %v", curlErr)
	}

	// ---- and the control: it IS reachable from the gateway's own network ---
	//
	// Without this the refusal above would be indistinguishable from a Filer
	// that is not running, a wrong name, or a store that has no Filer at all.
	// The gRPC port is what the gateway itself uses and what -disableHttp
	// leaves alone, so a connection to it proves the process is up and
	// routable from here while the HTTP door on 8888 answers nothing.
	if err := o.tcpProbe(ctx, backend, "innsegl-object-filer", "18888"); err != nil {
		t.Errorf("the Filer is not reachable from innsegl-object-backend either: %v\n\n"+
			"Then the refusal above says nothing about the isolation — it says the Filer "+
			"is not running, and the gateway could not be serving this bucket.", err)
	} else {
		t.Logf("OPS-029 phase B  from innsegl-object-backend, the Filer's gRPC port accepts a " +
			"connection, so the container is up and routable from there")
	}

	code, curlErr = o.curl(ctx, backend, "DELETE",
		filerDestroyURL("innsegl-object-filer", bStore.bucket, key))
	switch {
	case curlErr == nil && isHTTPSuccess(code):
		t.Errorf("the Filer's HTTP API answered HTTP %s from innsegl-object-backend. "+
			"-disableHttp is the control that closes the door itself rather than only "+
			"fencing it; without it the network is the only thing between a segment and "+
			"one unauthenticated request.", code)
	case curlErr == nil:
		t.Logf("OPS-029 phase B  from innsegl-object-backend, the Filer's HTTP DELETE answers "+
			"HTTP %s — the listener is gone, on a process that is up and routable", code)
	default:
		t.Logf("OPS-029 phase B  the Filer's HTTP API refused the connection outright: %v", curlErr)
	}

	// ---- THE FINDING: the segment is still there, byte for byte ------------
	//
	// Every refusal above is about a request. This is about the bytes, which is
	// what I4 is actually a claim over.
	got, getErr := bWorm.Get(name)
	if getErr != nil {
		t.Fatalf("the retained segment is GONE after the attempts above: %v\n\n"+
			"Phase A measured what destroys it. Something in the shipped arrangement "+
			"leaves that door open.", getErr)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("the retained segment read back as %d bytes that are not what was written", len(got))
	}
	t.Logf("OPS-029 phase B  the retained segment is intact: %d bytes, unchanged", len(got))

	// ---- and the bucket is still a working, locked bucket afterwards -------
	bcl, bclErr := bStore.clientAs(storeRootUser, storeRootPassword)
	if bclErr != nil {
		t.Fatalf("building a client for the shipped arrangement: %v", bclErr)
	}
	enabled, mode, _, _, lockErr := bcl.GetObjectLockConfig(ctx, bStore.bucket)
	if lockErr != nil {
		t.Fatalf("the shipped arrangement's bucket reports no object-lock configuration: %v", lockErr)
	}
	t.Logf("OPS-029 phase B  the bucket still reports object lock %q, default %v", enabled, deref(mode))
}

// filerDestroyURL is the one request that destroys a retained object through
// the Filer, written once so phase A and phase B cannot make different ones.
//
// A versioned S3 object is a DIRECTORY in the Filer's namespace — `<key>.versions`
// — holding one entry per version, and the retention lives on the entries.
// `recursive=true` is what removes them; `ignoreRecursiveError=true` is what
// keeps a partial failure from stopping halfway, which is what an attacker
// would pass and therefore what this has to attempt.
func filerDestroyURL(host, bucket, key string) string {
	return fmt.Sprintf("http://%s:8888/buckets/%s/%s.versions?recursive=true&ignoreRecursiveError=true",
		host, bucket, key)
}

// curl makes one unauthenticated request from a throwaway container on one
// network and returns the HTTP status it got, or an error if it could not
// connect at all.
//
// The two outcomes are kept apart deliberately: "did not resolve" and "answered
// 404" are different controls, and a helper that folded them into one boolean
// would let the weaker one pass for the stronger.
func (o *ops029) curl(ctx context.Context, network, method, url string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm",
		"--network", network, "--entrypoint", "sh", o.client, "-c",
		fmt.Sprintf("curl --silent --show-error --max-time 10 --output /dev/null "+
			"--write-out '%%{http_code}' -X %s %q", method, url))
	var out bytes.Buffer
	cmd.Stdout = &out
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(errOut.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// tcpProbe opens a TCP connection from a throwaway container on one network.
// It is the control for a refusal that would otherwise be a dead container.
func (o *ops029) tcpProbe(ctx context.Context, network, host, port string) error {
	script := fmt.Sprintf(
		"import socket,sys\ns=socket.create_connection((%q,%s),5)\ns.close()\n", host, port)
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm",
		"--network", network, "--entrypoint", "python3", o.client, "-c", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// isHTTPSuccess is true for a 2xx, which is the only outcome that means the
// request was carried out.
func isHTTPSuccess(code string) bool {
	return len(code) == 3 && code[0] == '2'
}

// waitForObjectStore blocks until a store answers an authenticated request.
func waitForObjectStore(ctx context.Context, c *objectStoreContainer) error {
	deadline := time.Now().Add(2 * time.Minute)
	var last error
	for time.Now().Before(deadline) {
		cl, err := c.clientAs(storeRootUser, storeRootPassword)
		if err == nil {
			attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
			_, err = cl.ListBuckets(attempt)
			cancel()
		}
		if err == nil {
			return nil
		}
		last = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return last
}
