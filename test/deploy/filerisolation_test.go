// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"innsegl.dev/innsegl/internal/segment"
)

// ---------------------------------------------------------------------------
// OPS-029 (PROPOSED for doc 07's TC-OPS) — the store's Filer is a second door
// to the same bytes, and nothing on the object network can reach it.
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
// Object lock is enforced at the S3 layer. The Filer is a different API to the
// same metadata, and it has no lock on it. The master's and the volume
// server's HTTP APIs write and delete raw needles with no credential either.
// So I4 — a sealed segment's bytes are never destroyed, by anyone — is worth
// exactly what the reachability of those doors is worth.
//
// THE STORE IS ONE PROCESS SINCE #451, AND TWO CONTROLS CLOSE THE DOORS:
//
//	1. every listener but S3 binds the container's loopback (-ip.bind), so
//	   from innsegl-objects only the S3 port accepts a connection,
//	2. the Filer's HTTP handlers are off (-filer.disableHttp), so even on
//	   loopback the destroying request finds nothing.
//
// S3's own gRPC port binds where S3 does, so it is reachable from
// innsegl-objects. It requires a per-host key. Phase B asserts an
// administrative call there is refused unsigned and refused when signed with
// the former public default, and accepted past authorisation only when signed
// with this host's key.
//
// WHY PHASE A EXISTS. "The delete was refused" is also true of a wrong path, a
// misspelled bucket, a server that is not running and an API that never
// existed. A refusal is evidence only when the same request, in the same
// shape, is shown WORKING somewhere — so phase A stands up the same process
// WITHOUT the controls (default bind address, Filer HTTP on, no key), writes a
// retained object through the gateway, watches the gateway refuse to delete it
// for the ROOT identity, and then destroys it with the unauthenticated
// request. It also shows the gRPC call accepted there. That is the
// anti-vacuity control appendonlyrole_test.go and SEG-005's canary are both
// built around, and it is why phase B's silence means something.
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
	shipped := cfg.service(t, objectStoreService)
	if got := shipped.networkNames(); strings.Join(got, ",") != "innsegl-objects" {
		t.Errorf("deploy/compose/innsegl.yml puts %s on %v; doc 05 §1 requires innsegl-objects "+
			"only. Phase B below measures the store on that network.", objectStoreService, got)
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
	aGRPC, portErr := freeHostPort(ctx)
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
		"--publish", "127.0.0.1:"+aGRPC+":18333",
		"--volume", root+"/deploy/compose/innsegl:/innsegl/init:ro",
		"--env", "INNSEGL_S3_IDENTITIES_FILE="+storeIdentitiesFile,
		"--env", "INNSEGL_OBJECT_STORE_ACCESS_KEY="+storeRootUser,
		"--env", "INNSEGL_OBJECT_STORE_SECRET_KEY="+storeRootPassword,
		"--env", "INNSEGL_OBJECT_STORE_BUCKET=innsegl-ops029",
		"--env", "INNSEGL_OBJECT_STORE_PREFIX="+storeSegmentPrefix,
		"--entrypoint", "sh", o.store, "-c",
		// `weed server -s3` — S3 AND the Filer in one process on one bind
		// address, with none of the shipped controls.
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

	// And S3's gRPC IAM cache, with no key: the call gets past authorisation
	// and stops only at the empty request. This is the control for phase B's
	// Unauthenticated.
	if c := s3AdminCall(ctx, "127.0.0.1:"+aGRPC, ""); c != codes.InvalidArgument {
		t.Fatalf("phase A's unauthenticated PutIdentity answered %v, want InvalidArgument (past "+
			"authorisation, refused only for the empty identity). Without this control phase "+
			"B's refusal says nothing.", c)
	}
	t.Log("OPS-029 phase A  unauthenticated PutIdentity on S3's gRPC port: accepted past authorisation")

	// -----------------------------------------------------------------------
	// PHASE B — the shipped process, and the same requests finding nothing.
	// -----------------------------------------------------------------------
	t.Log("OPS-029 phase B: the shipped one-process store")

	objects := o.tag + "-objects"
	if _, err := docker(ctx, "network", "create", objects); err != nil {
		t.Fatalf("creating %s: %v", objects, err)
	}
	o.networks = append(o.networks, objects)

	bPort, portErr := freeHostPort(ctx)
	if portErr != nil {
		t.Fatalf("reserving a host port: %v", portErr)
	}
	bGRPC, portErr := freeHostPort(ctx)
	if portErr != nil {
		t.Fatalf("reserving a host port: %v", portErr)
	}
	if len(shipped.Command) == 0 {
		t.Fatalf("deploy/compose/innsegl.yml gives %s no command; this case runs the "+
			"SHIPPED one rather than a copy of it", objectStoreService)
	}

	// THE SHIPPED IMAGE, COMMAND, ENVIRONMENT AND HOST MAP, read out of the
	// compose file rather than restated. The container name is per-run so a
	// live deployment is untouched; the network alias is the service name,
	// because that is what the sealer and the canary dial.
	//
	// THE WHOLE `command:` IS PASSED, not its tail. The image's entrypoint is
	// what supplies `weed`, so the compose file's first element is already the
	// subcommand — dropping it once left containers exiting on an unknown flag
	// (measured, the first time this was written).
	bName := o.tag + "-" + objectStoreService
	o.containers = append(o.containers, bName)
	discardError(docker(ctx, "rm", "--force", "--volumes", bName))
	args := []string{"run", "--detach", "--name", bName,
		"--network", objects, "--network-alias", objectStoreService,
		"--publish", "127.0.0.1:" + bPort + ":8333",
		"--publish", "127.0.0.1:" + bGRPC + ":18333",
		"--volume", root + "/deploy/compose/innsegl:/innsegl/init:ro",
		"--env", "INNSEGL_S3_IDENTITIES_FILE=" + storeIdentitiesFile,
		"--env", "INNSEGL_OBJECT_STORE_ACCESS_KEY=" + storeRootUser,
		"--env", "INNSEGL_OBJECT_STORE_SECRET_KEY=" + storeRootPassword,
		"--env", "INNSEGL_OBJECT_STORE_BUCKET=innsegl-ops029",
		"--env", "INNSEGL_OBJECT_STORE_PREFIX=" + storeSegmentPrefix,
	}
	args = append(args, shippedRunOptions(shipped)...)
	args = append(args, "--entrypoint", "sh", shipped.Image, "-c",
		"/innsegl/init/s3-identities.sh >/dev/null && exec sh /innsegl/init/object-store-start.sh "+
			strings.Join(shipped.Command, " "))
	if _, err := docker(ctx, args...); err != nil {
		t.Fatalf("starting %s from the shipped command %v: %v", objectStoreService, shipped.Command, err)
	}

	bStore := &objectStoreContainer{
		name: bName, endpoint: "127.0.0.1:" + bPort,
		bucket: "innsegl-ops029", client: o.client, root: root,
	}
	if err := waitForObjectStore(ctx, bStore); err != nil {
		logs, _ := docker(ctx, "logs", "--tail", "40", bName) //nolint:errcheck // a best-effort diagnostic on a path that is already failing
		t.Fatalf("the shipped one-process store never answered: %v\n%s", err, logs)
	}
	// The endpoint is the service name, not loopback: the client is on the
	// docker network the sealer is on, which is the arrangement under test.
	out, initErr = bStore.runObjectInitOn(ctx, objects,
		"--env", "INNSEGL_OBJECT_STORE_URL=http://"+objectStoreService+":8333")
	t.Logf("--- object-init.sh, phase B ---\n%s", out)
	if initErr != nil {
		t.Fatalf("object-init.sh failed against the shipped store: %v", initErr)
	}

	// A retained segment for the attempts to be aimed at. Without one the
	// requests below would be asking to destroy nothing, and "nothing was
	// destroyed" would be true however reachable the doors were.
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

	// ---- the control: the store IS reachable from innsegl-objects, on S3 ---
	//
	// Without this every refusal below would be indistinguishable from a
	// container that is not running or a name that does not resolve.
	if err := o.tcpProbe(ctx, objects, objectStoreService, "8333"); err != nil {
		t.Fatalf("S3 is not reachable from innsegl-objects: %v\n\nThen the refusals below say "+
			"nothing about the bind address; they say the store is not there.", err)
	}
	t.Logf("OPS-029 phase B  from innsegl-objects, %s:8333 (S3) accepts a connection", objectStoreService)

	// ---- every other listener, from the network the sealer is on ----------
	//
	// HTTP and gRPC of the master, the volume server and the Filer. Each
	// HTTP API among them writes or deletes with no credential.
	for _, p := range []struct{ port, what string }{
		{"9333", "master HTTP"}, {"19333", "master gRPC"},
		{"8080", "volume HTTP"}, {"18080", "volume gRPC"},
		{"8888", "Filer HTTP"}, {"18888", "Filer gRPC"},
	} {
		if err := o.tcpProbe(ctx, objects, objectStoreService, p.port); err == nil {
			t.Errorf("a container on innsegl-objects CONNECTED to %s:%s (%s). Only S3 may "+
				"listen beyond the container's loopback; -ip.bind=127.0.0.1 is the control.",
				objectStoreService, p.port, p.what)
		} else {
			t.Logf("OPS-029 phase B  from innsegl-objects, %-11s :%-5s refused", p.what, p.port)
		}
	}

	// ---- the attempt phase A destroyed with, from innsegl-objects ---------
	code, curlErr = o.curl(ctx, objects, "DELETE",
		filerDestroyURL(objectStoreService, bStore.bucket, key))
	switch {
	case curlErr == nil && isHTTPSuccess(code):
		t.Errorf("a container on innsegl-objects REACHED the Filer and its DELETE answered "+
			"HTTP %s.\n\nThat request destroys a COMPLIANCE-retained object with no "+
			"credential — phase A measured it.", code)
	case curlErr == nil:
		t.Errorf("a container on innsegl-objects REACHED the Filer; the request answered HTTP "+
			"%s rather than failing to connect. The handlers being off is the second "+
			"control, not the first: the port should not accept a connection from here.", code)
	default:
		t.Logf("OPS-029 phase B  from innsegl-objects, the Filer is not reachable: %v", curlErr)
	}

	// ---- the second lock: on the container's own loopback -----------------
	//
	// The same request from inside the container, where the listener is.
	// -filer.disableHttp leaves the port open and removes the handlers, so it
	// answers, and must not answer 2xx.
	inside, insideErr := docker(ctx, "exec", bName, "curl", "--silent", "--max-time", "10",
		"--output", "/dev/null", "--write-out", "%{http_code}", "-X", "DELETE",
		filerDestroyURL("127.0.0.1", bStore.bucket, key))
	switch {
	case insideErr != nil:
		t.Errorf("the Filer's HTTP port did not answer on the container's own loopback: %v. "+
			"Then the refusal above may be a Filer that is not running.", insideErr)
	case isHTTPSuccess(inside):
		t.Errorf("on the container's loopback the Filer's DELETE answered HTTP %s. "+
			"-filer.disableHttp is the control that closes the door itself rather than only "+
			"fencing it.", inside)
	default:
		t.Logf("OPS-029 phase B  on the container's loopback the Filer's DELETE answers HTTP %s "+
			"— the handlers are off on a listener that is up", inside)
	}

	// ---- S3's gRPC port requires this host's key --------------------------
	if c := s3AdminCall(ctx, "127.0.0.1:"+bGRPC, ""); c != codes.Unauthenticated {
		t.Errorf("an unsigned call on S3's gRPC port answered %v, want Unauthenticated. "+
			"Phase A showed the same call accepted without a key.", c)
	} else {
		t.Log("OPS-029 phase B  unsigned call on S3's gRPC port: Unauthenticated")
	}
	if c := s3AdminCall(ctx, "127.0.0.1:"+bGRPC, formerFilerKeyDefault); c != codes.Unauthenticated {
		t.Errorf("a call signed with the former public default key answered %v, want "+
			"Unauthenticated. The key must be this host's own.", c)
	} else {
		t.Log("OPS-029 phase B  call signed with the former public default: Unauthenticated")
	}
	// The control: signed with the key this host generated, the same call
	// gets past authorisation. Without it the two refusals above could be a
	// port that refuses everything.
	hostKey, keyErr := docker(ctx, "exec", bName, "cat", "/run/innsegl/s3/"+filerKeyFileName)
	if keyErr != nil {
		t.Fatalf("reading the generated key out of the store container: %v", keyErr)
	}
	if c := s3AdminCall(ctx, "127.0.0.1:"+bGRPC, hostKey); c != codes.InvalidArgument {
		t.Errorf("a call signed with this host's key answered %v, want InvalidArgument (past "+
			"authorisation). Then the refusals above say nothing about the key.", c)
	} else {
		t.Log("OPS-029 phase B  call signed with this host's key: past authorisation")
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

// shippedRunOptions turns the parts of a compose service that change how the
// process behaves — its environment and its host map — into `docker run`
// options, so a case can run the shipped command with everything it relies on.
func shippedRunOptions(svc interpolatedService) []string {
	var out []string
	for k, v := range svc.Environment {
		if v != nil {
			out = append(out, "--env", k+"="+*v)
		}
	}
	for _, h := range svc.ExtraHosts {
		out = append(out, "--add-host", strings.Replace(h, "=", ":", 1))
	}
	return out
}

// rawCodec sends and receives message bytes as they are. It lets a case call
// one gRPC method without the store's generated types: an empty request is a
// valid encoding of every proto message.
type rawCodec struct{}

func (rawCodec) Marshal(v any) ([]byte, error) {
	b, ok := v.(*[]byte)
	if !ok {
		return nil, fmt.Errorf("rawCodec marshals *[]byte, not %T", v)
	}
	return *b, nil
}

func (rawCodec) Unmarshal(data []byte, v any) error {
	b, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("rawCodec unmarshals into *[]byte, not %T", v)
	}
	*b = append([]byte(nil), data...)
	return nil
}

func (rawCodec) Name() string { return "proto" }

// s3AdminCall makes one PutIdentity call, with an empty identity, to an S3
// gateway's gRPC port and returns the status code. With a key it carries a
// Bearer token signed with that key, the way the store's own admin calls do;
// with "" it carries none.
//
// The empty identity is what makes the answer readable: authorisation runs
// first, so Unauthenticated means the call was refused for want of a key, and
// InvalidArgument means it got past authorisation and was stopped only for
// carrying no identity. Nothing is ever added.
func s3AdminCall(ctx context.Context, addr, key string) codes.Code {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return codes.Unknown
	}
	defer func() { _ = conn.Close() }()
	call, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if key != "" {
		call = metadata.AppendToOutgoingContext(call, "authorization", "Bearer "+adminToken(key))
	}
	req, resp := []byte{}, []byte{}
	err = conn.Invoke(call, "/messaging_pb.SeaweedS3IamCache/PutIdentity", &req, &resp,
		grpc.ForceCodec(rawCodec{}), grpc.WaitForReady(true))
	return status.Code(err)
}

// adminToken is an HS256 JWT with only an expiry, signed with key: the shape
// the store accepts as an admin token for its IAM gRPC services.
func adminToken(key string) string {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims := enc.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(time.Minute).Unix())))
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(header + "." + claims))
	return header + "." + claims + "." + enc.EncodeToString(mac.Sum(nil))
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
