// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// The object store is ONE process (#451), and only its S3 port is reachable.
//
// It was three containers because object lock is enforced at one of the
// store's layers only, the S3 gateway, while the Filer's HTTP API, the master's
// and the volume server's reach the same bytes with no credential. In one
// process all of them used to share one bind address. The pinned release adds
// `-filer.disableHttp`, and `-ip.bind` / `-s3.ip.bind` let every listener but
// S3 sit on the container's loopback. Then the fence OPS-029 asserts holds in
// one container: from the network the sealer and the canary are on, nothing
// but S3 answers.
//
// These cases read the interpolated compose file and start nothing. OPS-029
// (filerisolation_test.go) is the one that starts the shipped command and
// probes every port from that network.
// ---------------------------------------------------------------------------

// objectStoreService is the one object-store service, by its compose name.
// The name is the gateway's old one: every client addresses innsegl-s3:8333.
const objectStoreService = "innsegl-s3"

// objectStoreAdvertisedName is the name the process advertises to itself. It
// is the old storage container's name, kept so that the master's saved state
// on an existing volume still names this node (see the compose file).
const objectStoreAdvertisedName = "innsegl-object-store"

// shippedObjectStorePin is the release that has `-filer.disableHttp`, pinned
// by its index digest.
const shippedObjectStorePin = "chrislusf/seaweedfs:4.48@sha256:4e61d15fd35994cb1e43e1e553dff106794841fd9a99ade2fc8c8bfce4d7872d"

// objectStoreConfig interpolates the shipped stack, or skips when compose is
// absent (#101: an absent tool is a skip, never a pass).
func objectStoreConfig(t *testing.T) composeConfig {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping: %v", err)
	}
	return interpolateCompose(ctx, t, "innsegl-segments", "deploy/compose/innsegl.yml")
}

func TestTheObjectStoreIsOneProcess(t *testing.T) {
	cfg := objectStoreConfig(t)

	for _, gone := range []string{"innsegl-object-store", "innsegl-object-filer"} {
		if _, ok := cfg.Services[gone]; ok {
			t.Errorf("deploy/compose/innsegl.yml still declares %s. The object store is one "+
				"process now; a second container on the same volume is two servers writing "+
				"one data directory.", gone)
		}
	}

	svc := cfg.service(t, objectStoreService)
	if len(svc.Command) == 0 || svc.Command[0] != "server" {
		t.Fatalf("%s runs %v; the one process is `weed server`", objectStoreService, svc.Command)
	}
	for _, flag := range []string{"-filer", "-s3"} {
		if !slices.Contains(svc.Command, flag) {
			t.Errorf("%s's command has no %s: the one process must run it, or nothing does",
				objectStoreService, flag)
		}
	}
}

func TestTheObjectStoreRunsTheReleaseThatClosesTheFiler(t *testing.T) {
	root := repoRoot(t)
	if got := shippedObjectStoreImage(t, root); got != shippedObjectStorePin {
		t.Errorf("deploy/compose/innsegl.yml pins the object store to\n  %s\nwant\n  %s\n\n"+
			"-filer.disableHttp first shipped in 4.48. An older release refuses the flag, and "+
			"a newer one has not been measured against OPS-029 and SEG-005.",
			got, shippedObjectStorePin)
	}
}

// TestOnlyS3ListensBeyondTheObjectStoresLoopback is the static half of
// OPS-029: the flags that put every unauthenticated API on loopback.
func TestOnlyS3ListensBeyondTheObjectStoresLoopback(t *testing.T) {
	svc := objectStoreConfig(t).service(t, objectStoreService)

	for _, want := range []struct{ flag, why string }{
		{"-ip.bind=127.0.0.1", "the master, volume server and Filer listen on this address, " +
			"HTTP and gRPC. Their HTTP APIs write and delete with no credential"},
		{"-s3.ip.bind=0.0.0.0", "S3 is the one listener other containers may reach"},
		{"-ip=" + objectStoreAdvertisedName, "the address the parts give each other; it must " +
			"resolve to loopback inside the container (extra_hosts), and it must be the name " +
			"the master's saved state carries"},
		{"-filer.disableHttp", "the second lock on the Filer's HTTP API: closed at the " +
			"process, not only fenced by the bind address"},
		{"-filer.disableDirListing", "belt and braces for the same surface"},
		{"-s3.iam=false", "an IAM API on the S3 port itself"},
		{"-s3.port.iceberg=0", "an Iceberg REST catalog"},
		{"-s3.port.lance=0", "a Lance namespace server"},
		{"-master.telemetry=false", "the master reports cluster statistics upstream by default"},
	} {
		if !slices.Contains(svc.Command, want.flag) {
			t.Errorf("%s's command lacks %s: %s", objectStoreService, want.flag, want.why)
		}
	}

	if !slices.Contains(svc.ExtraHosts, objectStoreAdvertisedName+"=127.0.0.1") {
		t.Errorf("%s maps no %s to 127.0.0.1 (extra_hosts %v). The parts dial each other by "+
			"that name and listen only on loopback; without the mapping they cannot connect.",
			objectStoreService, objectStoreAdvertisedName, svc.ExtraHosts)
	}

	// S3's gRPC port binds where S3 does, so it is reachable from
	// innsegl-objects. It requires a per-host key; objectkey_test.go pins how
	// the key is made and handed over.
}

// TestTheObjectStoreKeepsItsDataVolumes: production holds sealed segments in
// these two volumes, so the one process mounts the same ones, where its data
// already is.
func TestTheObjectStoreKeepsItsDataVolumes(t *testing.T) {
	svc := objectStoreConfig(t).service(t, objectStoreService)

	mounts := map[string]string{}
	for _, v := range svc.Volumes {
		mounts[v.Target] = v.Source
	}
	for target, source := range map[string]string{
		"/data":           "innsegl-object-data",
		"/data/filerldb2": "innsegl-object-filer-data",
	} {
		if got := mounts[target]; got != source {
			t.Errorf("%s mounts %q at %s; want %s. That volume holds the segment %s of "+
				"every existing deployment.", objectStoreService, got, target, source,
				map[string]string{"/data": "bytes", "/data/filerldb2": "metadata"}[target])
		}
	}

	// The old Filer kept its store at <volume>/filerldb2. The image's default
	// is /data/filerldb2, which is now the volume's root, so the store is
	// pointed one level down to where the existing files are.
	if dir, ok := svc.Environment["WEED_LEVELDB2_DIR"]; !ok || dir == nil || *dir != "/data/filerldb2/filerldb2" {
		t.Errorf("%s does not point the Filer's store at /data/filerldb2/filerldb2, where "+
			"innsegl-object-filer-data keeps it. The metadata would start empty and every "+
			"sealed segment would be bytes nothing can address.", objectStoreService)
	}
}

func TestOnlyTheObjectNetworkReachesTheObjectStore(t *testing.T) {
	cfg := objectStoreConfig(t)

	if got := cfg.service(t, objectStoreService).networkNames(); strings.Join(got, ",") != "innsegl-objects" {
		t.Errorf("%s is on %v; want only innsegl-objects", objectStoreService, got)
	}
	for name, svc := range cfg.Services {
		if slices.Contains(svc.networkNames(), "innsegl-object-backend") {
			t.Errorf("%s is on innsegl-object-backend; that network is gone with the "+
				"containers it isolated", name)
		}
	}
}
