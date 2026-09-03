// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// INIT-003 (proposed, doc 07 layer U): the gitsign download is pinned by
// version AND SHA-256, and the SHA is verified before the binary is ever
// used (#117 point 1). "reuse #64's release workflow shape rather than
// inventing a second way to pin a download" — release.yml pins cosign by
// $COSIGN_VERSION and a recorded per-asset SHA-256, checked with
// `sha256sum -c` before the binary runs; this is the same shape for gitsign.

const testGitsignBody = "this is a stand-in for a real gitsign binary\n"

func testGitsignSHA() string {
	sum := sha256.Sum256([]byte(testGitsignBody))
	return hex.EncodeToString(sum[:])
}

func newTestGitsignServer(t *testing.T, body string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if _, err := w.Write([]byte(body)); err != nil {
			t.Logf("test gitsign server: writing the response body: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testInstallOptions(t *testing.T, baseURL string, checksum string) gitsignInstallOptions {
	t.Helper()
	return gitsignInstallOptions{
		Version:    "0.17.1",
		Checksums:  map[string]string{"linux/amd64": checksum},
		InstallDir: t.TempDir(),
		BaseURL:    baseURL,
		HTTPClient: http.DefaultClient,
		GOOS:       "linux",
		GOARCH:     "amd64",
	}
}

func TestINIT003DownloadsVerifiesAndInstallsAPinnedGitsign(t *testing.T) {
	srv := newTestGitsignServer(t, testGitsignBody, http.StatusOK)
	opts := testInstallOptions(t, srv.URL, testGitsignSHA())

	path, err := locateOrInstallGitsign(context.Background(), opts)
	if err != nil {
		t.Fatalf("locateOrInstallGitsign: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading installed gitsign: %v", err)
	}
	if string(got) != testGitsignBody {
		t.Fatalf("installed binary content = %q, want %q", got, testGitsignBody)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("installed gitsign is not executable: mode %v", info.Mode())
	}
	if !strings.HasPrefix(path, opts.InstallDir) {
		t.Fatalf("installed gitsign at %q, want it under %q (repository-local, never global)",
			path, opts.InstallDir)
	}
}

// TestINIT003AMismatchedSHARefusesAndInstallsNothing is point 1's central
// claim, tested directly: "If the SHA does not match, refuse and say so."
func TestINIT003AMismatchedSHARefusesAndInstallsNothing(t *testing.T) {
	srv := newTestGitsignServer(t, testGitsignBody, http.StatusOK)
	wrongSHA := strings.Repeat("0", 64)
	opts := testInstallOptions(t, srv.URL, wrongSHA)

	_, err := locateOrInstallGitsign(context.Background(), opts)
	if err == nil {
		t.Fatal("locateOrInstallGitsign with a mismatched checksum: want an error, got nil")
	}
	if !strings.Contains(err.Error(), "checksum") && !strings.Contains(err.Error(), "SHA") {
		t.Errorf("error %q does not explain that the checksum mismatched", err)
	}

	walkErr := filepath.WalkDir(opts.InstallDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !strings.Contains(d.Name(), ".tmp") {
			t.Errorf("a mismatched download left a file in the install directory: %s", path)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
}

func TestINIT003RefusesAnUnpinnedPlatform(t *testing.T) {
	opts := testInstallOptions(t, "http://unused.invalid", testGitsignSHA())
	opts.GOOS, opts.GOARCH = "windows", "amd64"

	_, err := locateOrInstallGitsign(context.Background(), opts)
	if err == nil {
		t.Fatal("locateOrInstallGitsign on an unpinned platform: want an error, got nil")
	}
}

// TestINIT003ASecondRunReusesTheVerifiedInstallWithoutRedownloading is the
// "locates" half of point 1: an already-installed, still-matching gitsign is
// found and reused rather than fetched again.
func TestINIT003ASecondRunReusesTheVerifiedInstallWithoutRedownloading(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if _, err := w.Write([]byte(testGitsignBody)); err != nil {
			t.Logf("test gitsign server: writing the response body: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	opts := testInstallOptions(t, srv.URL, testGitsignSHA())

	first, err := locateOrInstallGitsign(context.Background(), opts)
	if err != nil {
		t.Fatalf("first install: %v", err)
	}
	if calls != 1 {
		t.Fatalf("first install made %d HTTP calls, want 1", calls)
	}

	second, err := locateOrInstallGitsign(context.Background(), opts)
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	if second != first {
		t.Fatalf("second call resolved a different path: %q vs %q", second, first)
	}
	if calls != 1 {
		t.Fatalf("second call made an HTTP request: %d calls total, want 1 (already verified and installed)", calls)
	}
}

// TestINIT003ATamperedExistingInstallIsRedownloaded is defense in depth: a
// binary that was written to the install path by something other than this
// verified flow (or corrupted since) is never trusted on its path alone.
func TestINIT003ATamperedExistingInstallIsRedownloaded(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if _, err := w.Write([]byte(testGitsignBody)); err != nil {
			t.Logf("test gitsign server: writing the response body: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	opts := testInstallOptions(t, srv.URL, testGitsignSHA())

	first, err := locateOrInstallGitsign(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if writeErr := os.WriteFile(first, []byte("tampered"), 0o755); writeErr != nil {
		t.Fatal(writeErr)
	}

	second, err := locateOrInstallGitsign(context.Background(), opts)
	if err != nil {
		t.Fatalf("re-install over a tampered binary: %v", err)
	}
	if second != first {
		t.Fatalf("path changed: %q vs %q", second, first)
	}
	if calls != 2 {
		t.Fatalf("tampered install made %d HTTP calls, want 2 (re-fetched rather than trusted)", calls)
	}
	got, readErr := os.ReadFile(second)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != testGitsignBody {
		t.Fatalf("installed content after re-fetch = %q, want the verified body", got)
	}
}

func TestINIT003GitsignAssetNameMatchesUpstreamsConvention(t *testing.T) {
	rel := gitsignReleaseAsset("0.17.1", "linux", "amd64")
	if rel != "gitsign_0.17.1_linux_amd64" {
		t.Fatalf("gitsignReleaseAsset = %q, want %q", rel, "gitsign_0.17.1_linux_amd64")
	}
}

func TestINIT003PinnedChecksumsCoverTheReleaseBuildMatrix(t *testing.T) {
	// release.yml's own build matrix (cmd/innsegl/../../.github/workflows/release.yml):
	// "linux/amd64 linux/arm64 darwin/amd64 darwin/arm64". gitsign's pin must
	// cover the same platforms this project ships and develops on.
	want := []string{"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64"}
	for _, plat := range want {
		if _, ok := defaultGitsignChecksums[plat]; !ok {
			t.Errorf("defaultGitsignChecksums has no entry for %q", plat)
		}
	}
	for plat, sum := range defaultGitsignChecksums {
		if len(sum) != 64 {
			t.Errorf("defaultGitsignChecksums[%q] = %q, not a 64-character hex SHA-256", plat, sum)
		}
	}
}

func TestINIT003InstallDirDefaultsUnderGitDir(t *testing.T) {
	repo := initTestRepo(t)
	dir := gitsignInstallDir(repo)
	if !strings.HasPrefix(dir, filepath.Join(repo, ".git")) {
		t.Fatalf("gitsignInstallDir(%q) = %q, want it under %s", repo, dir, filepath.Join(repo, ".git"))
	}
}
