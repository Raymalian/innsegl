// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Locating or installing gitsign, pinned by version AND SHA-256 (#117
// point 1).
//
// "A setup command that downloads something unpinned is the supply-chain
// attack this project exists to prevent, performed by us." — so this file
// copies the SHAPE of .github/workflows/release.yml's cosign pin exactly,
// rather than inventing a second way to pin a download (#64, cited in the
// issue): a fixed VERSION, a per-platform SHA-256 recorded ahead of time, the
// download checked against it BEFORE the binary is trusted, and a refusal —
// not a warning — on any mismatch.
//
// # What the pin buys, stated as honestly as release.yml states it for cosign
//
// The checksum is fetched over the same channel the binary is fetched over,
// so it is not independent evidence about what sigstore/gitsign actually
// published. What it buys is IMMUTABILITY: a GitHub release asset can be
// replaced in place by whoever owns the repository, and a recorded hash turns
// that swap into a hard failure here instead of a silent substitution highly
// unlikely to be otherwise noticed on a laptop running `innsegl init` once.
//
// # Where the numbers below came from
//
// MEASURED 2026-09-03: downloaded
// https://github.com/sigstore/gitsign/releases/download/v0.17.1/checksums.txt
// (the release's own manifest) and cross-checked one entry —
// gitsign_0.17.1_darwin_arm64 — against `shasum -a 256` of the actual asset
// downloaded from the release page. They agreed. The other three platform
// entries below are read from the same checksums.txt.
//
// v0.17.1 is not a new choice: it is the version internal/signing's own test
// harness already pins (harnessGitsignVersion, sigstoreharness_test.go) and
// the version ADR-0031's Consequences names as the runtime dependency this
// project currently ships against. Two constants naming two different
// versions of the same released binary would be a version bump nobody could
// see landed only halfway.
const defaultGitsignVersion = "0.17.1"

// defaultGitsignChecksums is the pin. GOOS/GOARCH -> sha256 of the exact
// release asset (gitsign_<version>_<os>_<arch>, no extension: these are the
// four platforms release.yml's own build matrix ships, and the four this
// project develops and tests on.
var defaultGitsignChecksums = map[string]string{
	"darwin/amd64": "32c469eee2859694a67df0efee1a17f2574600ad73769a81315f360ee75f89e7",
	"darwin/arm64": "4994e9629aae6a3fea9c0f770f279b273bad3e86ac8ebd3e9dc90f317428589d",
	"linux/amd64":  "69213a8a0813a151e5a47d0060862952ff833a845d57309dff76f7ba6600abae",
	"linux/arm64":  "477018736a80b36e703dd58db8d6e158a2c1b8b727af0ab8ffdcce9fdf610ada",
}

const defaultGitsignBaseURL = "https://github.com/sigstore/gitsign/releases/download"

// gitsignDownloadTimeout bounds one release-asset fetch. IP §6.3 forbids
// indefinite hangs everywhere else in this codebase; a setup command talking
// to GitHub over an operator's network is no exception.
const gitsignDownloadTimeout = 90 * time.Second

// gitsignInstallOptions is what locateOrInstallGitsign needs. Production
// wiring is defaultGitsignInstallOptions; tests substitute BaseURL,
// Checksums, GOOS and GOARCH so the download is a loopback httptest.Server
// and the case is deterministic on every machine that runs the suite.
type gitsignInstallOptions struct {
	Version    string
	Checksums  map[string]string
	InstallDir string
	BaseURL    string
	HTTPClient *http.Client
	GOOS       string
	GOARCH     string
}

// gitsignInstallDir is where a downloaded gitsign lives: inside .git, which
// is inside the repository (#117 acceptance bullet four, "nothing is written
// outside the repository") and which is already the one place this project's
// own tooling treats as repository-local, ephemeral, machine-specific state —
// nobody expects `.git/` to be portable or committed.
func gitsignInstallDir(repo string) string {
	return filepath.Join(repo, ".git", "innsegl", "bin")
}

func defaultGitsignInstallOptions(repo string) gitsignInstallOptions {
	return gitsignInstallOptions{
		Version:    defaultGitsignVersion,
		Checksums:  defaultGitsignChecksums,
		InstallDir: gitsignInstallDir(repo),
		BaseURL:    defaultGitsignBaseURL,
		HTTPClient: &http.Client{Timeout: gitsignDownloadTimeout},
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
	}
}

// gitsignReleaseAsset names the release asset gitsign publishes for one
// platform, matching upstream's own convention exactly (no leading "v" on
// the version, no extension on darwin/linux).
func gitsignReleaseAsset(version, goos, goarch string) string {
	return fmt.Sprintf("gitsign_%s_%s_%s", version, goos, goarch)
}

// locateOrInstallGitsign resolves a pinned, SHA-256-verified gitsign binary,
// downloading it only when the repository-local install is absent or no
// longer matches the pin.
//
// "Locates" and "installs" are the same check run twice: an existing file at
// the install path is trusted ONLY after its own bytes re-hash to the pinned
// checksum, never on the strength of its path or its permission bits. A
// binary at that path that fails the re-check — corrupted, or replaced by
// something else — is treated exactly like a first run: fetched fresh,
// verified, and only then put in its place.
func locateOrInstallGitsign(ctx context.Context, opts gitsignInstallOptions) (string, error) {
	goos, goarch := opts.GOOS, opts.GOARCH
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	platform := goos + "/" + goarch
	want, ok := opts.Checksums[platform]
	if !ok {
		return "", fmt.Errorf("%w: %s; supported platforms are %s",
			errGitsignUnsupportedPlatform, platform, sortedPlatforms(opts.Checksums))
	}
	if len(want) != sha256.Size*2 {
		return "", fmt.Errorf("innsegl init: the pinned checksum for %s is %d characters, "+
			"not a 64-character SHA-256 hex digest — refusing to trust a malformed pin",
			platform, len(want))
	}

	asset := gitsignReleaseAsset(opts.Version, goos, goarch)
	target := filepath.Join(opts.InstallDir, opts.Version, asset)

	if verifyFileSHA256(target, want) == nil {
		return target, nil
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: gitsignDownloadTimeout}
	}
	url := opts.BaseURL + "/v" + opts.Version + "/" + asset

	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return "", fmt.Errorf("innsegl init: preparing the gitsign install directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), asset+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("innsegl init: preparing to download gitsign: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below has succeeded

	sum, err := downloadTo(ctx, client, url, tmp)
	closeErr := tmp.Close()
	if err != nil {
		return "", fmt.Errorf("innsegl init: downloading gitsign %s from %s: %w", opts.Version, url, err)
	}
	if closeErr != nil {
		return "", fmt.Errorf("innsegl init: writing the downloaded gitsign: %w", closeErr)
	}

	got := hex.EncodeToString(sum)
	if got != want {
		return "", fmt.Errorf("innsegl init: REFUSING gitsign %s for %s: downloaded from %s, "+
			"its SHA-256 is %s but the pinned checksum is %s. This is exactly the substitution "+
			"the pin exists to catch — the binary was not installed and will not be used",
			opts.Version, platform, url, got, want)
	}

	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return "", fmt.Errorf("innsegl init: making the verified gitsign executable: %w", err)
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return "", fmt.Errorf("innsegl init: installing the verified gitsign: %w", err)
	}
	return target, nil
}

// downloadTo streams an HTTP response into w and returns its SHA-256,
// computed over exactly the bytes written — never a second read of the file,
// which is how a TOCTOU gap between "hashed" and "used" is avoided.
func downloadTo(ctx context.Context, client *http.Client, url string, w io.Writer) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}

	h := sha256.New()
	if _, err := io.Copy(w, io.TeeReader(resp.Body, h)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// verifyFileSHA256 re-hashes a file already on disk and compares it to want.
// It refuses (rather than trusting the file) on any I/O error, including
// "does not exist" — the caller treats every error here as "download fresh".
func verifyFileSHA256(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return fmt.Errorf("checksum mismatch: have %s, want %s", got, want)
	}
	return nil
}

func sortedPlatforms(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// errGitsignUnsupportedPlatform is unused directly but documents the class of
// refusal locateOrInstallGitsign returns for an unpinned platform, for
// callers that want to distinguish it from a network or checksum failure.
var errGitsignUnsupportedPlatform = errors.New("innsegl init: unsupported platform for gitsign")
