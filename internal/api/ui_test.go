// SPDX-License-Identifier: Apache-2.0

package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The dashboard's own files, served by `innsegl api` (#475). The nginx
// container that used to serve them is gone; everything it did for the UI
// is held here: the files, the client-side router's fallback, the cache
// rules, the content types and the three security headers.

const testIndexHTML = "<!doctype html><title>innsegl</title><div id=root></div>"

// uiFixture writes a small built UI: index.html, a hashed bundle, a font,
// a root file and a nested directory.
func uiFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"index.html":                  testIndexHTML,
		"favicon.svg":                 "<svg xmlns='http://www.w3.org/2000/svg'/>",
		"assets/index-3f9a1c.js":      "console.log('bundle')",
		"assets/index-77b2e0.css":     "body{}",
		"assets/plex-sans-400.woff2":  "wOF2",
		"assets/plex-sans-400.woff":   "wOFF",
		"assets/index-3f9a1c.js.map":  "{}",
		"assets/nested/deep-1a2b.png": "\x89PNG",
		"guide.pdf":                   "%PDF",
		"blob.zzunknown":              "?",
	}
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// apiStub stands in for the query API: it answers every request it is
// given, so a test can tell which side served a path.
var apiStub = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTeapot)
	if _, err := io.WriteString(w, `{"api":"`+r.URL.Path+`"}`); err != nil {
		panic(err)
	}
})

func uiGet(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, target, nil))
	return rec
}

func mustDashboardHandler(t *testing.T, dir string) http.Handler {
	t.Helper()
	h, err := DashboardHandler(apiStub, dir)
	if err != nil {
		t.Fatalf("DashboardHandler(%q): %v", dir, err)
	}
	return h
}

func TestUIServesTheBuiltFiles(t *testing.T) {
	h := mustDashboardHandler(t, uiFixture(t))
	for _, tc := range []struct {
		path, body, contentType string
	}{
		{"/assets/index-3f9a1c.js", "console.log('bundle')", "text/javascript; charset=utf-8"},
		{"/assets/index-77b2e0.css", "body{}", "text/css; charset=utf-8"},
		{"/assets/plex-sans-400.woff2", "wOF2", "font/woff2"},
		{"/assets/plex-sans-400.woff", "wOFF", "font/woff"},
		{"/assets/index-3f9a1c.js.map", "{}", "application/json"},
		{"/assets/nested/deep-1a2b.png", "\x89PNG", "image/png"},
		{"/favicon.svg", "<svg xmlns='http://www.w3.org/2000/svg'/>", "image/svg+xml"},
		// Not in the fixed table: the system's, then a byte stream.
		{"/guide.pdf", "%PDF", "application/pdf"},
		{"/blob.zzunknown", "?", "application/octet-stream"},
	} {
		rec := uiGet(t, h, http.MethodGet, tc.path)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s: status %d, want 200", tc.path, rec.Code)
			continue
		}
		if got := rec.Body.String(); got != tc.body {
			t.Errorf("GET %s: body %q, want %q", tc.path, got, tc.body)
		}
		if got := rec.Header().Get("Content-Type"); got != tc.contentType {
			t.Errorf("GET %s: Content-Type %q, want %q", tc.path, got, tc.contentType)
		}
	}
}

func TestUIFallsBackToIndexForAppRoutes(t *testing.T) {
	h := mustDashboardHandler(t, uiFixture(t))
	for _, path := range []string{
		"/", "/index.html", "/runs/run-dd41951f", "/setup?code=abc", "/account",
		"/assets", "/nested/page", "/../../etc/passwd",
	} {
		rec := uiGet(t, h, http.MethodGet, path)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s: status %d, want 200 (the router's index.html)", path, rec.Code)
			continue
		}
		if got := rec.Body.String(); got != testIndexHTML {
			t.Errorf("GET %s: body %q, want index.html", path, got)
		}
		if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
			t.Errorf("GET %s: Content-Type %q, want text/html", path, got)
		}
	}
}

// A missing hashed asset is a 404, never index.html: a stale page asking for
// a deleted bundle must fail as a missing script, not parse HTML as one.
func TestUIMissingAssetIsNotFound(t *testing.T) {
	h := mustDashboardHandler(t, uiFixture(t))
	for _, path := range []string{"/assets/index-gone.js", "/assets/", "/assets/nested", "/assets/nested/"} {
		rec := uiGet(t, h, http.MethodGet, path)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s: status %d, want 404", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), testIndexHTML) {
			t.Errorf("GET %s answered with index.html", path)
		}
	}
}

// /api/ belongs to the query API, every path of it, including the ones it
// does not know: an unknown API route is the API's 404, never the router's
// index.html with a 200.
func TestUINeverSwallowsTheAPI(t *testing.T) {
	h := mustDashboardHandler(t, uiFixture(t))
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/health"},
		{http.MethodGet, "/api/v1/no-such-route"},
		{http.MethodGet, "/api/"},
		{http.MethodGet, "/api"},
		{http.MethodPost, "/api/v1/auth/login/begin"},
	} {
		rec := uiGet(t, h, tc.method, tc.path)
		if rec.Code != http.StatusTeapot {
			t.Errorf("%s %s: status %d, want the API's own answer", tc.method, tc.path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), testIndexHTML) {
			t.Errorf("%s %s answered with index.html", tc.method, tc.path)
		}
	}
	// A path that only starts with the letters is the UI's.
	if rec := uiGet(t, h, http.MethodGet, "/apiary"); rec.Body.String() != testIndexHTML {
		t.Errorf("GET /apiary: %q, want index.html", rec.Body.String())
	}
}

func TestUICacheRules(t *testing.T) {
	h := mustDashboardHandler(t, uiFixture(t))
	for _, tc := range []struct{ path, want string }{
		// Hashed names: immutable, a year.
		{"/assets/index-3f9a1c.js", "public, max-age=31536000, immutable"},
		{"/assets/plex-sans-400.woff2", "public, max-age=31536000, immutable"},
		// index.html names the current hashes; a cached copy pins a browser
		// to a deleted bundle.
		{"/", "no-store"},
		{"/index.html", "no-store"},
		{"/runs/run-1", "no-store"},
		// Unhashed root files are revalidated.
		{"/favicon.svg", "no-cache"},
	} {
		rec := uiGet(t, h, http.MethodGet, tc.path)
		if got := rec.Header().Values("Cache-Control"); len(got) != 1 || got[0] != tc.want {
			t.Errorf("GET %s: Cache-Control %q, want exactly %q", tc.path, got, tc.want)
		}
	}
}

func TestUIRefusesWritesToStaticFiles(t *testing.T) {
	h := mustDashboardHandler(t, uiFixture(t))
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := uiGet(t, h, method, "/index.html")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /index.html: status %d, want 405", method, rec.Code)
		}
		if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
			t.Errorf("%s /index.html: Allow %q, want \"GET, HEAD\"", method, got)
		}
	}
	rec := uiGet(t, h, http.MethodHead, "/assets/index-3f9a1c.js")
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD of an asset: status %d, %d body bytes; want 200 and none", rec.Code, rec.Body.Len())
	}
}

// The three headers dashboard-nginx.conf added to every response, with its
// values, on the UI and on the API alike — and exactly once each, which the
// nginx config had to strip a duplicate to manage.
func TestDashboardSecurityHeaders(t *testing.T) {
	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
		"X-Frame-Options":        "DENY",
	}
	withUI := mustDashboardHandler(t, uiFixture(t))
	apiOnly := mustDashboardHandler(t, "")
	for _, tc := range []struct {
		name string
		h    http.Handler
		path string
	}{
		{"index", withUI, "/"},
		{"asset", withUI, "/assets/index-3f9a1c.js"},
		{"missing asset", withUI, "/assets/gone.js"},
		{"api through the UI", withUI, "/api/v1/health"},
		{"api only", apiOnly, "/api/v1/health"},
	} {
		rec := uiGet(t, tc.h, http.MethodGet, tc.path)
		for k, v := range want {
			if got := rec.Header().Values(k); len(got) != 1 || got[0] != v {
				t.Errorf("%s (%s): %s = %q, want exactly %q", tc.name, tc.path, k, got, v)
			}
		}
	}
}

// No UI directory: the API alone, as before #475, so tests and a
// development API keep working. A non-API path is the API's to answer.
func TestNoUIDirServesTheAPIAlone(t *testing.T) {
	h := mustDashboardHandler(t, "")
	if rec := uiGet(t, h, http.MethodGet, "/"); rec.Code != http.StatusTeapot {
		t.Errorf("GET / with no UI: status %d, want the API's own answer", rec.Code)
	}
}

func TestDashboardHandlerRefusesAUIDirWithoutIndex(t *testing.T) {
	empty := t.TempDir()
	if _, err := DashboardHandler(apiStub, empty); err == nil || !strings.Contains(err.Error(), "index.html") {
		t.Errorf("an empty UI directory: err %v, want one naming index.html", err)
	}
	if _, err := DashboardHandler(apiStub, filepath.Join(empty, "absent")); err == nil {
		t.Error("a UI directory that does not exist was accepted")
	}
	file := filepath.Join(empty, "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := DashboardHandler(apiStub, file); err == nil {
		t.Error("a UI directory that is a file was accepted")
	}
	dirIndex := t.TempDir()
	if err := os.Mkdir(filepath.Join(dirIndex, "index.html"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := DashboardHandler(apiStub, dirIndex); err == nil {
		t.Error("a UI directory whose index.html is a directory was accepted")
	}
	if _, err := DashboardHandler(nil, uiFixture(t)); err == nil {
		t.Error("a nil API handler was accepted")
	}
}

// A file outside the UI directory is never served, through .. or through a
// symbolic link out of it.
func TestUIServesNothingOutsideItsDirectory(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := uiFixture(t)
	if err := os.Symlink(secret, filepath.Join(dir, "assets", "leak.txt")); err != nil {
		t.Fatal(err)
	}
	h := mustDashboardHandler(t, dir)
	for _, path := range []string{"/assets/leak.txt", "/assets/../../" + filepath.Base(outside) + "/secret.txt"} {
		rec := uiGet(t, h, http.MethodGet, path)
		if strings.Contains(rec.Body.String(), "secret") {
			t.Errorf("GET %s served a file outside the UI directory", path)
		}
	}
}

// The UI directory is read at request time, so a file that cannot be read
// is a 404 for an asset and a 500 for index.html, never a crash.
func TestUIIndexRemovedAfterStart(t *testing.T) {
	dir := uiFixture(t)
	h := mustDashboardHandler(t, dir)
	if err := os.Remove(filepath.Join(dir, "index.html")); err != nil {
		t.Fatal(err)
	}
	if rec := uiGet(t, h, http.MethodGet, "/runs/x"); rec.Code != http.StatusInternalServerError {
		t.Errorf("index.html gone: status %d, want 500", rec.Code)
	}
}
