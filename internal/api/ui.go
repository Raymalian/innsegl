// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"os"
	"path"
	"strings"
)

// The dashboard's own files (#475). `innsegl api` serves the built web/ UI
// next to the query API, on one origin, so the browser's relative
// `/api/v1/...` requests reach this process with no proxy in between. The
// nginx container that did this before is gone; what it did is here:
//
//   - every path under /api/ is the query API's, including ones it does not
//     know, so an unknown API route is its 404 and never the router's page;
//   - a file in the UI directory is served as itself;
//   - a missing file under /assets/ is a 404, because a stale page asking
//     for a deleted bundle must fail as a missing script;
//   - every other path is index.html: the router is history.pushState with
//     no routing dependency (web/src/app/router.tsx), so a reloaded or
//     pasted deep link has to be answered with the page that resolves it;
//   - hashed /assets/ files are cached for a year; index.html never is,
//     because it names the current hashes; other files are revalidated;
//   - a strict Content-Security-Policy and three hardening headers on
//     every response (securityHeaders), and an index.html with an inline
//     script refused at start, because that policy would block it (#612).
//
// Files are opened through os.Root, so neither `..` nor a symbolic link
// reaches anything outside the UI directory.

const (
	uiIndex      = "index.html"
	uiAssetsPath = "/assets/"
	apiPath      = "/api/"

	cacheImmutable  = "public, max-age=31536000, immutable"
	cacheNever      = "no-store"
	cacheRevalidate = "no-cache"
)

// uiContentTypes are the types the built UI ships, fixed here rather than
// left to the host's mime tables: the runtime image is Alpine with no
// /etc/mime.types, and Go's built-in table has no font types. Anything else
// falls through to mime.TypeByExtension.
var uiContentTypes = map[string]string{
	".html":        "text/html; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".json":        "application/json",
	".map":         "application/json",
	".svg":         "image/svg+xml",
	".png":         "image/png",
	".ico":         "image/x-icon",
	".woff2":       "font/woff2",
	".woff":        "font/woff",
	".txt":         "text/plain; charset=utf-8",
	".webmanifest": "application/manifest+json",
}

// DashboardHandler is the handler `innsegl api` serves: the query API in
// apiHandler, the built UI from uiDir, and the security headers on both.
// An empty uiDir serves the API alone, as before #475, so tests and a
// development API need no UI. A uiDir without an index.html is refused: a
// dashboard that answers every page with a 404 is a failure better seen at
// start.
func DashboardHandler(apiHandler http.Handler, uiDir string) (http.Handler, error) {
	if apiHandler == nil {
		return nil, errors.New("api: the dashboard handler needs the query API")
	}
	if uiDir == "" {
		return securityHeaders(apiHandler), nil
	}
	root, err := os.OpenRoot(uiDir)
	if err != nil {
		return nil, fmt.Errorf("api: open the UI directory: %w", err)
	}
	info, err := root.Stat(uiIndex)
	if err != nil {
		return nil, fmt.Errorf("api: the UI directory %s has no %s: %w", uiDir, uiIndex, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("api: the UI directory's %s is not a file", uiIndex)
	}
	page, err := root.ReadFile(uiIndex)
	if err != nil {
		return nil, fmt.Errorf("api: read the UI directory's %s: %w", uiIndex, err)
	}
	if found := inlineScript(string(page)); found != "" {
		return nil, fmt.Errorf("api: the UI directory's %s carries an inline script (%s), "+
			"which the dashboard's Content-Security-Policy blocks; rebuild the UI with web/vite.config.ts", uiIndex, found)
	}
	return securityHeaders(&uiHandler{api: apiHandler, root: root}), nil
}

// dashboardCSP is the dashboard's Content-Security-Policy (#612, FE-155).
// Script, style, image, font and fetch all come from this origin and from
// nowhere else; nothing inline runs, nothing is evaluated from a string, no
// plugin loads, no <base> re-points relative URLs, no other site frames the
// page and no form posts elsewhere. A page that handles unlock material must
// not run injected script, and this is what stops it.
//
// There is no nonce because there is nothing inline to vouch for: the theme
// bootstrap is moved to its own file by web/vite.config.ts at build, and
// DashboardHandler refuses an index.html that still carries one. WebAuthn
// (navigator.credentials) is not governed by CSP; its requests to
// /api/v1/auth/ are same-origin fetches, which connect-src allows.
const dashboardCSP = "default-src 'self'; script-src 'self'; style-src 'self'; " +
	"img-src 'self'; font-src 'self'; connect-src 'self'; object-src 'none'; " +
	"base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

// securityHeaders sets the policy and the three headers the nginx config
// added to every response, with its values. Set, not Add, so a header the
// query API also sets (nosniff, server.go) appears once. The policy is on
// the API's JSON too: it costs nothing there and covers any response a
// browser is tricked into rendering.
//
// No Strict-Transport-Security, as before: the plain-HTTP address stays for
// localhost (ADR-0066's amendment).
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", dashboardCSP)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// inlineScript reports the first piece of script in page that dashboardCSP
// would block — a <script> with a body or without a src, an on* event
// attribute, a javascript: URL — or "" when there is none. It reads the one
// file the build writes, not arbitrary HTML: tags and attributes as the HTML
// tokenizer splits them, comments skipped, script bodies read to </script.
func inlineScript(page string) string {
	lower := strings.ToLower(page)
	for i := 0; i < len(lower); {
		lt := strings.IndexByte(lower[i:], '<')
		if lt < 0 {
			return ""
		}
		i += lt
		if strings.HasPrefix(lower[i:], "<!--") {
			end := strings.Index(lower[i+4:], "-->")
			if end < 0 {
				return ""
			}
			i += 4 + end + 3
			continue
		}
		name, attrs, next := scanTag(lower, i+1)
		i = next
		for _, a := range attrs {
			if strings.HasPrefix(a.name, "on") {
				return "an " + a.name + " attribute"
			}
			if strings.HasPrefix(strings.TrimSpace(a.value), "javascript:") {
				return "a javascript: URL"
			}
		}
		if name != "script" {
			continue
		}
		hasSrc := false
		for _, a := range attrs {
			if a.name == "src" {
				hasSrc = true
			}
		}
		end := strings.Index(lower[i:], "</script")
		if end < 0 {
			return "an unterminated <script>"
		}
		body := lower[i : i+end]
		i += end
		if !hasSrc || strings.TrimSpace(body) != "" {
			return "a <script> without src"
		}
	}
	return ""
}

type tagAttr struct{ name, value string }

// scanTag reads the tag whose name starts at i (just after '<') and returns
// its name, its attributes and the index after its '>'. A closing tag or a
// declaration has a name starting with '/' or '!' and is skipped whole.
func scanTag(s string, i int) (string, []tagAttr, int) {
	isSpace := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' }
	start := i
	for i < len(s) && !isSpace(s[i]) && s[i] != '>' && s[i] != '/' {
		i++
	}
	if i == start && i < len(s) && s[i] == '/' {
		// "</name ...>": a closing tag.
		for i < len(s) && s[i] != '>' {
			i++
		}
		return "", nil, min(i+1, len(s))
	}
	name := s[start:i]
	var attrs []tagAttr
	for i < len(s) {
		for i < len(s) && (isSpace(s[i]) || s[i] == '/') {
			i++
		}
		if i >= len(s) || s[i] == '>' {
			return name, attrs, min(i+1, len(s))
		}
		ns := i
		for i < len(s) && !isSpace(s[i]) && s[i] != '>' && s[i] != '=' && s[i] != '/' {
			i++
		}
		a := tagAttr{name: s[ns:i]}
		for i < len(s) && isSpace(s[i]) {
			i++
		}
		if i < len(s) && s[i] == '=' {
			i++
			for i < len(s) && isSpace(s[i]) {
				i++
			}
			if i < len(s) && (s[i] == '"' || s[i] == '\'') {
				q := s[i]
				i++
				vs := i
				for i < len(s) && s[i] != q {
					i++
				}
				a.value = s[vs:i]
				i = min(i+1, len(s))
			} else {
				vs := i
				for i < len(s) && !isSpace(s[i]) && s[i] != '>' {
					i++
				}
				a.value = s[vs:i]
			}
		}
		attrs = append(attrs, a)
	}
	return name, attrs, i
}

type uiHandler struct {
	api  http.Handler
	root *os.Root
}

func (u *uiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, apiPath) {
		u.api.ServeHTTP(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	// path.Clean of a rooted path never climbs above "/", and os.Root
	// refuses anything that would leave the directory regardless.
	clean := path.Clean("/" + r.URL.Path)
	name := strings.TrimPrefix(clean, "/")
	if name != "" && name != uiIndex && u.serveFile(w, r, name, clean) {
		return
	}
	if strings.HasPrefix(r.URL.Path, uiAssetsPath) {
		http.NotFound(w, r)
		return
	}
	if !u.serveFile(w, r, uiIndex, "/"+uiIndex) {
		http.Error(w, "the dashboard's index.html cannot be read", http.StatusInternalServerError)
	}
}

// serveFile serves name from the UI directory when it is a regular file
// there, and reports whether it did.
func (u *uiHandler) serveFile(w http.ResponseWriter, r *http.Request, name, urlPath string) bool {
	f, err := u.root.Open(name)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	h := w.Header()
	switch {
	case name == uiIndex:
		h.Set("Cache-Control", cacheNever)
	case strings.HasPrefix(urlPath, uiAssetsPath):
		h.Set("Cache-Control", cacheImmutable)
	default:
		h.Set("Cache-Control", cacheRevalidate)
	}
	h.Set("Content-Type", uiContentType(name))
	http.ServeContent(w, r, name, info.ModTime(), f)
	return true
}

func uiContentType(name string) string {
	ext := strings.ToLower(path.Ext(name))
	if t, ok := uiContentTypes[ext]; ok {
		return t
	}
	if t := mime.TypeByExtension(ext); t != "" {
		return t
	}
	return "application/octet-stream"
}
