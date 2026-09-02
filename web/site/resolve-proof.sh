#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Drive the real Go module resolver at a local copy of this site (RM-058, #66).
#
# WHY THIS EXISTS
# ---------------
# The claim RM-058 has to make is "`go get innsegl.dev/innsegl` resolves".
# Reading the meta tag and agreeing that it looks right is not that claim —
# the toolchain's parser is the only opinion that counts, and it has rules
# about the tag that are easy to satisfy by eye and fail in practice (the root
# must be a prefix of the import path; the middle field is a VCS name; two
# tags for one prefix is ambiguous).
#
# So this runs the actual go command against the actual files in web/site/,
# with no deployment involved, and lets it succeed or fail.
#
# HOW IT GETS THE GO COMMAND TO TALK TO A DIRECTORY ON THIS MACHINE
# -----------------------------------------------------------------
# The go command resolves a vanity path by requesting the import path itself
# as a URL — the host is baked into the module path and cannot be overridden
# by a flag. Two facts make that reachable without touching DNS or /etc/hosts:
#
#   1. cmd/go's HTTP clients use http.ProxyFromEnvironment, so HTTP_PROXY and
#      HTTPS_PROXY steer module fetches the same way they steer anything else.
#   2. With GOINSECURE matching the path, cmd/go tries https:// first and then
#      falls back to plain http:// (cmd/go/internal/web/http.go).
#
# The harness below is therefore an ordinary HTTP forward proxy. It refuses
# CONNECT for innsegl.dev:443 — which is what makes the run deterministic
# whether or not the domain has been deployed yet — so the go command falls
# back to http://innsegl.dev/innsegl?go-get=1, which the proxy answers out of
# web/site/ using Cloudflare Pages' rules: clean URLs, then _redirects.
# Everything else (proxy.golang.org, github.com) is tunnelled to the real host,
# so the resolution the go command performs is genuinely end to end: our meta
# tag, then a real clone of the real repository.
#
# Usage: resolve-proof.sh <site-dir> <module-path> <repo-url>

set -euo pipefail

SITE_DIR="${1:?site dir}"
MODULE_PATH="${2:?module path}"
REPO_URL="${3:?repo url}"

for tool in go git; do
  command -v "${tool}" >/dev/null 2>&1 || { printf 'FAIL: %s not on PATH\n' "${tool}" >&2; exit 1; }
done

WORK="$(mktemp -d)"
PROXY_PID=""
cleanup() {
  if [ -n "${PROXY_PID}" ]; then
    kill "${PROXY_PID}" 2>/dev/null || true
    wait "${PROXY_PID}" 2>/dev/null || true
  fi
  rm -rf "${WORK}"
}
trap cleanup EXIT

mkdir -p "${WORK}/harness"
cat > "${WORK}/harness/go.mod" <<'GOMOD'
module innseglsiteharness

go 1.27
GOMOD

cat > "${WORK}/harness/main.go" <<'GOFILE'
// SPDX-License-Identifier: Apache-2.0

// An HTTP forward proxy that answers for one host out of a directory of
// static files, applying Cloudflare Pages' serving rules, and tunnels
// everything else to where it really lives.
package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type rule struct {
	from   string // "/repo" or "/innsegl/*"
	to     string
	status int
}

type site struct {
	dir   string
	host  string
	rules []rule
}

// parseRedirects reads Pages' _redirects: "<from> <to> [status]", # comments.
func parseRedirects(path string) []rule {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []rule
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		st := 302
		if len(f) >= 3 {
			if n, err := strconv.Atoi(f[2]); err == nil {
				st = n
			}
		}
		out = append(out, rule{from: f[0], to: f[1], status: st})
	}
	return out
}

// serveFile applies Pages' static matching: exact file, then clean URL
// (<path>.html), then <path>/index.html.
func (s *site) serveFile(w http.ResponseWriter, urlPath string) bool {
	clean := filepath.Clean("/" + strings.TrimPrefix(urlPath, "/"))
	candidates := []string{}
	if clean == "/" {
		candidates = append(candidates, "index.html")
	} else {
		rel := strings.TrimPrefix(clean, "/")
		candidates = append(candidates, rel, rel+".html", filepath.Join(rel, "index.html"))
	}
	for _, c := range candidates {
		p := filepath.Join(s.dir, c)
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() {
			continue
		}
		body, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if strings.HasSuffix(p, ".html") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		} else if strings.HasSuffix(p, ".css") {
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		}
		w.WriteHeader(http.StatusOK)
		w.Write(body)
		return true
	}
	return false
}

func (s *site) serve(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	log.Printf("site %s %s?%s", r.Method, p, r.URL.RawQuery)

	if s.serveFile(w, p) {
		return
	}
	for _, ru := range s.rules {
		matched := false
		splat := ""
		if strings.HasSuffix(ru.from, "/*") {
			prefix := strings.TrimSuffix(ru.from, "*")
			if strings.HasPrefix(p, prefix) {
				matched = true
				splat = strings.TrimPrefix(p, prefix)
			}
		} else if p == ru.from {
			matched = true
		}
		if !matched {
			continue
		}
		to := strings.ReplaceAll(ru.to, ":splat", splat)
		if ru.status == 200 {
			if s.serveFile(w, to) {
				return
			}
			break
		}
		w.Header().Set("Location", to)
		w.WriteHeader(ru.status)
		return
	}
	w.WriteHeader(http.StatusNotFound)
	s.serveFile(w, "/404.html")
}

func main() {
	dir := os.Args[1]
	host := os.Args[2]
	s := &site{dir: dir, host: host, rules: parseRedirects(filepath.Join(dir, "_redirects"))}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ln.Addr().(*net.TCPAddr).Port)
	os.Stdout.Sync()

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			hostOnly, _, _ := net.SplitHostPort(r.Host)
			if hostOnly == s.host {
				// Refuse TLS to the vanity host so the run does not depend on
				// whether the domain has been deployed. cmd/go falls back to
				// plain HTTP, which is the branch this harness serves.
				log.Printf("connect REFUSED %s", r.Host)
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			log.Printf("connect %s", r.Host)
			up, err := net.Dial("tcp", r.Host)
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			hj, ok := w.(http.Hijacker)
			if !ok {
				up.Close()
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			down, _, err := hj.Hijack()
			if err != nil {
				up.Close()
				return
			}
			down.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			go func() { io.Copy(up, down); up.Close() }()
			io.Copy(down, up)
			down.Close()
			return
		}
		if r.URL.Host == s.host {
			s.serve(w, r)
			return
		}
		log.Printf("plain-http REFUSED %s", r.URL)
		w.WriteHeader(http.StatusBadGateway)
	})
	log.Fatal(http.Serve(ln, h))
}
GOFILE

PROXY_LOG="${WORK}/proxy.log"
# Built rather than `go run`, so that the PID we hold is the server itself and
# killing it actually releases the port.
( cd "${WORK}/harness" && GOWORK=off GOFLAGS= go build -o "${WORK}/harness/harness" . )
"${WORK}/harness/harness" "${SITE_DIR}" "innsegl.dev" > "${WORK}/port" 2> "${PROXY_LOG}" &
PROXY_PID=$!
disown "${PROXY_PID}" 2>/dev/null || true

PORT=""
i=0
while [ "${i}" -lt 200 ]; do
  PORT="$(head -n1 "${WORK}/port" 2>/dev/null || true)"
  case "${PORT}" in
    [0-9]*) break ;;
  esac
  PORT=""
  i=$((i + 1))
  perl -e 'select undef, undef, undef, 0.1' 2>/dev/null || true
done
if [ -z "${PORT}" ]; then
  printf 'FAIL: local site harness did not start\n' >&2
  cat "${PROXY_LOG}" >&2
  exit 1
fi
printf '    harness http://127.0.0.1:%s (serving %s as innsegl.dev)\n' "${PORT}" "${SITE_DIR}"

# The exact request the toolchain makes, through the harness, first.
GOGET_BODY="${WORK}/goget.html"
if ! curl -sS --proxy "http://127.0.0.1:${PORT}" \
     -o "${GOGET_BODY}" -w '    GET http://innsegl.dev/%{url_effective}\n' \
     "http://innsegl.dev/${MODULE_PATH#*/}?go-get=1" >/dev/null 2>&1; then
  # curl is a convenience; its absence is not a failure of the tag.
  printf '    (curl unavailable — skipping the raw ?go-get=1 fetch)\n'
else
  printf '    ?go-get=1 response is %s bytes\n' "$(wc -c < "${GOGET_BODY}" | tr -d ' ')"
  if ! grep -qF "<meta name=\"go-import\" content=\"${MODULE_PATH} git ${REPO_URL}\">" "${GOGET_BODY}"; then
    printf 'FAIL: the ?go-get=1 response does not carry the go-import tag\n' >&2
    exit 1
  fi
fi

export GOWORK=off
export GOFLAGS=
export GOPROXY="https://proxy.golang.org,direct"
# GOPRIVATE keeps innsegl.dev off the module proxy and the checksum database,
# so the go command must resolve it the way a first adopter's `go get` does:
# by asking innsegl.dev itself.
export GOPRIVATE="${MODULE_PATH%%/*}"
export GOINSECURE="${MODULE_PATH%%/*}"
export HTTP_PROXY="http://127.0.0.1:${PORT}"
export HTTPS_PROXY="http://127.0.0.1:${PORT}"
export http_proxy="${HTTP_PROXY}"
export https_proxy="${HTTPS_PROXY}"
export NO_PROXY=""
export no_proxy=""
export GOBIN="${WORK}/bin"

printf '\n    go list -m -x %s@latest\n' "${MODULE_PATH}"
LIST_OUT="${WORK}/list.out"
LIST_ERR="${WORK}/list.err"
if ! (cd "${WORK}" && go list -m -x "${MODULE_PATH}@latest") > "${LIST_OUT}" 2> "${LIST_ERR}"; then
  printf 'FAIL: the go command could not resolve %s through the meta tag\n' "${MODULE_PATH}" >&2
  sed 's/^/      /' "${LIST_ERR}" >&2
  exit 1
fi
sed 's/^/      /' "${LIST_OUT}"

if ! grep -q "go-get=1" "${LIST_ERR}"; then
  printf 'FAIL: the go command never requested ?go-get=1 — it did not use the meta tag\n' >&2
  sed 's/^/      /' "${LIST_ERR}" >&2
  exit 1
fi
if ! grep -q "?go-get=1" "${PROXY_LOG}"; then
  printf 'FAIL: the local site never saw a ?go-get=1 request\n' >&2
  sed 's/^/      /' "${PROXY_LOG}" >&2
  exit 1
fi

printf '\n    go install %s/cmd/innsegl@latest\n' "${MODULE_PATH}"
INSTALL_ERR="${WORK}/install.err"
if ! (cd "${WORK}" && go install "${MODULE_PATH}/cmd/innsegl@latest") > /dev/null 2> "${INSTALL_ERR}"; then
  printf 'FAIL: `go install %s/cmd/innsegl@latest` failed\n' "${MODULE_PATH}" >&2
  sed 's/^/      /' "${INSTALL_ERR}" >&2
  exit 1
fi
if [ ! -x "${GOBIN}/innsegl" ]; then
  printf 'FAIL: no binary at %s/innsegl after go install\n' "${GOBIN}" >&2
  exit 1
fi
printf '      %s\n' "$("${GOBIN}/innsegl" version)"

printf '\n    requests the site actually served:\n'
grep '^.*site GET' "${PROXY_LOG}" | sed 's/^/      /' || true

printf '\nOK: the go command resolved %s through the go-import tag in web/site/ and built its binary.\n' "${MODULE_PATH}"
